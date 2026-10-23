import Foundation
import WebKit

/// 路径 B：所有 API 请求都在 WKWebView 里用 fetch() 发出去。
///
/// 为什么必须这样：`cf_clearance` 除了绑 IP 和 UA，还会被 Cloudflare 关联到
/// 签发时的 TLS 指纹。WebKit 过盾拿到的凭据，交给 CFNetwork（URLSession）去用，
/// 指纹对不上，照样回挑战页。只有让 WebKit 自己发请求，指纹才始终一致。
///
/// 传输层依然经本地代理（DoH + ECH）出去，所以阻断问题不受影响。
@MainActor
final class WebViewTransport: NSObject, WKNavigationDelegate {

    static let shared = WebViewTransport()

    private var webView: WKWebView?
    private var isLoading = false
    private var loadContinuations: [CheckedContinuation<Void, Never>] = []
    private var loaded = false

    /// 载入站点首页。带尾点不需要了——代理会 MITM 并用 ECH 出去。
    func prepare() {
        guard webView == nil else {
            if !loaded && !isLoading { load() }
            return
        }
        let config = WKWebViewConfiguration()
        config.websiteDataStore = .default()
        let view = WKWebView(frame: .zero, configuration: config)
        view.customUserAgent = AppConfig.userAgent
        view.navigationDelegate = self
        webView = view
        load()
    }

    private func load() {
        guard let view = webView else { return }
        isLoading = true
        loaded = false
        view.load(URLRequest(url: URL(string: "https://linux.do/")!))
    }

    /// 等待首页加载完成；超时也放行，交给 fetch 自己报错。
    private func waitUntilLoaded(timeout: TimeInterval) async {
        if loaded { return }
        await withCheckedContinuation { (cont: CheckedContinuation<Void, Never>) in
            loadContinuations.append(cont)
            Task { [weak self] in
                try? await Task.sleep(nanoseconds: UInt64(timeout * 1_000_000_000))
                guard let self = self else { return }
                await MainActor.run { self.flushContinuations() }
            }
        }
    }

    private func flushContinuations() {
        let pending = loadContinuations
        loadContinuations.removeAll()
        pending.forEach { $0.resume() }
    }

    func webView(_ webView: WKWebView, didFinish navigation: WKNavigation!) {
        loaded = true
        isLoading = false
        flushContinuations()
    }

    func webView(_ webView: WKWebView, didFail navigation: WKNavigation!, withError error: Error) {
        isLoading = false
        flushContinuations()
    }

    func webView(_ webView: WKWebView, didFailProvisionalNavigation navigation: WKNavigation!, withError error: Error) {
        isLoading = false
        flushContinuations()
    }

    /// 在页面里执行 fetch，返回 (body, statusCode)。
    func fetch(
        path: String,
        method: String,
        body: Data?,
        contentType: String?
    ) async throws -> (Data, Int) {
        prepare()
        await waitUntilLoaded(timeout: 20)

        guard let view = webView else {
            throw NSError(domain: "WebViewTransport", code: -1,
                          userInfo: [NSLocalizedDescriptionKey: "WebView 未就绪"])
        }

        let script = """
        const options = { method: method, credentials: "include", headers: headers };
        if (body !== "") { options.body = body; }
        const response = await fetch(path, options);
        const text = await response.text();
        return JSON.stringify({ status: response.status, body: text });
        """

        var headers: [String: String] = [
            "Accept": "application/json",
            "X-Requested-With": "XMLHttpRequest"
        ]
        if let contentType = contentType { headers["Content-Type"] = contentType }

        let payload: Any? = try await withCheckedThrowingContinuation { cont in
            view.callAsyncJavaScript(
                script,
                arguments: [
                    "path": path,
                    "method": method,
                    "body": body.flatMap { String(data: $0, encoding: .utf8) } ?? "",
                    "headers": headers
                ],
                in: nil,
                contentWorld: .page
            ) { result in
                switch result {
                case .success(let value): cont.resume(returning: value)
                case .failure(let error): cont.resume(throwing: error)
                }
            }
        }

        guard let json = payload as? String,
              let data = json.data(using: .utf8),
              let object = try? JSONSerialization.jsonObject(with: data) as? [String: Any],
              let status = object["status"] as? Int,
              let text = object["body"] as? String else {
            throw NSError(domain: "WebViewTransport", code: -2,
                          userInfo: [NSLocalizedDescriptionKey: "WebView 返回格式异常"])
        }

        return (Data(text.utf8), status)
    }
}
