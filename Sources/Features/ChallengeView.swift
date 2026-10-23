import SwiftUI
import WebKit

/// 用真正的 WKWebView 过 Cloudflare 挑战。
///
/// 前提：代理已启动，且系统 Wi-Fi 的 HTTP 代理指向 127.0.0.1:<端口>。
/// 这样一来 WebKit 的流量会经本地代理进来，代理用 ECH 连 Cloudflare，
/// 挑战页里的 JS 由 WebKit 执行——这是唯一能拿到合法 cf_clearance 的办法。
struct ChallengeView: View {

    @Environment(\.dismiss) private var dismiss

    let port: Int

    @State private var status = "正在加载…"
    @State private var hasClearance = false

    var body: some View {
        NavigationStack {
            VStack(spacing: 0) {
                Text(status)
                    .font(.footnote)
                    .foregroundColor(.secondary)
                    .frame(maxWidth: .infinity, alignment: .leading)
                    .padding(.horizontal, 16)
                    .padding(.vertical, 10)

                ChallengeWebView(
                    port: port,
                    onStatus: { status = $0 },
                    onClearance: { hasClearance = $0 }
                )
            }
            .navigationTitle("通过 Cloudflare 验证")
            .navigationBarTitleDisplayMode(.inline)
            .toolbar {
                ToolbarItem(placement: .cancellationAction) {
                    Button("关闭") { dismiss() }
                }
                ToolbarItem(placement: .confirmationAction) {
                    Button("完成") {
                        CookieHarvester.sync { message in
                            status = message
                            dismiss()
                        }
                    }
                    .disabled(!hasClearance)
                }
            }
        }
    }
}

private struct ChallengeWebView: UIViewRepresentable {

    let port: Int
    let onStatus: (String) -> Void
    let onClearance: (Bool) -> Void

    func makeCoordinator() -> Coordinator {
        Coordinator(onStatus: onStatus, onClearance: onClearance)
    }

    func makeUIView(context: Context) -> WKWebView {
        let config = WKWebViewConfiguration()
        config.websiteDataStore = .default()
        let webView = WKWebView(frame: .zero, configuration: config)
        webView.navigationDelegate = context.coordinator
        webView.customUserAgent = AppConfig.userAgent
        webView.load(URLRequest(url: URL(string: "https://linux.do/")!))
        context.coordinator.startPolling(webView)
        return webView
    }

    func updateUIView(_ webView: WKWebView, context: Context) {}

    final class Coordinator: NSObject, WKNavigationDelegate {

        private let onStatus: (String) -> Void
        private let onClearance: (Bool) -> Void
        private var timer: Timer?

        init(onStatus: @escaping (String) -> Void, onClearance: @escaping (Bool) -> Void) {
            self.onStatus = onStatus
            self.onClearance = onClearance
        }

        func startPolling(_ webView: WKWebView) {
            timer = Timer.scheduledTimer(withTimeInterval: 1.5, repeats: true) { [weak self, weak webView] _ in
                guard let self = self, let webView = webView else { return }
                webView.evaluateJavaScript("document.title") { title, _ in
                    let pageTitle = (title as? String) ?? ""
                    webView.configuration.websiteDataStore.httpCookieStore.getAllCookies { cookies in
                        let clearance = cookies.first {
                            $0.name == "cf_clearance" && $0.domain.contains("linux.do")
                        }
                        let has = clearance != nil
                        DispatchQueue.main.async {
                            self.onClearance(has)
                            if has {
                                self.onStatus("已拿到 cf_clearance，可以点「完成」保存凭据")
                            } else if pageTitle.lowercased().contains("just a moment") {
                                self.onStatus("Cloudflare 正在验证，等待它自己完成…")
                            } else {
                                self.onStatus("当前页面：\(pageTitle.isEmpty ? "加载中" : pageTitle)")
                            }
                        }
                    }
                }
            }
        }

        func webView(_ webView: WKWebView, didFailProvisionalNavigation navigation: WKNavigation!, withError error: Error) {
            onStatus("加载失败：\(error.localizedDescription)")
        }

        func webView(_ webView: WKWebView, didFinish navigation: WKNavigation!) {
            onStatus("页面已加载")
        }

        deinit {
            timer?.invalidate()
        }
    }
}

/// 把 WebView 里的 linux.do Cookie 同步到 app 的 HTTPCookieStorage。
enum CookieHarvester {

    static func sync(completion: @escaping (String) -> Void) {
        let store = WKWebsiteDataStore.default().httpCookieStore
        store.getAllCookies { cookies in
            let relevant = cookies.filter { $0.domain.contains("linux.do") }
            for cookie in relevant {
                HTTPCookieStorage.shared.setCookie(cookie)
            }
            let stored = HTTPCookieStorage.shared.cookies ?? []
            if !stored.isEmpty,
               let header = HTTPCookie.requestHeaderFields(with: stored)["Cookie"] {
                CookieVault.save(header)
            }
            let hasSession = relevant.contains { $0.name == "_t" }
            let hasClearance = relevant.contains { $0.name == "cf_clearance" }
            let message = "已同步 \(relevant.count) 个 Cookie（会话 \(hasSession ? "有" : "无")，clearance \(hasClearance ? "有" : "无")）"
            DispatchQueue.main.async { completion(message) }
        }
    }
}
