import SwiftUI
import WebKit

/// 与站点交互的 WebView。两种用途：
/// - `.login`：用户在里面完成登录，需要拿到 `_t` 会话
/// - `.cloudflareBypass`：只需要 Cloudflare 放行，拿到 `cf_clearance` 即可
///
/// 原版 App 就是这么做的：链接了 WebKit，`cf_clearance` 字符串一次都不出现，
/// 因为它不显式处理——WKWebView 是真浏览器，挑战 JS 自己会跑完，
/// 随后把整袋 cookie 交给原生请求。见 `CommunityWebSession.swift`。
enum WebSessionPurpose {
    case login
    case cloudflareBypass

    /// 判定「这一轮可以收工」的 cookie。
    var requiredCookie: String {
        switch self {
        case .login: return "_t"
        case .cloudflareBypass: return "cf_clearance"
        }
    }
}

struct WebLoginView: View {

    @Environment(\.dismiss) private var dismiss
    @EnvironmentObject private var auth: AuthStore

    @State private var isLoading = true
    @State private var message: String?

    var body: some View {
        NavigationStack {
            WebLoginWebView(isLoading: $isLoading) {
                Task {
                    await auth.completeWebLogin()
                    if auth.isLoggedIn {
                        dismiss()
                    } else {
                        message = auth.errorMessage ?? "会话未能建立，请再试一次"
                    }
                }
            }
            .ignoresSafeArea(edges: .bottom)
            .navigationTitle("登录 linux.do")
            .navigationBarTitleDisplayMode(.inline)
            .toolbar {
                ToolbarItem(placement: .cancellationAction) {
                    Button("取消") { dismiss() }
                }
            }
            .overlay(alignment: .bottom) {
                if isLoading {
                    ProgressView()
                        .padding(10)
                        .background(.ultraThinMaterial, in: Capsule())
                        .padding(.bottom, 24)
                } else if let message = message {
                    Text(message)
                        .font(.footnote)
                        .padding(10)
                        .background(.ultraThinMaterial, in: RoundedRectangle(cornerRadius: 10))
                        .padding(.horizontal, 16)
                        .padding(.bottom, 24)
                }
            }
        }
    }
}

struct WebLoginWebView: UIViewRepresentable {

    var purpose: WebSessionPurpose = .login
    @Binding var isLoading: Bool
    /// 把 WebView 的真实状态回传出来。
    /// 空白页时只有 URL / 标题 / 错误能说明到底是「没拿到页面」还是「拿到了但渲染不了」。
    var onStatus: ((String) -> Void)?
    var onReady: () -> Void

    func makeCoordinator() -> Coordinator {
        Coordinator(self)
    }

    func makeUIView(context: Context) -> WKWebView {
        let configuration = WKWebViewConfiguration()
        configuration.websiteDataStore = .default()
        let webView = WKWebView(frame: .zero, configuration: configuration)
        // 关键：WebView 与原生请求必须用同一个 UA。
        // cf_clearance 与 User-Agent 绑定，UA 不一致时过盾拿到的凭据对原生请求无效。
        webView.customUserAgent = AppConfig.userAgent
        webView.navigationDelegate = context.coordinator
        webView.allowsBackForwardNavigationGestures = true
        let url = purpose == .login
            ? AppConfig.baseURL.appendingPathComponent("login")
            : AppConfig.baseURL
        webView.load(URLRequest(url: url))
        return webView
    }

    func updateUIView(_ webView: WKWebView, context: Context) {
        context.coordinator.parent = self
    }

    final class Coordinator: NSObject, WKNavigationDelegate {

        var parent: WebLoginWebView
        private var notified = false

        init(_ parent: WebLoginWebView) {
            self.parent = parent
        }

        func webView(_ webView: WKWebView, didStartProvisionalNavigation navigation: WKNavigation!) {
            parent.isLoading = true
            parent.onStatus?("正在连接…")
        }

        func webView(_ webView: WKWebView, didFinish navigation: WKNavigation!) {
            parent.isLoading = false
            let url = webView.url?.absoluteString ?? "无地址"
            webView.evaluateJavaScript("document.title") { [weak self] title, _ in
                guard let self = self else { return }
                let name = (title as? String) ?? "（无标题）"
                let blank = (name.isEmpty || name == "（无标题）")
                self.parent.onStatus?(
                    "已加载：\(url)\n标题：\(blank ? "空" : name)"
                )
            }
            harvestCookies(from: webView)
        }

        func webView(_ webView: WKWebView, didFail navigation: WKNavigation!, withError error: Error) {
            parent.isLoading = false
            parent.onStatus?("加载失败：\(error.localizedDescription)")
        }

        func webView(
            _ webView: WKWebView,
            didFailProvisionalNavigation navigation: WKNavigation!,
            withError error: Error
        ) {
            parent.isLoading = false
            parent.onStatus?("无法连接：\(error.localizedDescription)")
        }

        /// 把 linux.do 相关 cookie 同步给 URLSession。
        ///
        /// 这里刻意不要求 `_t`：Cloudflare 过盾只产生 `cf_clearance`，
        /// 用户此时并未登录。早先以 `_t` 为门槛，导致过盾结果永远进不了
        /// `HTTPCookieStorage`，原生请求一直被挑战。
        private func harvestCookies(from webView: WKWebView) {
            guard !notified else { return }
            webView.configuration.websiteDataStore.httpCookieStore.getAllCookies { [weak self] cookies in
                guard let self = self else { return }
                let relevant = cookies.filter { $0.domain.contains("linux.do") }
                guard relevant.contains(where: { $0.name == self.parent.purpose.requiredCookie }) else {
                    return
                }

                for cookie in relevant {
                    HTTPCookieStorage.shared.setCookie(cookie)
                }

                self.notified = true
                DispatchQueue.main.async {
                    self.parent.onReady()
                }
            }
        }
    }
}
