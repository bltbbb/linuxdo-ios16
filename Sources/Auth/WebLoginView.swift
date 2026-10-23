import SwiftUI
import WebKit

/// 可靠的登录路径：用 WKWebView 打开真实登录页。
/// 它能执行 Cloudflare 的挑战 JS、拿到 `cf_clearance` 与 `_t`，
/// 再把 cookie 灌进 `HTTPCookieStorage`，供 URLSession 复用。
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

    @Binding var isLoading: Bool
    var onLoggedIn: () -> Void

    func makeCoordinator() -> Coordinator {
        Coordinator(self)
    }

    func makeUIView(context: Context) -> WKWebView {
        let configuration = WKWebViewConfiguration()
        configuration.websiteDataStore = .default()
        let webView = WKWebView(frame: .zero, configuration: configuration)
        webView.navigationDelegate = context.coordinator
        webView.allowsBackForwardNavigationGestures = true
        webView.load(URLRequest(url: AppConfig.baseURL.appendingPathComponent("login")))
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
        }

        func webView(_ webView: WKWebView, didFinish navigation: WKNavigation!) {
            parent.isLoading = false
            harvestCookies(from: webView)
        }

        func webView(_ webView: WKWebView, didFail navigation: WKNavigation!, withError error: Error) {
            parent.isLoading = false
        }

        func webView(
            _ webView: WKWebView,
            didFailProvisionalNavigation navigation: WKNavigation!,
            withError error: Error
        ) {
            parent.isLoading = false
        }

        /// 登录成功后 `_t` 会话 cookie 存在，此时把 linux.do 相关 cookie 全部同步给 URLSession。
        private func harvestCookies(from webView: WKWebView) {
            guard !notified else { return }
            webView.configuration.websiteDataStore.httpCookieStore.getAllCookies { [weak self] cookies in
                guard let self = self else { return }
                let relevant = cookies.filter { $0.domain.contains("linux.do") }
                guard relevant.contains(where: { $0.name == "_t" }) else { return }

                for cookie in relevant {
                    HTTPCookieStorage.shared.setCookie(cookie)
                }

                self.notified = true
                DispatchQueue.main.async {
                    self.parent.onLoggedIn()
                }
            }
        }
    }
}
