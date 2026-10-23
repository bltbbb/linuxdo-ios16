import SwiftUI
import UIKit
import WebKit

/// 渲染 Discourse 返回的 `cooked` HTML。
/// 与 PWA 方案的区别仅在于：仍在原生列表内、走原生导航与原生登录态。
struct RichTextWebView: UIViewRepresentable {

    let html: String
    @Binding var height: CGFloat

    func makeCoordinator() -> Coordinator {
        Coordinator(self)
    }

    func makeUIView(context: Context) -> WKWebView {
        let configuration = WKWebViewConfiguration()
        configuration.dataDetectorTypes = [.link]
        let webView = WKWebView(frame: .zero, configuration: configuration)
        webView.navigationDelegate = context.coordinator
        webView.isOpaque = false
        webView.backgroundColor = .clear
        webView.scrollView.backgroundColor = .clear
        webView.scrollView.isScrollEnabled = false
        webView.scrollView.contentInset = .zero
        webView.setContentHuggingPriority(.required, for: .vertical)
        webView.setContentCompressionResistancePriority(.required, for: .vertical)
        return webView
    }

    func updateUIView(_ webView: WKWebView, context: Context) {
        context.coordinator.parent = self
        guard context.coordinator.loadedHTML != html else { return }
        context.coordinator.loadedHTML = html
        webView.loadHTMLString(RichTextWebView.document(body: html), baseURL: AppConfig.baseURL)
    }

    static func dismantleUIView(_ webView: WKWebView, coordinator: Coordinator) {
        webView.stopLoading()
        webView.navigationDelegate = nil
    }

    final class Coordinator: NSObject, WKNavigationDelegate {

        var parent: RichTextWebView
        var loadedHTML: String?

        init(_ parent: RichTextWebView) {
            self.parent = parent
        }

        func webView(_ webView: WKWebView, didFinish navigation: WKNavigation!) {
            measure(webView)
        }

        func webView(
            _ webView: WKWebView,
            decidePolicyFor navigationAction: WKNavigationAction,
            decisionHandler: @escaping (WKNavigationActionPolicy) -> Void
        ) {
            guard let url = navigationAction.request.url else {
                decisionHandler(.allow)
                return
            }
            if navigationAction.navigationType == .linkActivated {
                decisionHandler(.cancel)
                UIApplication.shared.open(url, options: [:], completionHandler: nil)
            } else {
                decisionHandler(.allow)
            }
        }

        private func measure(_ webView: WKWebView) {
            webView.evaluateJavaScript("Math.ceil(document.body.scrollHeight)") { [weak self] value, _ in
                guard let self = self, let number = value as? NSNumber else { return }
                let newHeight = CGFloat(truncating: number)
                guard newHeight > 0 else { return }
                if abs(self.parent.height - newHeight) > 0.5 {
                    DispatchQueue.main.async {
                        self.parent.height = newHeight
                    }
                }
            }
        }
    }

    static func document(body: String) -> String {
        """
        <!doctype html>
        <html><head>
        <meta charset="utf-8">
        <meta name="viewport" content="width=device-width, initial-scale=1, maximum-scale=1">
        <style>
        :root { color-scheme: light dark; }
        body {
            margin: 0; padding: 2px 0;
            font: -apple-system-body;
            font-family: -apple-system, "PingFang SC", "Helvetica Neue", sans-serif;
            font-size: 16px; line-height: 1.62;
            word-wrap: break-word; overflow-wrap: anywhere;
            -webkit-text-size-adjust: 100%;
        }
        a { color: #1a7f37; text-decoration: none; }
        img, video, iframe, svg { max-width: 100% !important; height: auto; border-radius: 8px; }
        pre {
            background: rgba(127,127,127,0.12); padding: 10px 12px; border-radius: 8px;
            overflow-x: auto; font-size: 13px; line-height: 1.45;
        }
        code {
            font-family: ui-monospace, SFMono-Regular, Menlo, monospace; font-size: 13px;
            background: rgba(127,127,127,0.12); padding: 1px 4px; border-radius: 4px;
        }
        pre code { background: transparent; padding: 0; }
        blockquote {
            margin: 8px 0; padding-left: 12px;
            border-left: 3px solid rgba(127,127,127,0.45);
            color: rgba(127,127,127,1);
        }
        table { border-collapse: collapse; max-width: 100%; font-size: 14px; }
        th, td { border: 1px solid rgba(127,127,127,0.35); padding: 4px 8px; }
        aside.quote { display: none; }
        .onebox, .lightbox-wrapper { border-radius: 8px; overflow: hidden; }
        </style>
        </head><body>\(body)</body></html>
        """
    }
}
