import SwiftUI

/// 只做一件事：让 WKWebView 走一遍 Cloudflare，把 `cf_clearance` 同步进
/// `HTTPCookieStorage`，供设备授权等原生请求复用。
///
/// 这是原版 App 的做法：它不显式处理 `cf_clearance`（二进制里该字符串一次不出现），
/// 而是靠 WKWebView 是真浏览器这一点——挑战 JS 自己跑完，随后整袋 cookie 交给原生请求。
/// 见原版符号 `CommunityWebSession.swift` / `WebBrowserWebView.swift`。
struct CloudflareBypassView: View {

    @Environment(\.dismiss) private var dismiss

    /// 拿到凭据后回调；调用方据此继续设备授权。
    var onReady: () -> Void

    @State private var isLoading = true
    @State private var finished = false
    /// WebView 回传的真实状态（URL / 标题 / 错误）。
    /// 空白页时这是唯一能区分「没拿到页面」和「页面渲染不了」的证据。
    @State private var detail: String?

    var body: some View {
        NavigationStack {
            ZStack(alignment: .top) {
                WebLoginWebView(
                    purpose: .cloudflareBypass,
                    isLoading: $isLoading,
                    onStatus: { detail = $0 }
                ) {
                    guard !finished else { return }
                    finished = true
                    persistCookies()
                    onReady()
                    dismiss()
                }
                .ignoresSafeArea(edges: .bottom)

                VStack(spacing: 8) {
                    statusBar
                    if let text = detail {
                        Text(text)
                            .font(.caption2)
                            .monospaced()
                            .foregroundColor(.secondary)
                            .multilineTextAlignment(.leading)
                            .padding(10)
                            .frame(maxWidth: .infinity, alignment: .leading)
                            .background(.ultraThinMaterial, in: RoundedRectangle(cornerRadius: 10))
                            .textSelection(.enabled)
                    }
                }
                .padding(.horizontal, 16)
                .padding(.top, 10)
            }
            .navigationTitle("安全验证")
            .navigationBarTitleDisplayMode(.inline)
            .toolbar {
                ToolbarItem(placement: .cancellationAction) {
                    Button("取消") { dismiss() }
                }
                ToolbarItem(placement: .confirmationAction) {
                    // 兜底：挑战页长时间不出结果时，允许先跳过让原生请求试一次。
                    Button("跳过") {
                        persistCookies()
                        onReady()
                        dismiss()
                    }
                    .disabled(finished)
                }
            }
        }
    }

    private var statusBar: some View {
        HStack(spacing: 8) {
            if isLoading {
                ProgressView()
                Text("正在通过安全验证…")
            } else {
                Image(systemName: "checkmark.shield")
                Text(finished ? "验证通过" : "如出现验证框，请点击完成")
            }
        }
        .font(.footnote)
        .padding(.horizontal, 14)
        .padding(.vertical, 8)
        .background(.ultraThinMaterial, in: Capsule())
    }

    /// 过盾结果也存进钥匙串：`HTTPCookieStorage` 是沙盒存储，卸载重装会清空，
    /// 而 cf_clearance 有效期较长，没必要让用户重蹈一次。
    private func persistCookies() {
        if let header = DiscourseClient.shared.currentCookieHeader() {
            CookieVault.save(header)
        }
    }
}
