import SwiftUI
import UIKit

/// 网络设置：安全直连（DoH + ECH）、一键实测、自定义反代、UA 覆盖、服务器 IP。
struct NetworkSettingsView: View {

    @Environment(\.dismiss) private var dismiss

    @State private var input: String = NetworkSettings.customIPs.joined(separator: ", ")
    @State private var baseURLInput: String = NetworkSettings.customBaseURL?.absoluteString ?? ""
    @State private var uaInput: String = NetworkSettings.customUserAgent ?? ""
    @State private var status: String?
    @State private var testing = false
    @State private var secureDirect = DohProxyService.shared.isRunning
    @State private var shareItem: ShareItem?

    var body: some View {
        NavigationStack {
            Form {
                Section {
                    Toggle("安全直连（DoH + ECH）", isOn: $secureDirect)
                        .onChange(of: secureDirect) { applySecureDirect($0) }
                    Button {
                        shareCA()
                    } label: {
                        Label("安装根证书", systemImage: "checkmark.seal")
                    }
                } header: {
                    Text("安全直连")
                } footer: {
                    Text("开启后所有请求经本机代理，用 ECH 加密 ClientHello 出网，中间设备看不到 linux.do，绕开域名阻断。\n\n首次使用：点「安装根证书」→ 存到「文件」→ 点开安装描述文件 → 设置 → 通用 → 关于本机 → 证书信任设置 → 为该证书打开完全信任。")
                }

                if let status = status {
                    Section {
                        Text(status)
                            .font(.footnote.monospaced())
                            .foregroundColor(.secondary)
                            .textSelection(.enabled)
                    }
                }

                Section {
                    Button {
                        runDiagnose()
                    } label: {
                        if testing {
                            HStack(spacing: 8) {
                                ProgressView()
                                Text("正在实测…")
                            }
                        } else {
                            Label("用当前网络实测", systemImage: "antenna.radiowaves.left.and.right")
                        }
                    }
                    .disabled(testing)
                } header: {
                    Text("连通性")
                } footer: {
                    Text("DoH 解析 → TLS 握手 → 取一次 /session/csrf.json。显示 HTTP 状态码说明链路已通；显示「被 Cloudflare 挑战拦截」说明还缺有效的 cf_clearance。")
                }

                Section {
                    TextField("https://linux.do", text: $baseURLInput)
                        .textInputAutocapitalization(.never)
                        .autocorrectionDisabled(true)
                        .keyboardType(.URL)
                        .accessibilityLabel("自定义 API 根地址")
                } header: {
                    Text("自定义 API 根地址（可选）")
                } footer: {
                    Text("留空就用官方 https://linux.do。填自建反代时，Cookie 要按该域名重新登录。")
                }

                Section {
                    TextEditor(text: $uaInput)
                        .frame(minHeight: 60)
                        .font(.caption.monospaced())
                        .textInputAutocapitalization(.never)
                        .autocorrectionDisabled(true)
                        .accessibilityLabel("User-Agent")
                } header: {
                    Text("User-Agent（可选）")
                } footer: {
                    Text("Cloudflare 的 cf_clearance 与 User-Agent 绑定。要复用浏览器签发的 cf_clearance，这里必须填那个浏览器一模一样的 UA。留空用内置的 Safari UA。")
                }

                Section {
                    TextEditor(text: $input)
                        .frame(minHeight: 80)
                        .font(.caption.monospaced())
                        .textInputAutocapitalization(.never)
                        .autocorrectionDisabled(true)
                        .accessibilityLabel("服务器 IP")
                } header: {
                    Text("服务器 IP（可选）")
                } footer: {
                    Text("一般不用填。开启安全直连后，寻址由本地代理的 DoH 负责。多个用逗号分隔，留空则自动。")
                }

                Section {
                    Button {
                        save()
                    } label: {
                        Label("保存", systemImage: "checkmark.circle")
                    }
                    Button(role: .destructive) {
                        input = ""
                        baseURLInput = ""
                        uaInput = ""
                        NetworkSettings.clear()
                        NetworkSettings.customBaseURL = nil
                        NetworkSettings.customUserAgent = nil
                        status = "已清空，恢复默认"
                    } label: {
                        Label("清空并恢复默认", systemImage: "trash")
                    }
                }
                Section {
                    HStack {
                        Text("版本")
                        Spacer()
                        Text(Self.versionText)
                            .foregroundColor(.secondary)
                    }
                } footer: {
                    Text("看不到「安装根证书」说明装的是旧包，请从 Releases 重新安装最新版。")
                }
            }
            .sheet(item: $shareItem) { item in
                ActivityView(url: item.url)
            }
            .navigationTitle("网络设置")
            .navigationBarTitleDisplayMode(.inline)
            .toolbar {
                ToolbarItem(placement: .cancellationAction) {
                    Button("关闭") { dismiss() }
                }
            }
        }
    }

    // MARK: - 安全直连

    private func applySecureDirect(_ enabled: Bool) {
        if enabled {
            if let port = DohProxyService.shared.start(host: "linux.do") {
                DiscourseClient.shared.setProxyPort(port)
                status = "安全直连已启动\n本地代理 127.0.0.1:\(port)\n若仍被挑战，请确认根证书已安装并完全信任。"
            } else {
                secureDirect = false
                DiscourseClient.shared.setProxyPort(nil)
                status = "启动失败：Rust 代理没能起来，查看 Xcode 日志里的 doh_proxy 输出。"
            }
        } else {
            DohProxyService.shared.stop()
            DiscourseClient.shared.setProxyPort(nil)
            status = "安全直连已关闭，回到系统网络。"
        }
    }

    private func shareCA() {
        guard let ca = DohProxyService.shared.rootCA(),
              let url = DohProxyService.shared.makeProfile(ca: ca) else {
            status = "生成根证书失败"
            return
        }
        shareItem = ShareItem(url: url)
    }

    // MARK: - 其它

    private static var versionText: String {
        let version = Bundle.main.infoDictionary?["CFBundleShortVersionString"] as? String ?? "?"
        let build = Bundle.main.infoDictionary?["CFBundleVersion"] as? String ?? "?"
        return "\(version) (\(build))"
    }

    private func runDiagnose() {
        testing = true
        status = nil
        Task {
            status = await DirectTransport.shared.diagnose()
            testing = false
        }
    }

    private func save() {
        NetworkSettings.customUserAgent = uaInput

        let trimmedBase = baseURLInput.trimmingCharacters(in: .whitespacesAndNewlines)
        if trimmedBase.isEmpty {
            NetworkSettings.customBaseURL = nil
        } else if let url = URL(string: trimmedBase), url.scheme != nil, url.host != nil {
            NetworkSettings.customBaseURL = url
        } else {
            status = "反代地址无效，需要形如 https://example.com"
            return
        }

        let ips = input
            .split(whereSeparator: { $0 == "," || $0 == "\n" || $0 == " " })
            .map { $0.trimmingCharacters(in: .whitespaces) }
            .filter { !$0.isEmpty }

        if ips.isEmpty {
            NetworkSettings.clear()
        } else {
            NetworkSettings.customIPs = ips
        }

        let ipLine = ips.isEmpty ? "服务器 IP：自动" : "服务器 IP：\(ips.joined(separator: ", "))"
        let baseLine = NetworkSettings.customBaseURL.map { "反代：\($0.absoluteString)" } ?? "反代：官方 linux.do"
        status = "已保存\n\(ipLine)\n\(baseLine)\n\n返回列表下拉刷新。"
    }
}

private struct ShareItem: Identifiable {
    let id = UUID()
    let url: URL
}

private struct ActivityView: UIViewControllerRepresentable {
    let url: URL

    func makeUIViewController(context: Context) -> UIActivityViewController {
        UIActivityViewController(activityItems: [url], applicationActivities: nil)
    }

    func updateUIViewController(_ controller: UIActivityViewController, context: Context) {}
}
