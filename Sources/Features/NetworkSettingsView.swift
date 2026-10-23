import SwiftUI

/// 网络设置：一键实测、自定义反代地址、手动指定服务器 IP。
///
/// 站点走 Cloudflare，中间设备对握手里的 SNI 做精确匹配并 RST，
/// 所以「换哪个 IP 都不通」。客户端已经用带尾点的 SNI 绕开这件事，
/// 正常情况下这里什么都不用填。
struct NetworkSettingsView: View {

    @Environment(\.dismiss) private var dismiss

    @State private var input: String = NetworkSettings.customIPs.joined(separator: ", ")
    @State private var baseURLInput: String = NetworkSettings.customBaseURL?.absoluteString ?? ""
    @State private var status: String?
    @State private var testing = false

    var body: some View {
        NavigationStack {
            Form {
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
                    Text("DoH 解析 → TLS 握手 → 取一次 /session/csrf.json。\n显示 HTTP 状态码就说明链路已通；显示「被 Cloudflare 挑战拦截」说明要重新导入带 cf_clearance 的 Cookie。")
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
                    TextField("https://linux.do", text: $baseURLInput)
                        .textInputAutocapitalization(.never)
                        .autocorrectionDisabled(true)
                        .keyboardType(.URL)
                        .accessibilityLabel("自定义 API 根地址")
                } header: {
                    Text("自定义 API 根地址（可选）")
                } footer: {
                    Text("留空就用官方 https://linux.do。填自建反代（例如自己的 VPS 反代）时，Cookie 要按该域名重新登录。")
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
                    Text("一般不用填，客户端自己用 DoH 解析并挑能连通的地址。多个用逗号分隔，留空则自动。\n\nTLS 的 SNI 与 HTTP 的 Host 仍然是 linux.do，证书照常校验——这里只换「连到哪个 IP」，不降低任何安全性。")
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
                        NetworkSettings.clear()
                        NetworkSettings.customBaseURL = nil
                        status = "已清空，恢复默认"
                    } label: {
                        Label("清空并恢复默认", systemImage: "trash")
                    }
                }
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

    private func runDiagnose() {
        testing = true
        status = nil
        Task {
            status = await DirectTransport.shared.diagnose()
            testing = false
        }
    }

    private func save() {
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
