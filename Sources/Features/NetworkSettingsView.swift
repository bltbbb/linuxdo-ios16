import SwiftUI

/// 手动指定服务器 IP。
///
/// 站点在 Cloudflare 后面，默认解析出的地址在国内经常整段不可达。
/// 填一个能连通的 IP 后，app 直接按它建连，TLS 仍以域名握手，证书照常校验。
struct NetworkSettingsView: View {

    @Environment(\.dismiss) private var dismiss

    @State private var input: String = NetworkSettings.customIPs.joined(separator: ", ")
    @State private var status: String?

    var body: some View {
        NavigationStack {
            Form {
                Section {
                    TextEditor(text: $input)
                        .frame(minHeight: 80)
                        .font(.caption.monospaced())
                        .textInputAutocapitalization(.never)
                        .autocorrectionDisabled(true)
                        .accessibilityLabel("服务器 IP")
                } header: {
                    Text("服务器 IP")
                } footer: {
                    Text("多个用逗号分隔。留空则回到自动 DoH 解析。\n\nTLS 的 SNI 与 HTTP 的 Host 仍然是 linux.do，所以证书校验照常进行——这里只换「连到哪个 IP」，不降低任何安全性。")
                }

                if let status = status {
                    Section {
                        Text(status)
                            .font(.footnote)
                            .foregroundColor(.secondary)
                            .textSelection(.enabled)
                    }
                }

                Section {
                    Button {
                        save()
                    } label: {
                        Label("保存", systemImage: "checkmark.circle")
                    }
                    Button(role: .destructive) {
                        input = ""
                        NetworkSettings.clear()
                        status = "已清空，恢复自动解析"
                    } label: {
                        Label("清空并恢复自动", systemImage: "trash")
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

    private func save() {
        let ips = input
            .split(whereSeparator: { $0 == "," || $0 == "\n" || $0 == " " })
            .map { $0.trimmingCharacters(in: .whitespaces) }
            .filter { !$0.isEmpty }

        guard !ips.isEmpty else {
            NetworkSettings.clear()
            status = "已清空，恢复自动解析"
            return
        }

        NetworkSettings.customIPs = ips
        status = "已保存 \(ips.count) 个地址：\(ips.joined(separator: ", "))\n下拉刷新列表试试。"
    }
}
