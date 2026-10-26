import SwiftUI
import UIKit

/// 网络设置：安全直连（DoH + ECH）、一键实测、自定义反代、UA 覆盖、服务器 IP。
struct NetworkSettingsView: View {

    @Environment(\.dismiss) private var dismiss
    @EnvironmentObject private var auth: AuthStore

    @State private var input: String = NetworkSettings.customIPs.joined(separator: ", ")
    @State private var baseURLInput: String = NetworkSettings.customBaseURL?.absoluteString ?? ""
    @State private var uaInput: String = NetworkSettings.customUserAgent ?? ""
    @State private var status: String?
    @State private var testing = false
    @State private var secureDirect = DohProxyService.shared.isRunning
    @State private var shareItem: ShareItem?
    @State private var challengePort: Int?
    /// 是否弹出安全验证页。测试入口也要走一遍 WebView 过盾：
    /// cf_clearance 绑定出口 IP，换网络（WiFi ↔ 蜂窝）后旧的必然失效，
    /// 只有当前网络下由 WebView 现拿的凭据才能让原生请求通过。
    @State private var showingBypass = false


    @State private var quicEnabled = NetworkSettings.preferQUIC
    /// 最近一次请求实际协商到的 HTTP 版本（h3 / h2 / http/1.1）。
    @State private var lastProtocol: String?

    var body: some View {
        NavigationStack {
            Form {
                // QUIC 放在最前面：这是唯一不需要梯子、不需要代理、
                // WiFi 与蜂窝都一样的出网方式，也是原版的做法。
                Section {
                    Toggle("优先 QUIC / HTTP3", isOn: $quicEnabled)
                        .onChange(of: quicEnabled) { enabled in
                            DiscourseClient.shared.setPreferQUIC(enabled)
                            lastProtocol = nil
                            status = enabled
                                ? "已切到 QUIC 模式，下次请求直接走 HTTP/3。"
                                : "已关闭 QUIC，回到 TCP。"
                        }
                    Button {
                        probeProtocol()
                    } label: {
                        Label("测试当前出网协议", systemImage: "speedometer")
                    }
                    if let lastProtocol = lastProtocol {
                        Text("实际协议：\(lastProtocol)")
                            .font(.caption.monospaced())
                            .foregroundColor(.secondary)
                    }
                } header: {
                    Text("QUIC（推荐）")
                } footer: {
                    Text("原版的连接统计是 100% HTTP/3、0% 走 TCP。走 TCP 时 TLS 握手里的域名是明文，部分网络会直接重置连接；QUIC 把握手加密，看不到域名，因此不需要梯子。\n\n点「测试当前出网协议」如果显示 h3，说明 QUIC 生效。")
                }

                Section {
                    Toggle("安全直连（DoH + ECH）", isOn: $secureDirect)
                        .onChange(of: secureDirect) { applySecureDirect($0) }
                    Button {
                        shareCA()
                    } label: {
                        Label("安装根证书", systemImage: "checkmark.seal")
                    }
                    if let port = DohProxyService.shared.runningPort {
                        Button {
                            challengePort = port
                        } label: {
                            Label("通过 Cloudflare 验证", systemImage: "checkmark.shield")
                        }
                        Text("1. 先到 设置 → Wi-Fi → 当前网络 → 配置代理 → 手动，服务器填 127.0.0.1，端口填 \(port)\n2. 回到这里点上面这一行，等挑战页自己跑完\n3. 点页面右上角「完成」保存凭据，然后去 Wi-Fi 里把代理关掉")
                            .font(.caption)
                            .foregroundColor(.secondary)
                    }
                } header: {
                    Text("安全直连")
                } footer: {
                    Text("开启后原生请求经本机代理，用 ECH 加密 ClientHello 出网，中间设备看不到 linux.do。\n\n首次使用：点「安装根证书」→ 存到「文件」→ 点开安装描述文件 → 设置 → 通用 → 关于本机 → 证书信任设置 → 为该证书打开完全信任。\n\n如果仍被 Cloudflare 挑战，用上面的验证页让 WebKit 亲自过盾。")
                }

                Section {
                    Button {
                        if let url = DohProxyService.shared.makeDNSProfile() {
                            shareItem = ShareItem(url: url)
                        } else {
                            status = "生成加密 DNS 描述文件失败"
                        }
                    } label: {
                        Label("安装加密 DNS（DoH）", systemImage: "lock.shield")
                    }
                } header: {
                    Text("加密 DNS（推荐先装）")
                } footer: {
                    Text("装一次对整个系统生效，WiFi 和蜂窝都覆盖，不用再设 Wi-Fi 代理。\n\n为什么需要：网页视图走系统 DNS，被污染时会解析到假 IP、加载超时。装上后解析走 DoH，挑战页才能打开。\n\n安装后到「设置 → 通用 → VPN 与设备管理」确认已安装。")
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
                    Button {
                        showingBypass = true
                    } label: {
                        Label("测试设备码登录", systemImage: "number.square")
                    }
                    if let code = auth.deviceCode {
                        Text("授权码：\(code.userCode)\n验证地址：\(code.activationURL?.absoluteString ?? code.verificationUri)")
                            .font(.caption.monospaced())
                            .textSelection(.enabled)
                    }
                    if auth.isPolling {
                        Text("正在轮询授权结果…").font(.caption).foregroundColor(.secondary)
                    }
                    if let error = auth.errorMessage {
                        Text(error)
                            .font(.caption.monospaced())
                            .foregroundColor(.red)
                            .textSelection(.enabled)
                    }
                } header: {
                    Text("设备码登录（测试）")
                } footer: {
                    Text("不会退出当前登录。失败只显示错误；成功才会替换为新会话。\n拿到 user_code 后，用「通过 Cloudflare 验证」那个页面打开验证地址完成授权。")
                }

                Section {
                    Button(role: .destructive) {
                        Task { await auth.signOut() }
                    } label: {
                        Label("退出登录", systemImage: "rectangle.portrait.and.arrow.right")
                    }
                } footer: {
                    Text("退出后回到登录页，可重新走设备授权流程。")
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
            .fullScreenCover(item: Binding(
                get: { challengePort.map { ChallengeTarget(id: $0) } },
                set: { challengePort = $0?.id }
            )) { target in
                ChallengeView(port: target.id)
            }
            .fullScreenCover(isPresented: $showingBypass) {
                CloudflareBypassView {
                    Task { await auth.beginDeviceLogin() }
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

    // MARK: - QUIC 探测

    /// 发一次最轻的请求，看实际协商到的协议。
    /// h3 说明 QUIC 生效；h2 / http/1.1 说明还在走 TCP。
    private func probeProtocol() {
        status = "正在测试出网协议…"
        lastProtocol = nil
        Task {
            do {
                _ = try await DiscourseClient.shared.latestForProtocolProbe()
                let name = ProtocolCollector.shared.lastProtocolName ?? "未知"
                lastProtocol = name
                status = name == "h3"
                    ? "QUIC 生效：请求走的是 HTTP/3，不需要梯子。"
                    : "当前走的是 \(name)，QUIC 未生效（服务器未提供 h3 或 UDP 被拦）。"
            } catch {
                lastProtocol = ProtocolCollector.shared.lastProtocolName
                status = "测试失败：\(error.localizedDescription)"
            }
        }
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

private struct ChallengeTarget: Identifiable {
    let id: Int
}
