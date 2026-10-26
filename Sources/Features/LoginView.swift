import SwiftUI
import UIKit

struct LoginView: View {

    enum Field: Hashable {
        case account, password, code
    }

    @EnvironmentObject private var auth: AuthStore

    // 主路径：设备授权
    @State private var copiedCode = false
    @State private var copiedLink = false

    // 兜底
    @State private var showFallbacks = false
    @State private var cookieInput = ""
    @State private var apiKeyInput = ""
    @State private var account = ""
    @State private var password = ""
    @State private var code = ""
    @State private var encryptedResult = ""
    /// 授权码生成时刻，用于倒计时。由 onChange 跟随 auth.deviceCode 维护。
    /// 是否需要在出码前先过一次 Cloudflare 盾。
    /// 手上已有 cf_clearance 时直接出码，避免每次都弹验证页。
    @State private var showingBypass = false
    @State private var codeIssuedAt: Date?

    @FocusState private var focused: Field?

    var body: some View {
        NavigationStack {
            Form {
                if auth.isRestoring {
                    Section {
                        HStack(spacing: 8) {
                            ProgressView()
                            Text("正在恢复上次的会话…")
                                .font(.footnote)
                                .foregroundColor(.secondary)
                        }
                    }
                }

                deviceSection

                if let message = auth.errorMessage {
                    Section {
                        Text(message)
                            .font(.caption2)
                            .monospaced()
                            .foregroundColor(.red)
                            .textSelection(.enabled)
                        Button {
                            showingBypass = true
                        } label: {
                            Label("重新过安全验证", systemImage: "arrow.clockwise.shield")
                        }
                        .disabled(auth.isBusy)
                    } header: {
                        Text("错误详情（可长按复制）")
                    }
                }

                Section {
                    Button(showFallbacks ? "收起其他登录方式" : "其他登录方式") {
                        withAnimation { showFallbacks.toggle() }
                    }
                }

                if showFallbacks {
                    cookieSection
                    apiKeySection
                    computerSection
                    passwordSection
                }
            }
            .navigationTitle("LINUX DO")
            .onChange(of: auth.deviceCode?.deviceCode) { _ in
                codeIssuedAt = auth.deviceCode == nil ? nil : Date()
            }
            .sheet(isPresented: $showingBypass) {
                CloudflareBypassView {
                    Task { await auth.beginDeviceLogin() }
                }
            }
        }
    }

    /// 本地是否已有 Cloudflare 放行凭据。
    /// 只判断存在性：是否仍有效只有真发一次请求才知道，
    /// 过期时下面的「重新过安全验证」可以重来。
    private var hasClearance: Bool {
        (HTTPCookieStorage.shared.cookies ?? []).contains { $0.name == "cf_clearance" }
    }
    // MARK: - 设备授权（主路径）

    private var deviceSection: some View {
        Section {
            if let code = auth.deviceCode {
                VStack(alignment: .leading, spacing: 14) {
                    Text("在浏览器打开下面的地址，输入这组授权码并确认。")
                        .font(.footnote)
                        .foregroundColor(.secondary)

                    HStack {
                        Text(code.userCode)
                            .font(.system(size: 30, weight: .bold, design: .monospaced))
                            .textSelection(.enabled)
                        Spacer()
                        Button {
                            UIPasteboard.general.string = code.userCode
                            copiedCode = true
                        } label: {
                            Image(systemName: copiedCode ? "checkmark" : "doc.on.doc")
                        }
                        .buttonStyle(.borderless)
                        .accessibilityLabel("复制授权码")
                    }

                    if let url = code.activationURL {
                        Text(url.absoluteString)
                            .font(.caption2)
                            .foregroundColor(.secondary)
                            .textSelection(.enabled)
                        Button {
                            UIPasteboard.general.string = url.absoluteString
                            copiedLink = true
                        } label: {
                            Label(copiedLink ? "地址已复制" : "复制授权地址", systemImage: "doc.on.doc")
                        }
                    }

                    if let issuedAt = codeIssuedAt {
                        TimelineView(.periodic(from: Date(), by: 1)) { context in
                            let deadline = issuedAt.addingTimeInterval(
                                TimeInterval(max(code.expiresIn, 60))
                            )
                            let remain = max(0, Int(deadline.timeIntervalSince(context.date)))
                            Text(
                                remain > 0
                                    ? "剩余 \(remain / 60):\(String(format: "%02d", remain % 60))"
                                    : "授权码已过期，请重新获取"
                            )
                            .font(.caption)
                            .foregroundColor(remain > 60 ? .secondary : .orange)
                        }
                    }

                    HStack(spacing: 8) {
                        if auth.isPolling {
                            ProgressView()
                            Text("等待浏览器授权…")
                                .font(.footnote)
                                .foregroundColor(.secondary)
                        }
                        Spacer()
                        Button("取消") { auth.cancelDeviceLogin() }
                            .font(.footnote)
                    }
                }
                .padding(.vertical, 6)
            } else {
                Button {
                    focused = nil
                    copiedCode = false
                    copiedLink = false
                    if hasClearance {
                        Task { await auth.beginDeviceLogin() }
                    } else {
                        showingBypass = true
                    }
                } label: {
                    HStack {
                        Spacer()
                        if auth.isBusy {
                            ProgressView()
                        } else {
                            Label("设备授权登录", systemImage: "key.horizontal.fill").bold()
                        }
                        Spacer()
                    }
                }
                .disabled(auth.isBusy)
            }
        } header: {
            Text("登录（设备授权）")
        } footer: {
            Text("生成 8 位授权码后，在任意浏览器打开 linux.do/user-api-key/activate 输入即可。不需要密码，也不需要粘贴 Cookie；授权得到的密钥不会自动过期。")
        }
    }

    // MARK: - 兜底：Cookie

    private var cookieSection: some View {
        Section {
            TextEditor(text: $cookieInput)
                .frame(minHeight: 72)
                .font(.caption.monospaced())
                .textInputAutocapitalization(.never)
                .autocorrectionDisabled(true)
                .accessibilityLabel("登录 Cookie")

            Button {
                focused = nil
                Task { await auth.signInWithCookie(cookieInput) }
            } label: {
                HStack {
                    Spacer()
                    if auth.isBusy {
                        ProgressView()
                    } else {
                        Label("用这个 Cookie 登录", systemImage: "checkmark.shield")
                    }
                    Spacer()
                }
            }
            .disabled(
                auth.isBusy
                    || cookieInput.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty
            )
        } header: {
            Text("用 Cookie 登录")
        } footer: {
            Text("设备授权不可用时的退路：电脑浏览器登录 linux.do → F12 → Application → Cookies → 复制 _t 的值。")
        }
    }

    // MARK: - 兜底：手动 API Key

    private var apiKeySection: some View {
        Section {
            TextField("粘贴 User API Key", text: $apiKeyInput)
                .textInputAutocapitalization(.never)
                .autocorrectionDisabled(true)
                .font(.caption.monospaced())
            Button {
                focused = nil
                Task { await auth.signInWithAPIKey(apiKeyInput) }
            } label: {
                Label("用这个 Key 登录", systemImage: "key.fill")
            }
            .disabled(
                auth.isBusy
                    || apiKeyInput.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty
            )
        } header: {
            Text("手动粘贴 API Key")
        } footer: {
            Text("如果已经在站点或用原版 App 授权过，直接粘贴那个 User API Key 也可以。")
        }
    }

    // MARK: - 兜底：电脑授权（手工粘贴加密结果）

    private var computerSection: some View {
        Section {
            if let url = auth.computerAuthorizationURL {
                Text("1. 复制链接，到电脑浏览器登录论坛并确认授权。")
                    .font(.footnote)
                Button {
                    UIPasteboard.general.string = url.absoluteString
                } label: {
                    Label("复制授权链接", systemImage: "doc.on.doc")
                }
                Text("2. 把电脑网页显示的整段加密结果粘回下面。")
                    .font(.footnote)
                TextEditor(text: $encryptedResult)
                    .frame(minHeight: 90)
                    .font(.caption.monospaced())
                    .textInputAutocapitalization(.never)
                    .autocorrectionDisabled(true)
                Button {
                    focused = nil
                    Task {
                        await auth.completeComputerLogin(encryptedResult: encryptedResult)
                        if auth.isLoggedIn { encryptedResult = "" }
                    }
                } label: {
                    Label("完成授权并登录", systemImage: "checkmark.shield")
                }
                .disabled(
                    auth.isBusy
                        || encryptedResult.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty
                )
                Button("取消本次授权", role: .cancel) {
                    auth.cancelComputerLogin()
                    encryptedResult = ""
                }
            } else {
                Button {
                    focused = nil
                    encryptedResult = ""
                    auth.beginComputerLogin()
                } label: {
                    Label("生成电脑授权链接", systemImage: "desktopcomputer")
                }
                .disabled(auth.isBusy)
            }
        } header: {
            Text("电脑授权（手工粘贴）")
        } footer: {
            Text("经典 User API Key 流程：电脑打开 /user-api-key/new 授权后，把加密串贴回手机解密。设备授权走不通时可用。")
        }
    }

    // MARK: - 兜底：账号密码

    private var passwordSection: some View {
        Section {
            TextField("用户名或邮箱", text: $account)
                .textContentType(.username)
                .textInputAutocapitalization(.never)
                .autocorrectionDisabled(true)
                .focused($focused, equals: .account)

            SecureField("密码", text: $password)
                .textContentType(.password)
                .focused($focused, equals: .password)

            if auth.needsSecondFactor {
                TextField("6 位动态验证码", text: $code)
                    .keyboardType(.numberPad)
                    .textContentType(.oneTimeCode)
                    .focused($focused, equals: .code)
            }

            Button {
                focused = nil
                Task {
                    await auth.signIn(
                        account: account,
                        password: password,
                        secondFactorCode: auth.needsSecondFactor ? code : nil
                    )
                }
            } label: {
                Label("登录", systemImage: "person.badge.key")
            }
            .disabled(auth.isBusy)
        } header: {
            Text("账号密码")
        } footer: {
            Text("实测 POST /session 返回 403：站点拒绝非浏览器客户端提交登录。")
        }
    }
}
