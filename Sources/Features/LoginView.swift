import SwiftUI
import UIKit

struct LoginView: View {

    enum Field: Hashable {
        case account, password, code
    }

    @EnvironmentObject private var auth: AuthStore

    // 主路径
    @State private var cookieInput = ""

    // 保底
    @State private var apiKeyInput = ""

    // 站点已禁用的旧方式
    @State private var showDisabledPaths = false
    @State private var account = ""
    @State private var password = ""
    @State private var code = ""
    @State private var encryptedResult = ""
    @State private var copiedLink = false

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

                cookieSection
                apiKeySection

                if let message = auth.errorMessage {
                    Section {
                        Text(message)
                            .font(.caption2)
                            .monospaced()
                            .foregroundColor(.red)
                            .textSelection(.enabled)
                    } header: {
                        Text("错误详情（可长按复制）")
                    }
                }

                Section {
                    Button(showDisabledPaths ? "收起其他方式" : "其他方式（站点已禁用）") {
                        withAnimation { showDisabledPaths.toggle() }
                    }
                }

                if showDisabledPaths {
                    deviceSection
                    passwordSection
                    computerSection
                }
            }
            .navigationTitle("LINUX DO")
            .onAppear {
                if account.isEmpty { focused = .account }
            }
        }
    }

    // MARK: - 登录 Cookie（唯一可用路径）

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
                        Label("用这个 Cookie 登录", systemImage: "checkmark.shield").bold()
                    }
                    Spacer()
                }
            }
            .disabled(
                auth.isBusy
                    || cookieInput.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty
            )
        } header: {
            Text("登录（用 Cookie）")
        } footer: {
            Text("电脑浏览器登录 linux.do → F12 → Application → Cookies → https://linux.do → 复制 _t 的值贴到上面。站点禁用了所有程序化登录（用户 API Key、设备码、原生表单都返回 403），浏览器会话 cookie 是唯一剩下的凭据。手机侧全程原生请求，不加载网页。")
        }
    }

    // MARK: - 手动 API Key

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
            Text("若你有管理员创建的 API Key，可直接粘贴。本站的用户 API Key 生成已被禁用。")
        }
    }

    // MARK: - 设备码（原版协议兼容路径）

    private var deviceSection: some View {
        Section {
            if let deviceCode = auth.deviceCode {
                VStack(alignment: .leading, spacing: 12) {
                    Text("在浏览器打开下面的地址，输入这组代码并授权：")
                        .font(.footnote)
                        .foregroundColor(.secondary)

                    Text(deviceCode.userCode)
                        .font(.system(size: 30, weight: .bold, design: .monospaced))
                        .frame(maxWidth: .infinity, alignment: .center)
                        .textSelection(.enabled)

                    Text(deviceCode.verificationUri)
                        .font(.caption2)
                        .textSelection(.enabled)

                    Button {
                        UIPasteboard.general.string = deviceCode.verificationUri
                    } label: {
                        Label("复制授权地址", systemImage: "doc.on.doc")
                    }

                    HStack {
                        if auth.isPolling {
                            ProgressView()
                            Text("等待授权…")
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
                    Task { await auth.beginDeviceLogin() }
                } label: {
                    Label("设备码登录", systemImage: "key.horizontal")
                }
                .disabled(auth.isBusy)
            }
        } header: {
            Text("设备码（原版同款）")
        } footer: {
            Text("原版设备授权还要求 App Attest 和 mTLS 设备证书。此复刻目前只能解析返回结果，无法伪造原版签名身份；如果申请接口返回 invalid_access，通常是设备证明缺失。")
        }
    }

    // MARK: - 账号密码（站点拒绝原生 POST）

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

    // MARK: - 电脑授权（站点已禁用 user api key 生成）

    private var computerSection: some View {
        Section {
            if let url = auth.computerAuthorizationURL {
                Text("1. 复制链接，到电脑浏览器登录论坛并确认授权。")
                    .font(.footnote)
                Button {
                    UIPasteboard.general.string = url.absoluteString
                    copiedLink = true
                } label: {
                    Label(copiedLink ? "链接已复制" : "复制授权链接", systemImage: "doc.on.doc")
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
                    copiedLink = false
                }
            } else {
                Button {
                    focused = nil
                    encryptedResult = ""
                    copiedLink = false
                    auth.beginComputerLogin()
                } label: {
                    Label("生成电脑授权链接", systemImage: "desktopcomputer")
                }
                .disabled(auth.isBusy)
            }
        } header: {
            Text("电脑授权")
        } footer: {
            Text("站点已禁用用户 API Key 生成（/user-api-key/new 返回「无法发布用户 API 密钥」），这条路走不通。")
        }
    }
}
