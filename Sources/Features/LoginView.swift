import SwiftUI
import UIKit

struct LoginView: View {

    enum Field: Hashable {
        case account, password, code
    }

    @EnvironmentObject private var auth: AuthStore
    @State private var account = ""
    @State private var password = ""
    @State private var code = ""
    @State private var encryptedResult = ""
    @State private var copiedLink = false
    @State private var apiKeyInput = ""
    @State private var cookieInput = ""
    @FocusState private var focused: Field?

    var body: some View {
        NavigationStack {
            Form {
                computerSection

                Section {
                    TextField("用户名或邮箱", text: $account)
                        .textContentType(.username)
                        .textInputAutocapitalization(.never)
                        .autocorrectionDisabled(true)
                        .focused($focused, equals: .account)

                    SecureField("密码", text: $password)
                        .textContentType(.password)
                        .focused($focused, equals: .password)
                } header: {
                    Text("账号密码登录（备用）")
                } footer: {
                    Text("直接向网站提交登录。若网站要求额外验证，可使用上方的电脑授权。")
                }
                .disabled(auth.isBusy || auth.isWaitingForComputer)

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
                    Text("任何途径拿到的 User API Key 都能粘到这里。这条路径不发起授权、不打开网页，只校验这个 key 能否读到你的账号。")
                }

                Section {
                    TextEditor(text: $cookieInput)
                        .frame(minHeight: 70)
                        .font(.caption.monospaced())
                        .textInputAutocapitalization(.never)
                        .autocorrectionDisabled(true)
                        .accessibilityLabel("登录 Cookie")
                    Button {
                        focused = nil
                        Task { await auth.signInWithCookie(cookieInput) }
                    } label: {
                        Label("用这个 Cookie 登录", systemImage: "checkmark.shield")
                    }
                    .disabled(
                        auth.isBusy
                            || cookieInput.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty
                    )
                } header: {
                    Text("粘贴登录 Cookie（推荐）")
                } footer: {
                    Text("电脑浏览器登录 linux.do → 按 F12 → Application → Cookies → https://linux.do → 复制 _t 的值贴到这里。这是站点唯一承认的认证方式，且全部走原生请求，手机不打开任何网页。")
                }

                Section {
                    if let code = auth.deviceCode {
                        VStack(alignment: .leading, spacing: 12) {
                            Text("在任意浏览器打开下面的地址，输入这组代码并授权：")
                                .font(.footnote)
                                .foregroundColor(.secondary)

                            Text(code.userCode)
                                .font(.system(size: 30, weight: .bold, design: .monospaced))
                                .frame(maxWidth: .infinity, alignment: .center)
                                .textSelection(.enabled)

                            Text(code.verificationUri)
                                .font(.caption2)
                                .textSelection(.enabled)

                            Button {
                                UIPasteboard.general.string = code.verificationUri
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
                            Label("设备码登录（原版同款）", systemImage: "key.horizontal")
                        }
                        .disabled(auth.isBusy)
                    }
                } header: {
                    Text("设备码登录")
                } footer: {
                    Text("与原版 app 相同的 OAuth 设备授权：手机只做轮询，不加载任何网页。若返回 403，说明站点不允许未注册的客户端。")
                }

                if auth.needsSecondFactor {
                    Section("两步验证") {
                        TextField("6 位动态验证码", text: $code)
                            .keyboardType(.numberPad)
                            .textContentType(.oneTimeCode)
                            .focused($focused, equals: .code)
                    }
                }

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
                        HStack {
                            Spacer()
                            if auth.isBusy { ProgressView() } else { Text("登录").bold() }
                            Spacer()
                        }
                    }
                    .disabled(auth.isBusy || auth.isWaitingForComputer)
                }
            }
            .navigationTitle("LINUX DO")
        }
    }

    @ViewBuilder
    private var computerSection: some View {
        Section {
            if let url = auth.computerAuthorizationURL {
                Text("1. 将链接发到电脑，在电脑浏览器登录论坛并确认授权。")
                    .font(.footnote)
                Button {
                    UIPasteboard.general.string = url.absoluteString
                    copiedLink = true
                } label: {
                    Label(copiedLink ? "链接已复制" : "复制电脑授权链接", systemImage: "doc.on.doc")
                }
                ShareLink(item: url.absoluteString) {
                    Label("分享授权链接", systemImage: "square.and.arrow.up")
                }
                Text("2. 将电脑网页显示的整段加密授权结果复制回来，粘贴到下方。")
                    .font(.footnote)
                TextEditor(text: $encryptedResult)
                    .frame(minHeight: 110)
                    .font(.caption.monospaced())
                    .textInputAutocapitalization(.never)
                    .autocorrectionDisabled(true)
                    .accessibilityLabel("电脑返回的加密授权结果")
                    .disabled(auth.isBusy)
                Button {
                    focused = nil
                    Task {
                        await auth.completeComputerLogin(encryptedResult: encryptedResult)
                        if auth.isLoggedIn { encryptedResult = "" }
                    }
                } label: {
                    if auth.isBusy {
                        ProgressView("正在验证授权…")
                    } else {
                        Label("完成授权并登录", systemImage: "checkmark.shield")
                    }
                }
                .disabled(auth.isBusy || encryptedResult.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty)
                Button("取消本次授权", role: .cancel) {
                    auth.cancelComputerLogin()
                    encryptedResult = ""
                    copiedLink = false
                }
                .disabled(auth.isBusy)
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
            Text("使用电脑授权登录")
        } footer: {
            Text("手机无需打开论坛网页。授权仅申请读取权限；待完成的授权在本机保留 24 小时。")
        }
    }
}
