import SwiftUI

struct LoginView: View {

    @EnvironmentObject private var auth: AuthStore
    @State private var showsWebLogin = false
    @State private var showsPasswordLogin = false

    var body: some View {
        NavigationStack {
            Form {
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
                    Button {
                        showsWebLogin = true
                    } label: {
                        Label("网页登录", systemImage: "safari")
                    }
                    Button {
                        showsPasswordLogin = true
                    } label: {
                        Label("账号密码登录", systemImage: "person.badge.key")
                    }
                    Button {
                        Task { await auth.beginDeviceLogin() }
                    } label: {
                        Label("设备码登录", systemImage: "key.horizontal")
                    }
                } header: {
                    Text("其他方式")
                } footer: {
                    Text("设备码登录需要站点开启 user api key device authorization；网页登录需要 WebKit 能渲染登录页；账号密码登录需要站点未启用交互式校验。")
                }
                .disabled(auth.isBusy || auth.isWaitingForBrowser)
            }
            .navigationTitle("LINUX DO")
            .sheet(isPresented: $showsWebLogin) {
                WebLoginView().environmentObject(auth)
            }
            .sheet(isPresented: $showsPasswordLogin) {
                PasswordLoginView().environmentObject(auth)
            }
        }
    }

    @ViewBuilder
    private var apiKeySection: some View {
        Section {
            if auth.isWaitingForBrowser {
                VStack(alignment: .leading, spacing: 12) {
                    Text("请在系统授权页面登录并点「授权」，完成后会自动返回。")
                        .font(.footnote)
                        .foregroundColor(.secondary)

                    HStack {
                        if auth.isWaitingForBrowser {
                            ProgressView()
                            Text("等待授权回调…")
                                .font(.footnote)
                                .foregroundColor(.secondary)
                        }
                        Spacer()
                        Button("取消") { auth.cancelUserApiKeyLogin() }
                            .font(.footnote)
                    }
                }
                .padding(.vertical, 6)
            } else {
                Button {
                    Task { await auth.beginUserApiKeyLogin() }
                } label: {
                    HStack {
                        Spacer()
                        if auth.isBusy {
                            ProgressView()
                        } else {
                            Label("浏览器授权登录", systemImage: "person.badge.key.fill").bold()
                        }
                        Spacer()
                    }
                }
                .disabled(auth.isBusy)
            }
        } header: {
            Text("登录 linux.do")
        } footer: {
            if !auth.isWaitingForBrowser {
                Text("在系统授权页面登录网站并确认只读授权，完成后使用用户密钥读取论坛。站点需允许第三方应用授权。")
            }
        }
    }
}

/// 账号密码登录，独立成页。
struct PasswordLoginView: View {

    enum Field: Hashable {
        case account, password, code
    }

    @Environment(\.dismiss) private var dismiss
    @EnvironmentObject private var auth: AuthStore

    @State private var account = ""
    @State private var password = ""
    @State private var code = ""
    @FocusState private var focused: Field?

    var body: some View {
        NavigationStack {
            Form {
                Section {
                    TextField("用户名或邮箱", text: $account)
                        .textContentType(.username)
                        .textInputAutocapitalization(.never)
                        .autocorrectionDisabled(true)
                        .focused($focused, equals: .account)

                    SecureField("密码", text: $password)
                        .textContentType(.password)
                        .focused($focused, equals: .password)
                } footer: {
                    Text("凭据只用于向 linux.do 换取会话 cookie。若站点启用了交互式校验，这里会返回 403。")
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
                            if auth.isLoggedIn { dismiss() }
                        }
                    } label: {
                        HStack {
                            Spacer()
                            if auth.isBusy { ProgressView() } else { Text("登录").bold() }
                            Spacer()
                        }
                    }
                    .disabled(auth.isBusy)
                }
            }
            .navigationTitle("账号密码登录")
            .navigationBarTitleDisplayMode(.inline)
            .toolbar {
                ToolbarItem(placement: .cancellationAction) {
                    Button("取消") { dismiss() }
                }
            }
        }
    }
}
