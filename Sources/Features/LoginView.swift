import SwiftUI

struct LoginView: View {

    enum Field: Hashable {
        case account, password, code
    }

    @EnvironmentObject private var auth: AuthStore
    @State private var account = ""
    @State private var password = ""
    @State private var code = ""
    @State private var showsWebLogin = false
    @FocusState private var focused: Field?

    var body: some View {
        NavigationStack {
            Form {
                Section {
                    Button {
                        showsWebLogin = true
                    } label: {
                        Label("网页登录（推荐）", systemImage: "safari")
                    }
                } footer: {
                    Text("linux.do 前置了 Cloudflare 交互式校验，原生请求通常无法通过。用内嵌浏览器完成校验与登录，cookie 会自动共享给原生接口。")
                }

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
                    Text("直接登录")
                } footer: {
                    Text("仅在服务器未拦截原生请求时可用。凭据只用于向 linux.do 换取 Discourse 会话 cookie。")
                }

                if auth.needsSecondFactor {
                    Section {
                        TextField("6 位动态验证码", text: $code)
                            .keyboardType(.numberPad)
                            .textContentType(.oneTimeCode)
                            .focused($focused, equals: .code)
                    } header: {
                        Text("两步验证")
                    } footer: {
                        Text("该账号启用了 TOTP 二次验证，请输入验证器当前显示的验证码。")
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
                            if auth.isBusy {
                                ProgressView()
                            } else {
                                Text("登录").bold()
                            }
                            Spacer()
                        }
                    }
                    .disabled(auth.isBusy)
                }
            }
            .navigationTitle("LINUX DO")
            .onAppear {
                if account.isEmpty { focused = .account }
            }
            .sheet(isPresented: $showsWebLogin) {
                WebLoginView()
                    .environmentObject(auth)
            }
        }
    }
}
