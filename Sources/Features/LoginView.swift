import SwiftUI

struct LoginView: View {

    enum Field: Hashable {
        case account, password, code
    }

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
                } header: {
                    Text("登录 linux.do")
                } footer: {
                    Text("走原生 HTTP 登录，全程不经过 WebKit，因此不受 iOS 16 浏览器内核兼容性影响。")
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
                    .disabled(auth.isBusy)
                }

                Section {
                    Button {
                        Task { await auth.beginDeviceLogin() }
                    } label: {
                        Label("设备码登录（纯 HTTP）", systemImage: "key.horizontal")
                    }
                    .disabled(auth.isBusy || auth.deviceCode != nil)
                } header: {
                    Text("备用")
                } footer: {
                    Text("设备码同样是纯 HTTP 流程；若站点未开启 user api key device authorization，会返回 403。浏览器授权（ASWebAuthenticationSession）和网页登录共用 iOS 16 的 WebKit，在本题设备上不可用，已移除入口。")
                }
            }
            .navigationTitle("LINUX DO")
            .onAppear {
                if account.isEmpty { focused = .account }
            }
        }
    }
}
