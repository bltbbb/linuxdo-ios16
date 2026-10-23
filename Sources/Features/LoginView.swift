import SwiftUI
import UIKit

struct LoginView: View {

    @EnvironmentObject private var auth: AuthStore
    @State private var showsWebLogin = false
    @State private var showsPasswordLogin = false

    var body: some View {
        NavigationStack {
            Form {
                deviceSection

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
                } header: {
                    Text("其他方式")
                } footer: {
                    Text("这两种都依赖浏览器会话：网页登录需要 WebKit 能正常渲染登录页，账号密码登录需要站点未启用交互式校验。仅在设备码登录不可用时使用。")
                }
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
    private var deviceSection: some View {
        Section {
            if let code = auth.deviceCode {
                VStack(alignment: .leading, spacing: 14) {
                    Text("用浏览器打开下面的地址，输入代码后授权：")
                        .font(.footnote)
                        .foregroundColor(.secondary)

                    Text(code.userCode)
                        .font(.system(size: 34, weight: .bold, design: .monospaced))
                        .frame(maxWidth: .infinity, alignment: .center)
                        .textSelection(.enabled)

                    Text(code.verificationUri)
                        .font(.footnote)
                        .textSelection(.enabled)
                        .frame(maxWidth: .infinity, alignment: .center)

                    Button {
                        if let url = code.browserURL {
                            UIApplication.shared.open(url)
                        }
                    } label: {
                        Label("在浏览器中打开", systemImage: "safari")
                            .frame(maxWidth: .infinity)
                    }
                    .buttonStyle(.borderedProminent)

                    HStack(spacing: 8) {
                        if auth.isPolling {
                            ProgressView()
                            Text("等待授权…").font(.footnote).foregroundColor(.secondary)
                        } else {
                            Text("未在等待授权").font(.footnote).foregroundColor(.secondary)
                        }
                        Spacer()
                        Button("取消") { auth.cancelDeviceLogin() }
                            .font(.footnote)
                    }
                }
                .padding(.vertical, 6)
            } else {
                Button {
                    Task { await auth.beginDeviceLogin() }
                } label: {
                    HStack {
                        Spacer()
                        if auth.isBusy {
                            ProgressView()
                        } else {
                            Label("设备码登录", systemImage: "key.horizontal").bold()
                        }
                        Spacer()
                    }
                }
                .disabled(auth.isBusy)
            }
        } header: {
            Text("登录 linux.do")
        } footer: {
            if auth.deviceCode == nil {
                Text("与原版 app 相同的 OAuth 设备授权流程。拿到 API Key 后直连接口，不使用 WebKit、不依赖 cookie。")
            }
        }
    }
}

/// 账号密码登录，独立成页，避免和主路径混在一起。
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
