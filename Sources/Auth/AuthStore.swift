import Foundation
import Combine

/// 用 `ObservableObject` + `@Published` 替代原 app 的 Observation 框架（iOS 17+）。
@MainActor
final class AuthStore: ObservableObject {

    @Published private(set) var currentUser: CurrentUser?
    @Published private(set) var isBusy = false
    @Published var errorMessage: String?
    @Published var needsSecondFactor = false

    private let client: DiscourseClient

    init(client: DiscourseClient = .shared) {
        self.client = client
    }

    var isLoggedIn: Bool { currentUser != nil }

    var displayName: String {
        guard let user = currentUser else { return "未登录" }
        if let name = user.name, !name.isEmpty { return name }
        return user.username
    }

    /// 冷启动时用持久化的 cookie 恢复会话，等价于原 app 的 `AuthState` 启动逻辑。
    func restoreSession() async {
        isBusy = true
        defer { isBusy = false }
        do {
            currentUser = try await client.currentUser()
        } catch {
            currentUser = nil
            errorMessage = error.localizedDescription
        }
    }

    func signIn(account: String, password: String, secondFactorCode: String? = nil) async {
        let trimmed = account.trimmingCharacters(in: .whitespacesAndNewlines)
        guard !trimmed.isEmpty, !password.isEmpty else {
            errorMessage = "请输入账号和密码"
            return
        }

        isBusy = true
        errorMessage = nil
        defer { isBusy = false }

        do {
            let outcome = try await client.login(
                account: trimmed,
                password: password,
                secondFactorCode: secondFactorCode
            )
            if outcome.success {
                currentUser = try await client.currentUser()
                needsSecondFactor = false
                errorMessage = nil
            } else {
                needsSecondFactor = outcome.secondFactorRequired
                errorMessage = outcome.message ?? "登录失败"
            }
        } catch {
            errorMessage = error.localizedDescription
        }
    }

    func signOut() async {
        isBusy = true
        defer { isBusy = false }
        try? await client.logout()
        currentUser = nil
        needsSecondFactor = false
        errorMessage = nil
    }

    /// 网页登录完成后调用：cookie 已由 WKWebView 导入，这里只验证会话并拉取用户。
    func completeWebLogin() async {
        isBusy = true
        defer { isBusy = false }
        do {
            if let user = try await client.currentUser() {
                currentUser = user
                needsSecondFactor = false
                errorMessage = nil
            } else {
                errorMessage = "未能取得会话，请重试"
            }
        } catch {
            errorMessage = error.localizedDescription
        }
    }
}
