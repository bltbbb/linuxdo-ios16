import Foundation
import Combine

/// 会话状态机。
///
/// 主路径是 OAuth Device Grant（API Key），与系统 WebKit 无关；
/// 网页登录只作为兜底保留。
@MainActor
final class AuthStore: ObservableObject {

    @Published private(set) var currentUser: CurrentUser?
    @Published private(set) var isBusy = false
    @Published private(set) var isPolling = false
    @Published private(set) var deviceCode: DeviceCodeResponse?
    @Published var errorMessage: String?
    @Published var needsSecondFactor = false

    private let client: DiscourseClient
    private var pollTask: Task<Void, Never>?

    init(client: DiscourseClient = .shared) {
        self.client = client
    }

    var isLoggedIn: Bool { currentUser != nil }

    var displayName: String {
        guard let user = currentUser else { return "未登录" }
        if let name = user.name, !name.isEmpty { return name }
        return user.username
    }

    // MARK: - 启动恢复

    func restoreSession() async {
        isBusy = true
        defer { isBusy = false }

        if let saved = TokenStore.load(), !saved.isEmpty {
            client.setApiKey(saved)
        }

        do {
            currentUser = try await client.currentUser()
        } catch {
            currentUser = nil
        }
    }

    // MARK: - Device Grant 登录（主路径）

    func beginDeviceLogin() async {
        isBusy = true
        errorMessage = nil
        defer { isBusy = false }

        do {
            let code = try await client.requestDeviceCode(
                clientId: DeviceAuthConfig.clientId,
                scopes: DeviceAuthConfig.scopes
            )
            deviceCode = code
            startPolling(code)
        } catch {
            var message = error.localizedDescription
            if let diagnostics = await diagnosticsSuffix() {
                message += "\n\n" + diagnostics
            }
            errorMessage = message
        }
    }

    private func startPolling(_ code: DeviceCodeResponse) {
        pollTask?.cancel()
        isPolling = true

        pollTask = Task { [weak self] in
            guard let self = self else { return }
            let deadline = Date().addingTimeInterval(TimeInterval(max(code.expiresIn, 60)))
            var interval = TimeInterval(max(code.interval, 3))

            while !Task.isCancelled, Date() < deadline {
                try? await Task.sleep(nanoseconds: UInt64(interval * 1_000_000_000))
                if Task.isCancelled { break }

                do {
                    let token = try await self.client.pollDeviceToken(
                        clientId: DeviceAuthConfig.clientId,
                        deviceCode: code.deviceCode
                    )

                    if let access = token.accessToken, !access.isEmpty {
                        TokenStore.save(access)
                        self.client.setApiKey(access)
                        self.currentUser = try await self.client.currentUser()
                        self.deviceCode = nil
                        self.isPolling = false
                        self.needsSecondFactor = false
                        self.errorMessage = nil
                        return
                    }

                    switch token.error {
                    case "slow_down":
                        interval += 5
                    case "access_denied":
                        self.isPolling = false
                        self.deviceCode = nil
                        self.errorMessage = "授权被拒绝"
                        return
                    case "expired_token":
                        self.isPolling = false
                        self.deviceCode = nil
                        self.errorMessage = "授权码已过期，请重新开始"
                        return
                    default:
                        continue   // authorization_pending
                    }
                } catch {
                    // 网络抖动：继续轮询直到超时
                    continue
                }
            }

            self.isPolling = false
            if self.deviceCode != nil {
                self.deviceCode = nil
                self.errorMessage = "授权超时，请重新开始"
            }
        }
    }

    func cancelDeviceLogin() {
        pollTask?.cancel()
        pollTask = nil
        isPolling = false
        deviceCode = nil
    }

    // MARK: - 网页登录（兜底）

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

    // MARK: - 表单登录（仅在没有 device grant 的站点上使用）

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
                var message = outcome.message ?? "登录失败"
                if let diagnostics = await diagnosticsSuffix() {
                    message += "\n\n" + diagnostics
                }
                errorMessage = message
            }
        } catch {
            var message = error.localizedDescription
            if let diagnostics = await diagnosticsSuffix() {
                message += "\n\n" + diagnostics
            }
            errorMessage = message
        }
    }

    // MARK: - 退出

    func signOut() async {
        pollTask?.cancel()
        pollTask = nil
        isBusy = true
        defer { isBusy = false }

        TokenStore.clear()
        client.setApiKey(nil)
        try? await client.logout()
        currentUser = nil
        needsSecondFactor = false
        deviceCode = nil
        isPolling = false
        errorMessage = nil
    }

    // MARK: - 诊断

    private func diagnosticsSuffix() async -> String? {
        let entries = await RequestLog.shared.snapshot()
        guard !entries.isEmpty else { return nil }
        return entries.suffix(4).map {
            "\($0.method) \($0.url) → \($0.status)\n\($0.note)"
        }.joined(separator: "\n\n")
    }
}
