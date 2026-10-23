import Foundation
import Combine
import Security

/// 会话状态机。
///
/// 主路径：Discourse User API Key（RSA）—— 浏览器授权一次，之后用 `User-Api-Key` 直连。
/// 备选：Device Grant（站点可能未启用）、网页登录、账号密码。
@MainActor
final class AuthStore: ObservableObject {

    @Published private(set) var currentUser: CurrentUser?
    @Published private(set) var isBusy = false
    @Published private(set) var isWaitingForBrowser = false
    @Published private(set) var authorizeURL: URL?
    @Published private(set) var deviceCode: DeviceCodeResponse?
    @Published private(set) var isPolling = false
    @Published var errorMessage: String?
    @Published var needsSecondFactor = false

    private let client: DiscourseClient
    private var pollTask: Task<Void, Never>?
    private var rsaMaterial: RSAKeyPair.Material?
    private var pendingNonce: String?

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

    // MARK: - User API Key（浏览器授权）

    func beginUserApiKeyLogin() async {
        isBusy = true
        errorMessage = nil
        defer { isBusy = false }

        guard let material = RSAKeyPair.generate() else {
            errorMessage = "无法生成 RSA 密钥对"
            return
        }
        rsaMaterial = material

        let nonce = RSAKeyPair.randomNonce()
        pendingNonce = nonce

        do {
            let url = try await client.requestUserApiKey(
                publicKeyPEM: material.publicKeyPEM,
                nonce: nonce,
                clientId: DeviceAuthConfig.clientId,
                scopes: DeviceAuthConfig.scopes,
                redirect: DeviceAuthConfig.authRedirect
            )
            authorizeURL = url
            isWaitingForBrowser = true
        } catch {
            var message = error.localizedDescription
            if let diagnostics = await diagnosticsSuffix() {
                message += "\n\n" + diagnostics
            }
            errorMessage = message
            rsaMaterial = nil
            pendingNonce = nil
        }
    }

    /// 处理 `linuxdoclient://auth?payload=...&nonce=...` 回调。
    func handleAuthCallback(url: URL) async {
        guard let components = URLComponents(url: url, resolvingAgainstBaseURL: false) else { return }
        let items = components.queryItems ?? []

        let payload = items.first { $0.name == "payload" }?.value
        let nonce = items.first { $0.name == "nonce" }?.value

        guard let payload = payload, !payload.isEmpty else {
            errorMessage = "授权回调里没有 payload"
            return
        }
        guard let material = rsaMaterial else {
            errorMessage = "私钥已丢失，请重新发起授权"
            return
        }
        if let nonce = nonce, let expected = pendingNonce, nonce != expected {
            errorMessage = "nonce 不匹配，已中止（可能是伪造回调）"
            return
        }

        guard let clear = RSAKeyPair.decrypt(base64: payload, privateKey: material.privateKey) else {
            errorMessage = "payload 解密失败：请确认站点把 payload 用 PKCS#1 v1.5 加密"
            return
        }
        guard let object = try? JSONSerialization.jsonObject(with: clear) as? [String: Any] else {
            errorMessage = "payload 不是 JSON：\(String(data: clear.prefix(200), encoding: .utf8) ?? "")"
            return
        }
        guard let key = object["key"] as? String, !key.isEmpty else {
            errorMessage = "payload 里没有 key 字段"
            return
        }

        TokenStore.save(key)
        client.setApiKey(key)

        do {
            currentUser = try await client.currentUser()
        } catch {
            currentUser = nil
        }

        if currentUser != nil {
            authorizeURL = nil
            isWaitingForBrowser = false
            pendingNonce = nil
            rsaMaterial = nil
            errorMessage = nil
        } else {
            errorMessage = "密钥已保存，但 /session/current.json 未返回用户"
        }
    }

    func cancelUserApiKeyLogin() {
        authorizeURL = nil
        isWaitingForBrowser = false
        pendingNonce = nil
        rsaMaterial = nil
    }

    // MARK: - Device Grant（站点可能未启用）

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
                        continue
                    }
                } catch {
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

    // MARK: - 表单登录（兜底）

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
        authorizeURL = nil
        isWaitingForBrowser = false
        rsaMaterial = nil
        pendingNonce = nil
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
