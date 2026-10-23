import Foundation
import Combine
import Security

/// 会话状态机。
///
/// 主路径：电脑完成 User API Key 授权，手机解密结果并直连接口。
/// 登录页另提供原生账号密码入口；未验证的设备码和旧网页登录代码不在界面展示。
@MainActor
final class AuthStore: ObservableObject {

    @Published private(set) var currentUser: CurrentUser?
    @Published private(set) var isBusy = false
    @Published private(set) var computerAuthorizationURL: URL?
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
    var isWaitingForComputer: Bool { computerAuthorizationURL != nil }

    var displayName: String {
        guard let user = currentUser else { return "未登录" }
        if let name = user.name, !name.isEmpty { return name }
        return user.username
    }

    // MARK: - 启动恢复

    func restoreSession() async {
        isBusy = true
        defer { isBusy = false }

        if let pending = PendingComputerAuthorizationStore.load() {
            rsaMaterial = pending.material
            pendingNonce = pending.nonce
            computerAuthorizationURL = try? computerURL(material: pending.material, nonce: pending.nonce)
        }

        if let saved = TokenStore.load(), !saved.isEmpty {
            client.setApiKey(saved)
        }

        // 卸载重装后 HTTPCookieStorage 已被清空，用 Keychain 里的会话恢复
        if !client.hasSessionCookie, let saved = CookieVault.load(),
           let host = client.baseURL.host {
            for cookie in CookieImporter.parse(saved, host: host) {
                HTTPCookieStorage.shared.setCookie(cookie)
            }
        }

        do {
            currentUser = try await client.currentUser()
            if currentUser != nil { cancelComputerLogin() }
        } catch {
            currentUser = nil
        }
    }

    // MARK: - User API Key（电脑授权，手机不加载网页）

    func beginComputerLogin() {
        guard !isBusy, !isWaitingForComputer else { return }
        cancelDeviceLogin()
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
            let url = try computerURL(material: material, nonce: nonce)
            try PendingComputerAuthorizationStore.save(material: material, nonce: nonce)
            computerAuthorizationURL = url
        } catch {
            cancelComputerLogin()
            errorMessage = error.localizedDescription
        }
    }

    private func computerURL(material: RSAKeyPair.Material, nonce: String) throws -> URL {
        try client.requestUserApiKey(
            publicKeyPEM: material.publicKeyPEM,
            nonce: nonce,
            clientId: UserApiKeyConfig.clientId,
            scopes: UserApiKeyConfig.scopes,
            redirect: nil
        )
    }

    /// 仅接收本次公钥加密的结果，不接收明文 API Key 或浏览器 Cookie。
    func completeComputerLogin(encryptedResult: String) async {
        guard !isBusy, isWaitingForComputer,
              let material = rsaMaterial, let nonce = pendingNonce else { return }
        guard PendingComputerAuthorizationStore.load()?.nonce == nonce else {
            cancelComputerLogin()
            errorMessage = "本次授权已过期或无法读取，请重新生成链接"
            return
        }
        isBusy = true
        errorMessage = nil
        defer { isBusy = false }
        do {
            let payload = try UserApiKeyAuthorization.decodePayload(
                encryptedResult,
                expectedNonce: nonce,
                privateKey: material.privateKey
            )
            client.setApiKey(payload.key)
            guard let user = try await client.currentUser() else {
                throw DiscourseError.unauthorized
            }
            try TokenStore.save(payload.key)
            currentUser = user
            cancelComputerLogin()
            needsSecondFactor = false
            errorMessage = nil
        } catch {
            // 网络或复制错误时保留私钥，让用户重试同一授权结果。
            client.setApiKey(TokenStore.load())
            let diagnostics = await diagnosticsSuffix()
            errorMessage = "授权未完成：\(error.localizedDescription)"
                + (diagnostics.map { "\n\n" + $0 } ?? "")
        }
    }

    func cancelComputerLogin() {
        computerAuthorizationURL = nil
        pendingNonce = nil
        rsaMaterial = nil
        PendingComputerAuthorizationStore.clear()
    }

    // MARK: - Device Grant（站点可能未启用）

    func beginDeviceLogin() async {
        guard !isBusy, !isWaitingForComputer else { return }
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
                        try TokenStore.save(access)
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
        guard !isBusy, !isWaitingForComputer else { return }
        cancelDeviceLogin()
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
                TokenStore.clear()
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

    // MARK: - 粘贴 Cookie 登录（站点唯一承认的方式）

    /// 用户从电脑浏览器复制会话 cookie（如 `_t=...`）粘进来。
    /// 之后的请求全部带这个 cookie，GET 不需要 CSRF，站点也拦不住。
    func signInWithCookie(_ raw: String) async {
        let host = client.baseURL.host ?? "linux.do"
        let cookies = CookieImporter.parse(raw, host: host)
        guard !cookies.isEmpty else {
            errorMessage = "没解析到有效 Cookie，请粘贴形如 _t=xxxx 的内容"
            return
        }

        isBusy = true
        errorMessage = nil
        defer { isBusy = false }

        for cookie in cookies {
            HTTPCookieStorage.shared.setCookie(cookie)
        }

        do {
            guard let user = try await client.currentUser() else {
                errorMessage = "Cookie 无效或已过期"
                    + "（/session/current.json 未返回用户）｜cookie=\(client.cookieDiagnostics())"
                return
            }
            currentUser = user
            if let header = client.currentCookieHeader() {
                CookieVault.save(header)
            }
            cancelComputerLogin()
            cancelDeviceLogin()
            needsSecondFactor = false
            errorMessage = nil
        } catch {
            var message = "Cookie 验证失败：\(error.localizedDescription)"
            if let diagnostics = await diagnosticsSuffix() {
                message += "\n\n" + diagnostics
            }
            errorMessage = message
        }
    }

    // MARK: - 手动粘贴 API Key（保底路径）

    func signInWithAPIKey(_ raw: String) async {
        let key = raw.trimmingCharacters(in: .whitespacesAndNewlines)
        guard !key.isEmpty else {
            errorMessage = "请先粘贴 API Key"
            return
        }

        isBusy = true
        errorMessage = nil
        defer { isBusy = false }

        let previous = TokenStore.load()
        client.setApiKey(key)

        do {
            guard let user = try await client.currentUser() else {
                client.setApiKey(previous)
                errorMessage = "这个 Key 不被站点接受（/session/current.json 没有返回用户）"
                return
            }
            try TokenStore.save(key)
            currentUser = user
            cancelComputerLogin()
            cancelDeviceLogin()
            needsSecondFactor = false
            errorMessage = nil
        } catch {
            client.setApiKey(previous)
            var message = "API Key 验证失败：\(error.localizedDescription)"
            if let diagnostics = await diagnosticsSuffix() {
                message += "\n\n" + diagnostics
            }
            errorMessage = message
        }
    }

    // MARK: - 退出

    func signOut() async {
        cancelComputerLogin()
        pollTask?.cancel()
        pollTask = nil
        isBusy = true
        defer { isBusy = false }

        TokenStore.clear()
        CookieVault.clear()
        client.setApiKey(nil)
        try? await client.logout()
        currentUser = nil
        needsSecondFactor = false
        deviceCode = nil
        isPolling = false
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
