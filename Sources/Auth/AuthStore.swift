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
    @Published private(set) var isRestoring = false
    /// 本地有凭据（cookie 或 api key）：允许直接进入主界面，不等网络校验。
    @Published private(set) var hasStoredSession = false
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
        isRestoring = true
        defer { isRestoring = false }

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

        // 关键：有凭据就直接放行，不在启动时等网络。
        // 校验丢到后台，失败也不阻塞界面。
        hasStoredSession = client.hasSessionCookie || !(TokenStore.load() ?? "").isEmpty
        guard hasStoredSession else { return }

        Task { [weak self] in
            guard let self = self else { return }
            do {
                if let user = try await self.client.currentUser() {
                    self.currentUser = user
                    self.cancelComputerLogin()
                    self.errorMessage = nil
                } else {
                    self.hasStoredSession = false
                    self.errorMessage = "上次的会话已失效，请重新登录"
                }
            } catch {
                // 网络不通时保留凭据，让用户还能看到上次的列表缓存；
                // 错误写进 errorMessage，界面上能查到原因。
                self.errorMessage = "会话校验未完成（可继续浏览缓存）：\(error.localizedDescription)"
            }
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

    // MARK: - 设备授权（Discourse 原生 user-api-key device flow）

    /// 出码 → 用户在浏览器输码授权 → 轮询拿到一次性 payload → RSA 解密 → 存 key。
    func beginDeviceLogin() async {
        guard !isBusy else { return }
        cancelComputerLogin()
        cancelDeviceLogin()
        isBusy = true
        errorMessage = nil
        defer { isBusy = false }

        guard let material = RSAKeyPair.generate() else {
            errorMessage = "无法生成 RSA 密钥对"
            return
        }
        let nonce = RSAKeyPair.randomNonce()

        do {
            let code = try await client.requestDeviceCode(
                publicKeyPEM: material.publicKeyPEM,
                nonce: nonce,
                clientId: DeviceAuthConfig.clientId,
                scopes: DeviceAuthConfig.scopes,
                applicationName: DeviceAuthConfig.applicationName
            )
            try PendingDeviceAuthorizationStore.save(
                material: material,
                nonce: nonce,
                deviceCode: code.deviceCode
            )
            rsaMaterial = material
            pendingNonce = nonce
            deviceCode = code
            startPolling(code)
        } catch {
            var message = "申请授权码失败：\(error.localizedDescription)"
            if let diagnostics = await diagnosticsSuffix() {
                message += "\n\n" + diagnostics
            }
            errorMessage = message
        }
    }

    /// 轮询期间 payload 只会出现一次，拿到就必须立刻解密再停。
    private func startPolling(_ code: DeviceCodeResponse) {
        pollTask?.cancel()
        isPolling = true

        pollTask = Task { [weak self] in
            guard let self = self else { return }
            let deadline = Date().addingTimeInterval(TimeInterval(max(code.expiresIn, 60)))
            let interval = TimeInterval(max(code.interval, 3))

            while !Task.isCancelled, Date() < deadline {
                try? await Task.sleep(nanoseconds: UInt64(interval * 1_000_000_000))
                if Task.isCancelled { return }

                do {
                    let poll = try await self.client.pollDeviceAuthorization(
                        deviceCode: code.deviceCode
                    )
                    switch poll.status {
                    case .authorizationPending:
                        continue
                    case .authorized:
                        await self.finishDeviceLogin(payload: poll.payload)
                        return
                    case .accessDenied:
                        await self.failDeviceLogin("授权被拒绝")
                        return
                    case .expiredToken:
                        await self.failDeviceLogin("授权码已过期，请重新开始")
                        return
                    }
                } catch {
                    // 单次网络抖动不该终止整轮授权，继续轮询到截止时间。
                    continue
                }
            }

            await self.failDeviceLogin("授权超时，请重新开始")
        }
    }

    private func finishDeviceLogin(payload: String?) async {
        defer { isPolling = false }

        guard let pending = PendingDeviceAuthorizationStore.load() else {
            deviceCode = nil
            errorMessage = "授权已完成，但本地私钥已失效，请重新授权"
            return
        }
        guard let payload = payload, !payload.isEmpty else {
            deviceCode = nil
            errorMessage = "授权已完成，但站点没有返回密钥，请重新授权"
            PendingDeviceAuthorizationStore.clear()
            return
        }

        // 第一步只做解密和落盘。
        //
        // payload 服务端只给一次，任何后续失败都不能让它白丢，
        // 所以先把 key 存进钥匙串，再去做网络验证。
        // 早先把 currentUser() 放在保存之前，一次 429 挑战就把刚拿到的密钥废了，
        // 用户不得不重新授权。
        do {
            let result = try UserApiKeyAuthorization.decodePayload(
                payload,
                expectedNonce: pending.nonce,
                privateKey: pending.material.privateKey
            )
            try TokenStore.save(result.key)
            client.setApiKey(result.key)
            hasStoredSession = true
            deviceCode = nil
            needsSecondFactor = false
            errorMessage = nil
            PendingDeviceAuthorizationStore.clear()
            rsaMaterial = nil
            pendingNonce = nil
        } catch {
            PendingDeviceAuthorizationStore.clear()
            var message = "解密授权结果失败：\(error.localizedDescription)"
            if let diagnostics = await diagnosticsSuffix() {
                message += "\n\n" + diagnostics
            }
            errorMessage = message
            return
        }

        // 第二步：取用户信息。失败不影响已登录状态——
        // Cloudflare 的 429 是临时的，重试几次通常就过。
        await loadCurrentUserWithRetry()
    }

    /// 取当前用户，失败重试。
    ///
    /// 只要 key 已经落盘，这里失败只是界面显示不出用户名，
    /// 下一次下拉刷新或重启会再试，不该把用户踢回登录页。
    private func loadCurrentUserWithRetry(attempts: Int = 3) async {
        for attempt in 1...attempts {
            do {
                if let user = try await client.currentUser() {
                    currentUser = user
                    return
                }
            } catch {
                if attempt == attempts {
                    errorMessage = "已登录，但暂时取不到用户信息（可稍后下拉刷新）：\(error.localizedDescription)"
                }
            }
            if attempt < attempts {
                try? await Task.sleep(nanoseconds: 2_000_000_000)
            }
        }
    }

    private func failDeviceLogin(_ message: String) async {
        pollTask?.cancel()
        pollTask = nil
        isPolling = false
        deviceCode = nil
        rsaMaterial = nil
        pendingNonce = nil
        PendingDeviceAuthorizationStore.clear()
        errorMessage = message
    }

    func cancelDeviceLogin() {
        pollTask?.cancel()
        pollTask = nil
        isPolling = false
        deviceCode = nil
        PendingDeviceAuthorizationStore.clear()
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
        hasStoredSession = false
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
