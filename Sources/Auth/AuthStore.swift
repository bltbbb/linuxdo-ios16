import Foundation
import Combine
import Security
import AuthenticationServices
import UIKit

/// 会话状态机。
///
/// 主路径：Discourse User API Key（RSA）—— 浏览器授权一次，之后用 `User-Api-Key` 直连。
/// 备选：Device Grant（站点可能未启用）、网页登录、账号密码。
@MainActor
final class AuthStore: NSObject, ObservableObject, ASWebAuthenticationPresentationContextProviding {

    @Published private(set) var currentUser: CurrentUser?
    @Published private(set) var isBusy = false
    @Published private(set) var isWaitingForBrowser = false
    @Published private(set) var deviceCode: DeviceCodeResponse?
    @Published private(set) var isPolling = false
    @Published var errorMessage: String?
    @Published var needsSecondFactor = false

    private let client: DiscourseClient
    private var pollTask: Task<Void, Never>?
    private var rsaMaterial: RSAKeyPair.Material?
    private var pendingNonce: String?
    private var browserSession: ASWebAuthenticationSession?
    private var presentationWindow: UIWindow?

    init(client: DiscourseClient = .shared) {
        self.client = client
        super.init()
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
        guard !isBusy, !isWaitingForBrowser else { return }
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
            let url = try client.requestUserApiKey(
                publicKeyPEM: material.publicKeyPEM,
                nonce: nonce,
                clientId: UserApiKeyConfig.clientId,
                scopes: UserApiKeyConfig.scopes,
                redirect: UserApiKeyConfig.authRedirect
            )
            guard let window = UIApplication.shared.connectedScenes
                .compactMap({ $0 as? UIWindowScene })
                .filter({ $0.activationState == .foregroundActive })
                .flatMap({ $0.windows })
                .first(where: { $0.isKeyWindow }) else {
                throw DiscourseError.transport("没有可展示授权页面的窗口，请回到应用后重试")
            }
            presentationWindow = window
            let browser = ASWebAuthenticationSession(
                url: url,
                callbackURLScheme: UserApiKeyConfig.callbackScheme
            ) { [weak self] callbackURL, error in
                Task { @MainActor [weak self] in
                    guard let self = self, self.pendingNonce == nonce else { return }
                    self.browserSession = nil
                    self.presentationWindow = nil
                    if let callbackURL = callbackURL {
                        await self.handleAuthCallback(url: callbackURL)
                    } else {
                        self.cancelUserApiKeyLogin()
                        if let error = error {
                            if (error as? ASWebAuthenticationSessionError)?.code != .canceledLogin {
                                self.errorMessage = "无法完成浏览器授权：\(error.localizedDescription)"
                            }
                        }
                    }
                }
            }
            browser.presentationContextProvider = self
            browser.prefersEphemeralWebBrowserSession = false
            browserSession = browser
            isWaitingForBrowser = true
            guard browser.start() else {
                throw DiscourseError.transport("无法打开系统授权页面，请重试")
            }
        } catch {
            cancelUserApiKeyLogin()
            errorMessage = error.localizedDescription
        }
    }

    func presentationAnchor(for session: ASWebAuthenticationSession) -> ASPresentationAnchor {
        presentationWindow ?? ASPresentationAnchor()
    }

    /// nonce 必须来自解密后的 payload，不能仅检查 URL 中的可选参数。
    func handleAuthCallback(url: URL) async {
        guard !isBusy, isWaitingForBrowser,
              let material = rsaMaterial, let nonce = pendingNonce else { return }
        isBusy = true
        defer { isBusy = false }
        do {
            let payload = try UserApiKeyAuthorization.decodeCallback(
                url,
                expectedRedirect: UserApiKeyConfig.authRedirect,
                expectedNonce: nonce,
                privateKey: material.privateKey
            )
            // 消耗本次授权状态，阻止同一回调重复处理。
            cancelUserApiKeyLogin()
            client.setApiKey(payload.key)
            guard let user = try await client.currentUser() else {
                throw DiscourseError.unauthorized
            }
            TokenStore.save(payload.key)
            currentUser = user
            needsSecondFactor = false
            errorMessage = nil
        } catch {
            cancelUserApiKeyLogin()
            client.setApiKey(TokenStore.load())
            errorMessage = "授权未完成：\(error.localizedDescription)"
        }
    }

    func cancelUserApiKeyLogin() {
        isWaitingForBrowser = false
        pendingNonce = nil
        rsaMaterial = nil
        let browser = browserSession
        browserSession = nil
        browser?.cancel()
        presentationWindow = nil
    }

    // MARK: - Device Grant（站点可能未启用）

    func beginDeviceLogin() async {
        guard !isBusy, !isWaitingForBrowser else { return }
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
        cancelUserApiKeyLogin()
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
