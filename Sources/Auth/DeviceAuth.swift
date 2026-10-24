import Foundation
import Security

/// 站点定制设备码登录的协议模型。
/// 静态分析显示原版在申请设备码前还会准备 App Attest 和 mTLS 客户端证书；
/// 本文件只负责解析设备码/轮询响应，不能替代那套设备证明。
///
/// 流程：
/// 1. `POST /login/device/code` 拿 device_code + user_code + verification_uri
/// 2. 用户在浏览器打开 verification_uri，输入 user_code 并授权
/// 3. app 按 interval 轮询 `POST /login/oauth/access_token`
/// 4. 拿到 access_token（即 Discourse 的 user API key）
/// 5. 之后所有请求带 `User-Api-Key: <token>`
///
/// 设备码轮询本身不依赖 CSRF；首次申请是否允许取决于服务端的设备证明。
enum DeviceAuthConfig {
    /// 复刻原版：client_id 直接沿用原版 bundle id。
    /// 站点若按 client_id 做白名单，只有这个值能通过。
    static let clientId = "org.linuxdo.community"
    /// 原版交换 token 时使用的 OAuth client id，与申请设备码的应用标识分开。
    static let tokenClientId = "discourse-ios"

    /// 与原版二进制里出现的 scope 集合对齐（read / write / notifications / user）；
    /// 多申请一个站点不认的 scope 会被判非法，整个请求 403。
    static let scopes = ["read", "write", "notifications"]
    static let applicationName = "LINUX DO"

}

struct DeviceCodeResponse: Decodable {
    let deviceCode: String
    let userCode: String
    let verificationUri: String
    let verificationUriComplete: String?
    let expiresIn: Int
    let interval: Int
    let clientId: String?
    let registrationToken: String?
    let publicKeyCredential: String?

    private enum CodingKeys: String, CodingKey {
        case deviceCode = "device_code"
        case userCode = "user_code"
        case verificationUri = "verification_uri"
        case verificationUriComplete = "verification_uri_complete"
        case verificationURL = "verificationURL"
        case verificationUrl = "verification_url"
        case expiresIn = "expires_in"
        case expiresAt = "expiresAt"
        case interval
        case clientId = "client_id"
        case registrationToken = "registration_token"
        case publicKeyCredential
    }

    init(from decoder: Decoder) throws {
        let c = try decoder.container(keyedBy: CodingKeys.self)
        deviceCode = try c.decode(String.self, forKey: .deviceCode)
        userCode = try c.decodeIfPresent(String.self, forKey: .userCode) ?? ""
        verificationUri = try c.decodeIfPresent(String.self, forKey: .verificationUri)
            ?? (try c.decodeIfPresent(String.self, forKey: .verificationURL))
            ?? (try c.decodeIfPresent(String.self, forKey: .verificationUrl))
            ?? ""
        verificationUriComplete = try c.decodeIfPresent(String.self, forKey: .verificationUriComplete)
        clientId = try c.decodeIfPresent(String.self, forKey: .clientId)
        registrationToken = try c.decodeIfPresent(String.self, forKey: .registrationToken)
        publicKeyCredential = try c.decodeIfPresent(String.self, forKey: .publicKeyCredential)
        interval = try c.decodeIfPresent(Int.self, forKey: .interval) ?? 5
        if let seconds = try c.decodeIfPresent(Int.self, forKey: .expiresIn) {
            expiresIn = seconds
        } else if let date = try c.decodeIfPresent(String.self, forKey: .expiresAt),
                  let expires = ISO8601DateFormatter().date(from: date) {
            expiresIn = max(0, Int(expires.timeIntervalSinceNow))
        } else {
            expiresIn = 600
        }
    }

    /// 用于「在浏览器中打开」的地址。
    var browserURL: URL? {
        URL(string: verificationUriComplete ?? verificationUri)
    }
}

struct DeviceTokenResponse: Decodable {
    let accessToken: String?
    let tokenType: String?
    let scope: String?
    let error: String?
    let errorDescription: String?
    let sessionCookie: String?
    let registrationToken: String?
    let username: String?
    let name: String?
    let registrationRequired: Bool?
    let retryAfter: Int?
    let identityToken: String?
    let authorizationCode: String?
    let nonce: String?

    private enum CodingKeys: String, CodingKey {
        case accessToken = "access_token"
        case tokenType = "token_type"
        case scope, error
        case errorDescription = "error_description"
        case sessionCookie, registrationToken, username, name, registrationRequired
        case retryAfter, identityToken, authorizationCode, nonce
    }

    init(from decoder: Decoder) throws {
        let c = try decoder.container(keyedBy: CodingKeys.self)
        accessToken = try c.decodeIfPresent(String.self, forKey: .accessToken)
        tokenType = try c.decodeIfPresent(String.self, forKey: .tokenType)
        scope = try c.decodeIfPresent(String.self, forKey: .scope)
        error = try c.decodeIfPresent(String.self, forKey: .error)
        errorDescription = try c.decodeIfPresent(String.self, forKey: .errorDescription)
        sessionCookie = try c.decodeIfPresent(String.self, forKey: .sessionCookie)
        registrationToken = try c.decodeIfPresent(String.self, forKey: .registrationToken)
        username = try c.decodeIfPresent(String.self, forKey: .username)
        name = try c.decodeIfPresent(String.self, forKey: .name)
        registrationRequired = try c.decodeIfPresent(Bool.self, forKey: .registrationRequired)
        retryAfter = try c.decodeIfPresent(Int.self, forKey: .retryAfter)
        identityToken = try c.decodeIfPresent(String.self, forKey: .identityToken)
        authorizationCode = try c.decodeIfPresent(String.self, forKey: .authorizationCode)
        nonce = try c.decodeIfPresent(String.self, forKey: .nonce)
    }

    /// 授权尚未完成，继续轮询。
    var isPending: Bool {
        error == "authorization_pending" || error == "slow_down"
            || error == "authorization_pending_device"
    }
}

/// user API key 存在 Keychain，不用 UserDefaults。
enum TokenStore {

    private static let service = "com.example.linuxdoclient.credentials"
    private static let account = "user-api-key"

    static func save(_ token: String) throws {
        let query: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: service,
            kSecAttrAccount as String: account
        ]
        let updates: [String: Any] = [
            kSecValueData as String: Data(token.utf8),
            kSecAttrAccessible as String: kSecAttrAccessibleAfterFirstUnlock
        ]
        var status = SecItemUpdate(query as CFDictionary, updates as CFDictionary)
        if status == errSecItemNotFound {
            status = SecItemAdd(query.merging(updates) { _, new in new } as CFDictionary, nil)
        }
        guard status == errSecSuccess else {
            throw DiscourseError.transport("无法保存登录密钥，钥匙串状态：\(status)")
        }
    }

    static func load() -> String? {
        let query: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: service,
            kSecAttrAccount as String: account,
            kSecReturnData as String: true,
            kSecMatchLimit as String: kSecMatchLimitOne
        ]
        var item: CFTypeRef?
        guard SecItemCopyMatching(query as CFDictionary, &item) == errSecSuccess,
              let data = item as? Data else {
            return nil
        }
        return String(data: data, encoding: .utf8)
    }

    static func clear() {
        let query: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: service,
            kSecAttrAccount as String: account
        ]
        SecItemDelete(query as CFDictionary)
    }
}
