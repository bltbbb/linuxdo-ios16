import Foundation
import Security

/// 站点定制设备码登录的候选实现。
/// 原版 IPA 含有下列端点字符串，但响应格式和令牌语义尚未核实，不能等同于标准 Discourse 协议。
///
/// 流程：
/// 1. `POST /login/device/code` 拿 device_code + user_code + verification_uri
/// 2. 用户在浏览器打开 verification_uri，输入 user_code 并授权
/// 3. app 按 interval 轮询 `POST /login/oauth/access_token`
/// 4. 拿到 access_token（即 Discourse 的 user API key）
/// 5. 之后所有请求带 `User-Api-Key: <token>`
///
/// 关键点：整个过程不碰 WKWebView，不需要 cookie 会话，也不需要 CSRF。
enum DeviceAuthConfig {
    /// 复刻原版：client_id 直接沿用原版 bundle id。
    /// 站点若按 client_id 做白名单，只有这个值能通过。
    static let clientId = "org.linuxdo.community"

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

    enum CodingKeys: String, CodingKey {
        case deviceCode = "device_code"
        case userCode = "user_code"
        case verificationUri = "verification_uri"
        case verificationUriComplete = "verification_uri_complete"
        case expiresIn = "expires_in"
        case interval
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

    enum CodingKeys: String, CodingKey {
        case accessToken = "access_token"
        case tokenType = "token_type"
        case scope, error
        case errorDescription = "error_description"
    }

    /// 授权尚未完成，继续轮询。
    var isPending: Bool {
        error == "authorization_pending" || error == "slow_down"
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
