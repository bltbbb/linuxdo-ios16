import Foundation
import Security

/// OAuth 2.0 Device Authorization Grant —— 原 app 1.0.2 用的就是这套。
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
    /// Discourse 用 client_id 区分客户端，bundle id 足够。
    static let clientId = "com.example.linuxdoclient"
    static let scopes = ["read", "write", "notifications", "session_info"]
    static let applicationName = "LinuxDoClient"

    /// User API Key 授权完成后，服务端 302 到这个自定义 scheme。
    /// 必须与 Info.plist 的 CFBundleURLSchemes 一致。
    static let authRedirect = "linuxdoclient://auth"
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

    static func save(_ token: String) {
        clear()
        let query: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: service,
            kSecAttrAccount as String: account,
            kSecValueData as String: Data(token.utf8),
            kSecAttrAccessible as String: kSecAttrAccessibleAfterFirstUnlock
        ]
        let status = SecItemAdd(query as CFDictionary, nil)
        if status != errSecSuccess {
            NSLog("[TokenStore] 保存失败：\(status)")
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
