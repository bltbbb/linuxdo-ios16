import Foundation
import Security

/// Discourse 原生 User API Key 设备授权（device authorization）。
///
/// 端点与语义均来自 Discourse 上游源码，不是站点私有扩展：
/// - `POST /user-api-key/device.json`       创建设备码
/// - `POST /user-api-key/device/poll.json`  轮询；授权完成后返回一次性 payload
/// - 浏览器侧的 `GET/POST /user-api-key/activate` 由站点页面承担，App 不参与
///
/// 这两个 POST 在 Discourse 里是 `skip_before_action :verify_authenticity_token`，
/// 因此不需要 CSRF。但 `ensure_json_request!` 强制要求
/// `Content-Type: application/json` 且 `Accept: application/json`，
/// 否则请求在进入业务逻辑之前就被判 `Discourse::InvalidAccess`——
/// API 上表现为 403 + `error_type=invalid_access`。
/// 历史上「站点禁用了设备授权」的判断就是被这个 403 误导的。
enum DeviceAuthConfig {

    /// 稳定的安装标识。站点按 client_id 记住公钥和 application_name，
    /// 同一台设备重复授权必须复用同一个值，否则每次都要重新建党。
    static let clientId: String = {
        let key = "device-auth-client-id"
        if let saved = UserDefaults.standard.string(forKey: key), !saved.isEmpty {
            return saved
        }
        let generated = UUID().uuidString
        UserDefaults.standard.set(generated, forKey: key)
        return generated
    }()

    /// 原版授权页显示的应用名就是这一串。
    static let applicationName = "LINUX DO iOS"

    /// 只申请站点实际放行的两个 scope。
    ///
    /// Discourse 的 `validate_params` 用 `UserApiKey.allowed_scopes.superset?` 校验，
    /// 多申请一个站点不认的 scope 会让整个请求变 403，所以这里保守取最小集。
    /// 发帖/点赞需要的 `write` 尚未实测放行，等写操作落地时再加。
    static let scopes = ["notifications", "session_info"]
}

// MARK: - 创建响应

struct DeviceCodeResponse: Decodable {

    let deviceCode: String
    let userCode: String
    let verificationUri: String
    /// 带 `request` 参数的完整地址，浏览器用它可以直接跳过手输流程。
    let verificationUriWithRequest: String?
    let expiresIn: Int
    let interval: Int

    private enum CodingKeys: String, CodingKey {
        case deviceCode = "device_code"
        case userCode = "user_code"
        case verificationUri = "verification_uri"
        case verificationUriWithRequest = "verification_uri_with_request"
        case expiresIn = "expires_in"
        case interval
    }

    init(from decoder: Decoder) throws {
        let c = try decoder.container(keyedBy: CodingKeys.self)
        deviceCode = try c.decode(String.self, forKey: .deviceCode)
        userCode = try c.decode(String.self, forKey: .userCode)
        verificationUri = try c.decodeIfPresent(String.self, forKey: .verificationUri) ?? ""
        verificationUriWithRequest = try c.decodeIfPresent(String.self, forKey: .verificationUriWithRequest)
        expiresIn = try c.decodeIfPresent(Int.self, forKey: .expiresIn) ?? 600
        interval = try c.decodeIfPresent(Int.self, forKey: .interval) ?? 5
    }

    /// 站点下发的 device_code 是 64 位十六进制（`DEVICE_CODE_REGEX = /\A\h{64}\z/`）。
    /// 形状不对就别拿去轮询，省得把无效请求打到站点。
    var isUsable: Bool {
        deviceCode.count == 64 && !userCode.isEmpty
    }

    /// 用户要去浏览器打开的地址。
    var activationURL: URL? {
        URL(string: verificationUriWithRequest ?? verificationUri)
    }
}

// MARK: - 轮询响应

struct DevicePollResponse: Decodable {

    enum Status: String, Decodable {
        case authorizationPending = "authorization_pending"
        case authorized
        case accessDenied = "access_denied"
        case expiredToken = "expired_token"
    }

    let status: Status
    /// 仅 `authorized` 时出现：RSA 加密的 `{key, nonce}`，服务端只给一次。
    let payload: String?

    private enum CodingKeys: String, CodingKey {
        case status, payload
    }

    init(from decoder: Decoder) throws {
        let c = try decoder.container(keyedBy: CodingKeys.self)
        let raw = try c.decode(String.self, forKey: .status)
        guard let parsed = Status(rawValue: raw) else {
            throw DiscourseError.decoding("未知的授权状态：\(raw)")
        }
        status = parsed
        payload = try c.decodeIfPresent(String.self, forKey: .payload)
    }

    var isPending: Bool { status == .authorizationPending }
}

// MARK: - 待完成的设备授权

/// 设备授权期间私钥必须活到轮询成功为止：用户去浏览器输码时 App 可能被系统回收，
/// 重启后还要能用同一把私钥解密 payload。
enum PendingDeviceAuthorizationStore {

    private struct Record: Codable {
        let privateKey: Data
        let nonce: String
        let deviceCode: String
        let createdAt: Date
    }

    private static let service = "com.example.linuxdoclient.credentials"
    private static let account = "pending-device-authorization"

    private static var query: [String: Any] {
        [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: service,
            kSecAttrAccount as String: account
        ]
    }

    static func save(
        material: RSAKeyPair.Material,
        nonce: String,
        deviceCode: String
    ) throws {
        var error: Unmanaged<CFError>?
        guard let data = SecKeyCopyExternalRepresentation(material.privateKey, &error) as Data? else {
            throw DiscourseError.transport("无法导出本次授权私钥")
        }
        let record = Record(
            privateKey: data,
            nonce: nonce,
            deviceCode: deviceCode,
            createdAt: Date()
        )
        var attributes = query
        attributes[kSecValueData as String] = try JSONEncoder().encode(record)
        attributes[kSecAttrAccessible as String] = kSecAttrAccessibleWhenUnlockedThisDeviceOnly
        clear()
        guard SecItemAdd(attributes as CFDictionary, nil) == errSecSuccess else {
            throw DiscourseError.transport("无法把待完成的设备授权写入钥匙串")
        }
    }

    static func load() -> (material: RSAKeyPair.Material, nonce: String, deviceCode: String)? {
        var attributes = query
        attributes[kSecReturnData as String] = true
        attributes[kSecMatchLimit as String] = kSecMatchLimitOne
        var result: CFTypeRef?
        guard SecItemCopyMatching(attributes as CFDictionary, &result) == errSecSuccess,
              let data = result as? Data,
              let record = try? JSONDecoder().decode(Record.self, from: data),
              // 设备码本身 10 分钟就废，留 30 分钟余量足够，超时直接清掉。
              Date().timeIntervalSince(record.createdAt) < 30 * 60,
              let material = RSAKeyPair.restore(privateKeyData: record.privateKey) else {
            clear()
            return nil
        }
        return (material, record.nonce, record.deviceCode)
    }

    static func clear() {
        SecItemDelete(query as CFDictionary)
    }
}

// MARK: - 密钥存储

/// user API key 存 Keychain，不用 UserDefaults。
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
