import Foundation
import Security

/// Discourse 的 User API Key 流程所需的 RSA 工具。
///
/// 流程：
/// 1. 客户端生成 RSA 2048 密钥对 + 随机 nonce
/// 2. 在系统认证浏览器中 GET `/user-api-key/new`，查询参数包含公钥等授权信息
/// 3. 用户在浏览器里登录并点「授权」
/// 4. 服务端回调 `auth_redirect?payload=...`，nonce 在加密 payload 内
/// 5. 客户端用私钥做 RSA PKCS#1 v1.5 解密，得到 `{"key": "...", "nonce": "..."}`
/// 6. 之后请求带 `User-Api-Key: <key>`
///
/// 网页登录和授权由浏览器维持会话，原生请求使用授权得到的密钥。
enum RSAKeyPair {

    struct Material {
        let privateKey: SecKey
        let publicKeyPEM: String
    }

    static func generate(bits: Int = 2048) -> Material? {
        let attributes: [String: Any] = [
            kSecAttrKeyType as String: kSecAttrKeyTypeRSA,
            kSecAttrKeySizeInBits as String: bits,
            kSecPrivateKeyAttrs as String: [
                kSecAttrIsPermanent as String: false
            ]
        ]

        var error: Unmanaged<CFError>?
        guard let privateKey = SecKeyCreateRandomKey(attributes as CFDictionary, &error) else {
            NSLog("[RSAKeyPair] 生成失败：\(String(describing: error))")
            return nil
        }
        guard let publicKey = SecKeyCopyPublicKey(privateKey) else { return nil }
        guard let der = SecKeyCopyExternalRepresentation(publicKey, &error) as Data? else {
            NSLog("[RSAKeyPair] 导出公钥失败：\(String(describing: error))")
            return nil
        }

        // SecKey 导出的 RSA 公钥是 PKCS#1 DER，OpenSSL 用 "RSA PUBLIC KEY" 头能直接解析。
        return Material(privateKey: privateKey, publicKeyPEM: pem(der: der, label: "RSA PUBLIC KEY"))
    }

    private static func pem(der: Data, label: String) -> String {
        let base64 = der.base64EncodedString(options: [.lineLength64Characters, .endLineWithLineFeed])
        return "-----BEGIN \(label)-----\n\(base64)\n-----END \(label)-----"
    }

    /// 用私钥解 discourse 加密的 payload。
    static func decrypt(base64: String, privateKey: SecKey) -> Data? {
        guard let cipher = Data(base64Encoded: base64, options: [.ignoreUnknownCharacters]) else {
            return nil
        }
        var error: Unmanaged<CFError>?
        guard let clear = SecKeyCreateDecryptedData(
            privateKey,
            .rsaEncryptionPKCS1,
            cipher as CFData,
            &error
        ) else {
            NSLog("[RSAKeyPair] 解密失败：\(String(describing: error))")
            return nil
        }
        return clear as Data
    }

    static func randomNonce(length: Int = 32) -> String {
        var bytes = [UInt8](repeating: 0, count: length)
        if SecRandomCopyBytes(kSecRandomDefault, length, &bytes) != errSecSuccess {
            return UUID().uuidString.replacingOccurrences(of: "-", with: "")
        }
        return bytes.map { String(format: "%02x", $0) }.joined()
    }
}

/// 经典 User API Key 流程的配置，与站点定制设备码流程分开。
enum UserApiKeyConfig {
    static let clientId: String = {
        let storageKey = "user-api-client-id"
        if let value = UserDefaults.standard.string(forKey: storageKey), !value.isEmpty {
            return value
        }
        let value = UUID().uuidString
        UserDefaults.standard.set(value, forKey: storageKey)
        return value
    }()

    // 当前客户端只读；不申请需要推送地址的 notifications 权限。
    static let scopes = ["read", "session_info"]
    // Discourse 默认允许此回调；站点管理员仍可自行调整允许列表。
    static let authRedirect = "discourse://auth_redirect"
    static let callbackScheme = "discourse"
}

enum UserApiKeyAuthorization {
    static func makeURL(
        baseURL: URL,
        applicationName: String,
        publicKeyPEM: String,
        nonce: String,
        clientId: String,
        scopes: [String],
        redirect: String
    ) throws -> URL {
        guard var components = URLComponents(url: baseURL, resolvingAgainstBaseURL: false) else {
            throw DiscourseError.badURL
        }
        let prefix = components.path.trimmingCharacters(in: CharacterSet(charactersIn: "/"))
        components.path = prefix.isEmpty ? "/user-api-key/new" : "/\(prefix)/user-api-key/new"
        components.fragment = nil
        components.queryItems = [
            URLQueryItem(name: "application_name", value: applicationName),
            URLQueryItem(name: "client_id", value: clientId),
            URLQueryItem(name: "scopes", value: scopes.joined(separator: ",")),
            URLQueryItem(name: "public_key", value: publicKeyPEM),
            URLQueryItem(name: "nonce", value: nonce),
            URLQueryItem(name: "auth_redirect", value: redirect)
        ]
        // Rails 按表单规则解析查询串；公钥中的加号必须编码，不能变成空格。
        components.percentEncodedQuery = components.percentEncodedQuery?
            .replacingOccurrences(of: "+", with: "%2B")
        guard let url = components.url else { throw DiscourseError.badURL }
        return url
    }

    struct Payload: Decodable {
        let key: String
        let nonce: String
    }

    static func decodeCallback(
        _ url: URL,
        expectedRedirect: String,
        expectedNonce: String,
        privateKey: SecKey
    ) throws -> Payload {
        guard let expected = URLComponents(string: expectedRedirect),
              let actual = URLComponents(url: url, resolvingAgainstBaseURL: false),
              actual.scheme?.lowercased() == expected.scheme?.lowercased(),
              actual.host?.lowercased() == expected.host?.lowercased(),
              actual.path == expected.path,
              actual.port == expected.port,
              actual.user == nil, actual.password == nil, actual.fragment == nil else {
            throw DiscourseError.decoding("授权回调地址不匹配")
        }
        let values = (actual.queryItems ?? []).filter { $0.name == "payload" }
        guard values.count == 1, let encrypted = values.first?.value, !encrypted.isEmpty else {
            throw DiscourseError.decoding("授权回调缺少唯一的 payload")
        }
        guard let data = RSAKeyPair.decrypt(base64: encrypted, privateKey: privateKey),
              let payload = try? JSONDecoder().decode(Payload.self, from: data),
              !payload.key.isEmpty else {
            throw DiscourseError.decoding("授权结果解密失败或缺少密钥")
        }
        guard !expectedNonce.isEmpty, payload.nonce == expectedNonce else {
            throw DiscourseError.decoding("授权结果 nonce 不匹配，请重新授权")
        }
        return payload
    }
}
