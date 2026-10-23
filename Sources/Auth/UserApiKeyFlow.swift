import Foundation
import Security

/// Discourse 的 User API Key 流程所需的 RSA 工具。
///
/// 流程：
/// 1. 客户端生成 RSA 2048 密钥对 + 随机 nonce
/// 2. `POST /user-api-key/new`（带公钥、nonce、scopes、auth_redirect）
///    服务端返回一个页面，内含加密后的 `payload`
/// 3. 用户在浏览器里登录并点「授权」
/// 4. 服务端 302 到 `auth_redirect?payload=...&nonce=...`
/// 5. 客户端用私钥做 RSA PKCS#1 v1.5 解密，得到 `{"key": "...", "nonce": "..."}`
/// 6. 之后请求带 `User-Api-Key: <key>`
///
/// 与 cookie 会话、WKWebView 都无关。
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

/// 从 `/user-api-key/new` 返回的 HTML 里取出加密 payload。
enum PayloadExtractor {

    static func extract(from html: String) -> String? {
        let patterns = [
            #"name="payload"\s+value="([^"]+)""#,
            #"value="([^"]+)"\s+name="payload""#,
            #"name='payload'\s+value='([^']+)'"#,
            #"id="payload"[^>]*value="([^"]+)""#
        ]
        for pattern in patterns {
            guard let regex = try? NSRegularExpression(pattern: pattern) else { continue }
            let range = NSRange(html.startIndex..<html.endIndex, in: html)
            guard let match = regex.firstMatch(in: html, range: range),
                  match.numberOfRanges > 1,
                  let captured = Range(match.range(at: 1), in: html) else { continue }
            return decodeEntities(String(html[captured]))
        }
        return nil
    }

    private static func decodeEntities(_ text: String) -> String {
        text
            .replacingOccurrences(of: "&amp;", with: "&")
            .replacingOccurrences(of: "&#43;", with: "+")
            .replacingOccurrences(of: "&#x2B;", with: "+")
            .replacingOccurrences(of: "&quot;", with: "\"")
            .replacingOccurrences(of: "&#39;", with: "'")
    }
}
