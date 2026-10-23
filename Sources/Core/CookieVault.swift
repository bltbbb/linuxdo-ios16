import Foundation
import Security

/// 把登录 Cookie 存进 Keychain。
///
/// `HTTPCookieStorage` 存在 app 沙盒里，卸载重装就清空——每次都要重新粘贴。
/// Keychain 条目不随 app 卸载删除，所以重装后能自动恢复会话。
enum CookieVault {

    private static let service = "com.example.linuxdoclient.session"
    private static let account = "session-cookie"

    static func save(_ cookieHeader: String) {
        let value = cookieHeader.trimmingCharacters(in: .whitespacesAndNewlines)
        guard !value.isEmpty else { return }

        clear()
        let query: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: service,
            kSecAttrAccount as String: account,
            kSecValueData as String: Data(value.utf8),
            kSecAttrAccessible as String: kSecAttrAccessibleAfterFirstUnlock
        ]
        let status = SecItemAdd(query as CFDictionary, nil)
        if status != errSecSuccess {
            NSLog("[CookieVault] 保存失败：\(status)")
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
              let data = item as? Data,
              let text = String(data: data, encoding: .utf8),
              !text.isEmpty else {
            return nil
        }
        return text
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
