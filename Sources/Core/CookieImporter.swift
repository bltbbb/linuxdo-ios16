import Foundation

/// 把用户粘贴的 Cookie 文本解析成 `HTTPCookie`。
///
/// 站点只承认浏览器会话，而会话凭据就是 `_t` 这类 cookie。
/// 用户从电脑浏览器复制出来后，这里直接还原成原生会话，全程不经过 WebKit。
enum CookieImporter {

    private static let attributeNames: Set<String> = [
        "path", "domain", "expires", "max-age", "samesite", "secure", "httponly",
        "priority", "partitioned"
    ]

    /// 支持三种粘贴形式：
    /// 1. `_t=xxxxx`
    /// 2. `_t=xxxxx; _forum_session=yyyyy`
    /// 3. 只有 `_t` 的值（裸值）
    static func parse(_ raw: String, host: String) -> [HTTPCookie] {
        let text = raw.trimmingCharacters(in: .whitespacesAndNewlines)
        guard !text.isEmpty else { return [] }

        var pairs: [(String, String)] = []

        for segment in text.split(separator: ";") {
            let part = segment.trimmingCharacters(in: .whitespacesAndNewlines)
            guard let separatorIndex = part.firstIndex(of: "=") else { continue }

            let name = String(part[part.startIndex..<separatorIndex])
                .trimmingCharacters(in: .whitespacesAndNewlines)
            let value = String(part[part.index(after: separatorIndex)...])
                .trimmingCharacters(in: .whitespacesAndNewlines)

            guard !name.isEmpty, !value.isEmpty else { continue }
            guard !attributeNames.contains(name.lowercased()) else { continue }
            pairs.append((name, value))
        }

        // 用户只复制了 _t 的值本身
        if pairs.isEmpty, !text.contains("=") {
            pairs.append(("_t", text))
        }

        let expires = Date().addingTimeInterval(60 * 60 * 24 * 60)
        return pairs.compactMap { name, value in
            HTTPCookie(properties: [
                .domain: host,
                .path: "/",
                .name: name,
                .value: value,
                .secure: "TRUE",
                .expires: expires
            ])
        }
    }
}
