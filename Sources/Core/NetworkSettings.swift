import Foundation

/// 用户手动指定的服务器 IP。
///
/// 站点走 Cloudflare，国内的 IP 可达性随时变化：DoH 返回的地址经常整段不通。
/// 这里允许用户自己填一个能连通的 IP，传输层直接用它建连，
/// TLS 的 SNI 与 HTTP 的 Host 仍然写域名，证书照常校验。
enum NetworkSettings {

    private static let key = "custom-host-ips"
    private static let baseURLKey = "custom-api-base-url"

    /// 自定义 API 根地址（自建反代）。空则用默认的 https://linux.do。
    static var customBaseURL: URL? {
        get {
            let raw = (UserDefaults.standard.string(forKey: baseURLKey) ?? "")
                .trimmingCharacters(in: .whitespacesAndNewlines)
            guard !raw.isEmpty, let url = URL(string: raw), url.host != nil else { return nil }
            return url
        }
        set {
            if let newValue = newValue {
                UserDefaults.standard.set(newValue.absoluteString, forKey: baseURLKey)
            } else {
                UserDefaults.standard.removeObject(forKey: baseURLKey)
            }
        }
    }

    static var customIPs: [String] {
        get {
            let raw = UserDefaults.standard.string(forKey: key) ?? ""
            return raw
                .split(whereSeparator: { $0 == "," || $0 == "\n" || $0 == " " })
                .map { $0.trimmingCharacters(in: .whitespaces) }
                .filter { !$0.isEmpty }
        }
        set {
            UserDefaults.standard.set(newValue.joined(separator: ","), forKey: key)
        }
    }

    static var hasCustomIPs: Bool {
        !customIPs.isEmpty
    }

    static func clear() {
        UserDefaults.standard.removeObject(forKey: key)
    }
}
