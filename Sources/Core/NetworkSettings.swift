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

    private static let userAgentKey = "custom-user-agent"

    /// 自定义 User-Agent。
    ///
    /// Cloudflare 的 `cf_clearance` 与 UA 绑定，要复用浏览器导出的 clearance，
    /// UA 必须和那个浏览器完全一致。
    static var customUserAgent: String? {
        get {
            let raw = (UserDefaults.standard.string(forKey: userAgentKey) ?? "")
                .trimmingCharacters(in: .whitespacesAndNewlines)
            return raw.isEmpty ? nil : raw
        }
        set {
            let value = newValue?.trimmingCharacters(in: .whitespacesAndNewlines) ?? ""
            if value.isEmpty {
                UserDefaults.standard.removeObject(forKey: userAgentKey)
            } else {
                UserDefaults.standard.set(value, forKey: userAgentKey)
            }
        }
    }

    private static let preferQUICKey = "prefer-quic"

    /// 是否优先用 QUIC/HTTP3 出网。默认开启。
    ///
    /// 原版的连接统计是 100% HTTP/3、0% HTTP/2，说明它完全不走 TCP。
    /// TCP 下 TLS ClientHello 的 SNI 是明文的，部分网络直接 RST；
    /// QUIC 握手在加密帧里，看不到域名。且走的是 Apple 原生 TLS 栈，
    /// 指纹与 Safari 一致，不像第三方 QUIC 库那样被 Cloudflare 判成机器人。
    static var preferQUIC: Bool {
        get {
            if UserDefaults.standard.object(forKey: preferQUICKey) == nil { return true }
            return UserDefaults.standard.bool(forKey: preferQUICKey)
        }
        set {
            UserDefaults.standard.set(newValue, forKey: preferQUICKey)
        }
    }
}
