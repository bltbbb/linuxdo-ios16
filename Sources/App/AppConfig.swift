import Foundation

/// 全局配置。刻意不读取任何 iOS 17+ 接口。
enum AppConfig {

    /// 论坛基于 Discourse；站点可能扩展认证接口，不假定与上游完全一致。
    static let baseURL = URL(string: "https://linux.do")!

    static let clientName = "LinuxDoClient"
    static let appVersion = "1.0.0"

    /// 原 app 强依赖 Cloudflare 前置，UA 必须足够像浏览器，否则可能被 403。
    ///
    /// Cloudflare 的 `cf_clearance` 与 User-Agent 绑定：要复用浏览器导出的
    /// clearance，UA 必须和那个浏览器一模一样，所以在网络设置里可以覆盖。
    static var userAgent: String {
        NetworkSettings.customUserAgent ?? defaultUserAgent
    }

    private static let defaultUserAgent: String = {
        let os = ProcessInfo.processInfo.operatingSystemVersion
        let ver = "\(os.majorVersion)_\(os.minorVersion)"
        // 不带任何 app 标识：Cloudflare 的 cf_clearance 与 UA 绑定，
        // 多一个后缀就会让浏览器拿到的 clearance 失效。
        return "Mozilla/5.0 (iPhone; CPU iPhone OS \(ver) like Mac OS X) "
            + "AppleWebKit/605.1.15 (KHTML, like Gecko) Version/\(os.majorVersion).\(os.minorVersion) "
            + "Mobile/15E148 Safari/604.1"
    }()

    static let perPage = 30
    static let cacheTTL: TimeInterval = 60 * 10
    /// 与原 app 的 SwiftData 三个实体对应，用于 Core Data 缓存键。
    enum CacheKey {
        static let site = "linuxdo.site-cache"
        static func topicList(_ filter: String, page: Int) -> String { "linuxdo.topic-list.\(filter).p\(page)" }
        static func topicDetail(_ id: Int) -> String { "linuxdo.topic-detail.\(id)" }
    }
}
