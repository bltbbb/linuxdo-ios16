import Foundation

/// 全局配置。刻意不读取任何 iOS 17+ 接口。
enum AppConfig {

    /// 后端就是标准 Discourse，与原 app 1.0.2 完全一致。
    static let baseURL = URL(string: "https://linux.do")!

    static let clientName = "LinuxDoClient"
    static let appVersion = "1.0.0"

    /// 原 app 强依赖 Cloudflare 前置，UA 必须足够像浏览器，否则可能被 403。
    static let userAgent: String = {
        let os = ProcessInfo.processInfo.operatingSystemVersion
        let ver = "\(os.majorVersion)_\(os.minorVersion)"
        return "Mozilla/5.0 (iPhone; CPU iPhone OS \(ver) like Mac OS X) "
            + "AppleWebKit/605.1.15 (KHTML, like Gecko) Version/\(os.majorVersion).\(os.minorVersion) "
            + "Mobile/15E148 Safari/604.1 \(clientName)/\(appVersion)"
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
