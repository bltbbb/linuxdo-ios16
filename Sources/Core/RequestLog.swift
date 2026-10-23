import Foundation

/// 环形请求日志，只存在内存里，用于真机排错。
///
/// 记录方法、路径、状态及脱敏诊断，用于区分会话错误与网络拦截。
actor RequestLog {

    static let shared = RequestLog()

    struct Entry {
        let method: String
        let url: String
        let status: Int
        let note: String
    }

    private var entries: [Entry] = []
    private let capacity = 60

    func record(method: String, url: String, status: Int, note: String) {
        let cleaned = note
            .replacingOccurrences(of: "\n", with: " ")
            .trimmingCharacters(in: .whitespacesAndNewlines)
        entries.append(
            Entry(method: method, url: url, status: status, note: String(cleaned.prefix(400)))
        )
        if entries.count > capacity {
            entries.removeFirst(entries.count - capacity)
        }
    }

    func snapshot() -> [Entry] {
        entries
    }

    func reset() {
        entries.removeAll()
    }

    /// 给用户看/复制的文本形式。
    func report() -> String {
        guard !entries.isEmpty else { return "（无请求记录）" }
        return entries.enumerated().map { index, entry in
            "[\(index + 1)] \(entry.method) \(entry.url) → \(entry.status)\n\(entry.note)"
        }.joined(separator: "\n\n")
    }
}
