import Foundation

/// 用 DoH（DNS over HTTPS）解析域名，绕开本地 DNS 污染。
/// 同时查 A 与 AAAA，多个端点并发，取最先成功的一个。
actor DoHResolver {

    static let shared = DoHResolver()

    /// 只放国内直连可达的端点。
    private static let endpoints = [
        // 原 app 自建的 DoH 中转，实测返回的是真实的 Cloudflare 边缘地址。
        "https://ios-app.ddd.oaifree.com/query-dns",
        "https://dns.alidns.com/dns-query",
        "https://doh.pub/dns-query",
        "https://223.5.5.5/dns-query",
        "https://1.12.12.12/dns-query",
        "https://doh.360.cn/dns-query"
    ]

    private static let session: URLSession = {
        let config = URLSessionConfiguration.ephemeral
        config.timeoutIntervalForRequest = 3
        config.timeoutIntervalForResource = 5
        config.requestCachePolicy = .reloadIgnoringLocalCacheData
        return URLSession(configuration: config)
    }()

    private var cache: [String: (ips: [String], expiresAt: Date)] = [:]
    private let cacheTTL: TimeInterval = 300

    enum ResolveError: LocalizedError {
        case allEndpointsFailed(String)

        var errorDescription: String? {
            switch self {
            case .allEndpointsFailed(let detail): return "DoH 解析失败：\(detail)"
            }
        }
    }

    /// 返回候选地址，IPv6 在前（CF 的 v6 在国内有时反而可用）。
    func resolve(_ host: String) async throws -> [String] {
        let outcome = await resolveReport(host)
        guard !outcome.ips.isEmpty else {
            throw ResolveError.allEndpointsFailed(
                outcome.report.isEmpty ? "全部端点无应答" : outcome.report.joined(separator: " | ")
            )
        }
        return outcome.ips
    }

    /// 收集**所有**端点的答案，并附带每个端点的结果。
    ///
    /// 不能「谁先答就用谁」：本地链路会伪造 DNS 应答（典型投毒落在
    /// Facebook 的 2a03:2880::/32 或 182.50.x.x），抢先返回的往往正是假地址，
    /// 一旦选中，后面所有握手都在攻击者给的 IP 上空转到超时。
    /// 这里把所有答案一起交给传输层，能完成握手并核对证书的那个才算数。
    func resolveReport(_ host: String) async -> (ips: [String], report: [String]) {
        if let entry = cache[host], entry.expiresAt > Date(), !entry.ips.isEmpty {
            return (entry.ips, ["命中缓存"])
        }

        var v4: [String] = []
        var v6: [String] = []
        var report: [String] = []

        await withTaskGroup(of: (String, Result<[String], Error>).self) { group in
            for endpoint in Self.endpoints {
                for recordType in [UInt16(1), UInt16(28)] {
                    let label = "\(Self.shortName(endpoint))#\(recordType == 1 ? "A" : "AAAA")"
                    group.addTask {
                        do {
                            let ips = try await Self.query(host: host, type: recordType, endpoint: endpoint)
                            return (label, .success(ips))
                        } catch {
                            return (label, .failure(error))
                        }
                    }
                }
            }

            while let (label, result) = await group.next() {
                switch result {
                case .success(let ips):
                    if ips.isEmpty {
                        report.append("\(label)空")
                        continue
                    }
                    var fresh: [String] = []
                    for ip in ips {
                        if ip.contains(":") {
                            if !v6.contains(ip) { v6.append(ip); fresh.append(ip) }
                        } else {
                            if !v4.contains(ip) { v4.append(ip); fresh.append(ip) }
                        }
                    }
                    if !fresh.isEmpty {
                        report.append("\(label)→\(fresh.joined(separator: ","))")
                    }
                case .failure:
                    report.append("\(label)✗")
                }
            }
        }

        let combined = Array((v6 + v4).prefix(12))
        if !combined.isEmpty {
            cache[host] = (combined, Date().addingTimeInterval(cacheTTL))
        }
        return (combined, report)
    }

    private static func shortName(_ endpoint: String) -> String {
        guard let name = URL(string: endpoint)?.host else { return endpoint }
        return name.hasPrefix("ios-app.") ? "oaifree" : name
    }

    func invalidate(_ host: String) {
        cache.removeValue(forKey: host)
    }

    // MARK: - 单次 DoH 查询（无状态，可并发）

    private static func query(host: String, type: UInt16, endpoint: String) async throws -> [String] {
        guard let url = URL(string: endpoint) else { return [] }

        var request = URLRequest(url: url)
        request.httpMethod = "POST"
        request.setValue("application/dns-message", forHTTPHeaderField: "Content-Type")
        request.setValue("application/dns-message", forHTTPHeaderField: "Accept")
        request.httpBody = buildQuery(host: host, type: type)

        let (data, response) = try await session.data(for: request)
        guard let http = response as? HTTPURLResponse, http.statusCode == 200 else {
            throw ResolveError.allEndpointsFailed("HTTP \((response as? HTTPURLResponse)?.statusCode ?? -1)")
        }
        return parseAnswers(data, type: type)
    }

    // MARK: - DNS 报文

    static func buildQuery(host: String, type: UInt16 = 1) -> Data {
        var data = Data()
        var identifier = UInt16.random(in: 1...UInt16.max)
        withUnsafeBytes(of: &identifier) { data.append(contentsOf: $0.reversed()) }
        data.append(contentsOf: [0x01, 0x00])   // RD=1
        data.append(contentsOf: [0x00, 0x01])   // QDCOUNT=1
        data.append(contentsOf: [0x00, 0x00])   // ANCOUNT
        data.append(contentsOf: [0x00, 0x00])   // NSCOUNT
        data.append(contentsOf: [0x00, 0x00])   // ARCOUNT

        for label in host.split(separator: ".") {
            let bytes = Array(label.utf8)
            guard bytes.count < 64 else { continue }
            data.append(UInt8(bytes.count))
            data.append(contentsOf: bytes)
        }
        data.append(0)
        data.append(contentsOf: [UInt8(type >> 8), UInt8(type & 0xff)])
        data.append(contentsOf: [0x00, 0x01])   // CLASS=IN
        return data
    }

    static func parseAnswers(_ data: Data, type: UInt16 = 1) -> [String] {
        let bytes = [UInt8](data)
        guard bytes.count > 12 else { return [] }

        let qdCount = Int(bytes[4]) << 8 | Int(bytes[5])
        let anCount = Int(bytes[6]) << 8 | Int(bytes[7])
        guard anCount > 0 else { return [] }

        var offset = 12
        for _ in 0..<qdCount {
            guard skipName(bytes, &offset) else { return [] }
            offset += 4
            guard offset <= bytes.count else { return [] }
        }

        var result: [String] = []
        for _ in 0..<anCount {
            guard skipName(bytes, &offset) else { break }
            guard offset + 10 <= bytes.count else { break }
            let recordType = Int(bytes[offset]) << 8 | Int(bytes[offset + 1])
            let rdLength = Int(bytes[offset + 8]) << 8 | Int(bytes[offset + 9])
            offset += 10
            guard offset + rdLength <= bytes.count else { break }

            if recordType == 1, rdLength == 4 {
                let ip = "\(bytes[offset]).\(bytes[offset + 1]).\(bytes[offset + 2]).\(bytes[offset + 3])"
                if !result.contains(ip) { result.append(ip) }
            } else if recordType == 28, rdLength == 16 {
                var groups: [String] = []
                for index in stride(from: 0, to: 16, by: 2) {
                    groups.append(String(format: "%x", Int(bytes[offset + index]) << 8 | Int(bytes[offset + index + 1])))
                }
                let ip = groups.joined(separator: ":")
                if !result.contains(ip) { result.append(ip) }
            }
            offset += rdLength
        }
        return result
    }

    private static func skipName(_ bytes: [UInt8], _ offset: inout Int) -> Bool {
        while offset < bytes.count {
            let length = Int(bytes[offset])
            if length == 0 {
                offset += 1
                return true
            }
            if length & 0xC0 == 0xC0 {
                offset += 2
                return true
            }
            offset += 1 + length
        }
        return false
    }
}
