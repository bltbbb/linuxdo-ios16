import Foundation

/// 用 DoH（DNS over HTTPS）解析域名，绕开本地 DNS 污染。
///
/// 原版 app 用 libcurl + `CURLOPT_DOH_URL` 做同样的事。这里不引入 C 依赖，
/// 直接按 RFC 8484 构造/解析 DNS 报文，走系统 URLSession 请求国内可达的 DoH 端点。
actor DoHResolver {

    static let shared = DoHResolver()

    /// 只放国内直连可达的端点；cloudflare / google 在不挂代理时不可用。
    private let endpoints = [
        "https://dns.alidns.com/dns-query",
        "https://doh.pub/dns-query",
        "https://223.5.5.5/dns-query"
    ]

    private var cache: [String: (ips: [String], expiresAt: Date)] = [:]
    private let cacheTTL: TimeInterval = 300

    private let session: URLSession = {
        let config = URLSessionConfiguration.ephemeral
        config.timeoutIntervalForRequest = 4
        config.timeoutIntervalForResource = 6
        config.requestCachePolicy = .reloadIgnoringLocalCacheData
        return URLSession(configuration: config)
    }()

    enum ResolveError: LocalizedError {
        case allEndpointsFailed(String)
        case emptyAnswer(String)

        var errorDescription: String? {
            switch self {
            case .allEndpointsFailed(let detail): return "DoH 解析失败：\(detail)"
            case .emptyAnswer(let host): return "DoH 未返回 \(host) 的 A 记录"
            }
        }
    }

    func resolve(_ host: String) async throws -> [String] {
        if let entry = cache[host], entry.expiresAt > Date(), !entry.ips.isEmpty {
            return entry.ips
        }

        var failures: [String] = []
        for endpoint in endpoints {
            do {
                let ips = try await query(host: host, endpoint: endpoint)
                if !ips.isEmpty {
                    cache[host] = (ips, Date().addingTimeInterval(cacheTTL))
                    return ips
                }
                failures.append("\(endpoint): 空应答")
            } catch {
                failures.append("\(endpoint): \(error.localizedDescription)")
            }
        }
        throw ResolveError.allEndpointsFailed(failures.joined(separator: " | "))
    }

    func invalidate(_ host: String) {
        cache.removeValue(forKey: host)
    }

    // MARK: - 单次 DoH 查询

    private func query(host: String, endpoint: String) async throws -> [String] {
        guard let url = URL(string: endpoint) else { return [] }

        var request = URLRequest(url: url)
        request.httpMethod = "POST"
        request.setValue("application/dns-message", forHTTPHeaderField: "Content-Type")
        request.setValue("application/dns-message", forHTTPHeaderField: "Accept")
        request.httpBody = Self.buildQuery(host: host)

        let (data, response) = try await session.data(for: request)
        guard let http = response as? HTTPURLResponse, http.statusCode == 200 else {
            throw ResolveError.allEndpointsFailed("HTTP \((response as? HTTPURLResponse)?.statusCode ?? -1)")
        }
        return Self.parseAnswers(data)
    }

    // MARK: - DNS 报文

    /// 构造一个标准 A 记录查询报文。
    static func buildQuery(host: String) -> Data {
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
        data.append(0)                          // 名字结束
        data.append(contentsOf: [0x00, 0x01])   // TYPE=A
        data.append(contentsOf: [0x00, 0x01])   // CLASS=IN
        return data
    }

    /// 从响应报文里取所有 A 记录的 IPv4 地址。
    static func parseAnswers(_ data: Data) -> [String] {
        let bytes = [UInt8](data)
        guard bytes.count > 12 else { return [] }

        let qdCount = Int(bytes[4]) << 8 | Int(bytes[5])
        let anCount = Int(bytes[6]) << 8 | Int(bytes[7])
        guard anCount > 0 else { return [] }

        var offset = 12
        // 跳过 question 段
        for _ in 0..<qdCount {
            guard skipName(bytes, &offset) else { return [] }
            offset += 4
            guard offset <= bytes.count else { return [] }
        }

        var result: [String] = []
        for _ in 0..<anCount {
            guard skipName(bytes, &offset) else { break }
            guard offset + 10 <= bytes.count else { break }
            let type = Int(bytes[offset]) << 8 | Int(bytes[offset + 1])
            let rdLength = Int(bytes[offset + 8]) << 8 | Int(bytes[offset + 9])
            offset += 10
            guard offset + rdLength <= bytes.count else { break }
            if type == 1, rdLength == 4 {
                let ip = "\(bytes[offset]).\(bytes[offset + 1]).\(bytes[offset + 2]).\(bytes[offset + 3])"
                if !result.contains(ip) { result.append(ip) }
            }
            offset += rdLength
        }
        return result
    }

    /// 跳过域名（可能是标签序列，也可能是压缩指针）。
    private static func skipName(_ bytes: [UInt8], _ offset: inout Int) -> Bool {
        while offset < bytes.count {
            let length = Int(bytes[offset])
            if length == 0 {
                offset += 1
                return true
            }
            if length & 0xC0 == 0xC0 {   // 压缩指针，两字节
                offset += 2
                return true
            }
            offset += 1 + length
        }
        return false
    }
}
