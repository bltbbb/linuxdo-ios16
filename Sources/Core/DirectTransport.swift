import Foundation
import Network
import Security

/// 绕过本地 DNS 污染的传输层：用 DoH 解析出 IP，再按 IP 建立 TLS 连接，
/// 但 TLS 的 SNI 与 HTTP 的 Host 仍然写域名——这样证书校验照常生效，
/// 服务器也正常返回内容。原版 app 用 libcurl 的 `CURLOPT_RESOLVE` 做的是同一件事。
final class DirectTransport {

    static let shared = DirectTransport()

    enum TransportError: LocalizedError {
        case badURL
        case connect(String)
        case timeout
        case malformedResponse

        var errorDescription: String? {
            switch self {
            case .badURL: return "请求地址无效"
            case .connect(let detail): return "直连失败：\(detail)"
            case .timeout: return "直连超时"
            case .malformedResponse: return "响应格式无法解析"
            }
        }
    }

    private let queue = DispatchQueue(label: "io.linuxdo.direct-transport")

    /// 已验证可连通的地址，按 host 缓存十分钟。
    private let cacheLock = NSLock()
    private var preferred: [String: (ip: String, at: Date)] = [:]

    func send(_ request: URLRequest, timeout: TimeInterval = 12) async throws -> (Data, HTTPURLResponse) {
        guard let url = request.url, let host = url.host else {
            throw TransportError.badURL
        }
        let port = url.port ?? 443

        // 候选顺序：用户手动指定 > DoH 解析结果 + 同段邻居扩展
        var seeds = NetworkSettings.customIPs
        if seeds.isEmpty {
            seeds = try await DoHResolver.shared.resolve(host)
        }
        let candidates = Self.expandNeighbours(seeds)
        guard !candidates.isEmpty else {
            throw TransportError.connect("没有可用的服务器地址")
        }

        // 上次打通的地址先用一次，省掉每次请求都重新探测的开销。
        if let cached = cachedIP(for: host) {
            do {
                return try await roundTrip(
                    request, url: url, host: host, ip: cached, port: port, timeout: min(timeout, 6)
                )
            } catch {
                storeCachedIP(nil, for: host)
            }
        }

        // 并发探测：每个候选各自有硬超时，谁先打通就用谁。
        let probeTimeout = min(timeout, 4)
        var lastError: Error?

        let raced = await withTaskGroup(
            of: (String, Result<(Data, HTTPURLResponse), Error>).self,
            returning: (String, (Data, HTTPURLResponse))?.self
        ) { group -> (String, (Data, HTTPURLResponse))? in
            for ip in candidates.prefix(20) {
                group.addTask {
                    do {
                        return (ip, .success(try await self.roundTrip(
                            request, url: url, host: host, ip: ip, port: port, timeout: probeTimeout
                        )))
                    } catch {
                        return (ip, .failure(error))
                    }
                }
            }

            var winner: (String, (Data, HTTPURLResponse))?
            while let outcome = await group.next() {
                if case .success(let payload) = outcome.1 {
                    winner = (outcome.0, payload)
                    group.cancelAll()
                    break
                }
                if case .failure(let error) = outcome.1 { lastError = error }
            }
            return winner
        }

        if let winner = raced {
            storeCachedIP(winner.0, for: host)
            return winner.1
        }
        throw lastError ?? TransportError.connect("所有候选地址均不可达（\(candidates.count) 个）")
    }

    /// 把解析结果扩展成同 /24 段的邻居候选。
    /// Cloudflare 同一段内的边缘节点通常都服务同一个站点，单点被封时邻居常可用。
    static func expandNeighbours(_ seeds: [String]) -> [String] {
        var result: [String] = []
        for seed in seeds where !result.contains(seed) {
            result.append(seed)
        }

        for seed in seeds.prefix(3) where !seed.contains(":") {
            let parts = seed.split(separator: ".")
            guard parts.count == 4, let last = Int(parts[3]) else { continue }
            let prefix = parts.prefix(3).joined(separator: ".")
            for offset in [-4, -3, -2, -1, 1, 2, 3, 4, 6, 8] {
                let candidate = last + offset
                guard candidate > 0, candidate < 255 else { continue }
                let value = "\(prefix).\(candidate)"
                if !result.contains(value) { result.append(value) }
            }
        }
        return result
    }


    // MARK: - 已连通地址缓存

    private func cachedIP(for host: String) -> String? {
        cacheLock.lock()
        defer { cacheLock.unlock() }
        guard let entry = preferred[host],
              Date().timeIntervalSince(entry.at) < 600 else { return nil }
        return entry.ip
    }

    private func storeCachedIP(_ ip: String?, for host: String) {
        cacheLock.lock()
        defer { cacheLock.unlock() }
        if let ip = ip {
            preferred[host] = (ip, Date())
        } else {
            preferred.removeValue(forKey: host)
        }
    }

    // MARK: - TLS

    /// SNI 故意带尾点写成 `linux.do.`。
    ///
    /// 中间设备对握手里的 SNI 做精确字符串匹配，命中就直接回 RST：
    /// 同一个 Cloudflare 边缘 IP，SNI 填 `cloudflare.com` 握手成功，
    /// 填 `linux.do` 立刻被重置——换哪个 IP 都表现为「直连超时」。
    /// 带尾点的写法不在名单里，而 RFC 6125 允许尾点，
    /// Cloudflare 照常返回 linux.do 的证书。
    ///
    /// 证书校验用的是去掉尾点的规范域名，信任链、有效期、SAN 一项不减。
    static func makeTLSOptions(host: String, sni overrideSNI: String? = nil) -> NWProtocolTLS.Options {
        let tlsOptions = NWProtocolTLS.Options()
        let sec = tlsOptions.securityProtocolOptions

        let sni = overrideSNI ?? (host.hasSuffix(".") ? host : host + ".")
        sni.withCString { sec_protocol_options_set_tls_server_name(sec, $0) }
        sec_protocol_options_set_min_tls_protocol_version(sec, .TLSv12)
        sec_protocol_options_set_peer_authentication_required(sec, true)

        let verifyQueue = DispatchQueue(label: "io.linuxdo.tls-verify")
        sec_protocol_options_set_verify_block(sec, { _, secTrust, complete in
            let trust = sec_trust_copy_ref(secTrust).takeRetainedValue()
            let policy = SecPolicyCreateSSL(true, host as CFString)
            SecTrustSetPolicies(trust, policy)
            var error: CFError?
            complete(SecTrustEvaluateWithError(trust, &error))
        }, verifyQueue)

        return tlsOptions
    }

    /// 用当前网络实测一次，逐项报告，方便判断卡在哪一层。
    ///
    /// 对同一批地址分别用「普通 SNI」和「带尾点 SNI」握手：
    /// 前者失败、后者成功说明尾点绕开有效；
    /// 两者都在 4 秒上下超时说明 TCP 就没通，只能换地址或走反代。
    func diagnose() async -> String {
        let host = "linux.do"
        var lines: [String] = []

        var seeds = NetworkSettings.customIPs
        if seeds.isEmpty {
            do {
                seeds = try await DoHResolver.shared.resolve(host)
                lines.append("DoH 解析到 \(seeds.count) 个：\(seeds.prefix(4).joined(separator: ", "))")
            } catch {
                lines.append("DoH 解析失败：\(error.localizedDescription)")
                return lines.joined(separator: "\n")
            }
        } else {
            lines.append("使用手填地址 \(seeds.count) 个：\(seeds.prefix(4).joined(separator: ", "))")
        }

        guard !seeds.isEmpty else {
            return lines.joined(separator: "\n") + "\n没有可用地址"
        }

        lines.append("")
        for ip in Array(seeds.prefix(2)) {
            async let plain = tlsProbe(ip: ip, host: host, sni: host, timeout: 6)
            async let dotted = tlsProbe(ip: ip, host: host, sni: host + ".", timeout: 6)
            let (plainResult, dottedResult) = await (plain, dotted)
            lines.append("\(ip)")
            lines.append("  普通 SNI：\(plainResult)")
            lines.append("  尾点 SNI：\(dottedResult)")
        }

        lines.append("")
        guard let probeURL = URL(string: "https://\(host)/session/csrf.json") else {
            return lines.joined(separator: "\n")
        }
        var request = URLRequest(url: probeURL)
        request.httpMethod = "GET"
        request.setValue(AppConfig.userAgent, forHTTPHeaderField: "User-Agent")

        let started = Date()
        do {
            let (data, response) = try await send(request, timeout: 12)
            let elapsed = String(format: "%.2f", Date().timeIntervalSince(started))
            var tail = "完整请求：HTTP \(response.statusCode)，耗时 \(elapsed)s"
            if AuthResponseDiagnostics.isCloudflareChallenge(response) {
                tail += "（被 Cloudflare 挑战拦截，需要带 cf_clearance 的 Cookie）"
            }
            let body = String(data: data.prefix(160), encoding: .utf8) ?? ""
            if !body.isEmpty {
                tail += "\n" + body.replacingOccurrences(of: "\n", with: " ")
            }
            lines.append(tail)
        } catch {
            let elapsed = String(format: "%.2f", Date().timeIntervalSince(started))
            lines.append("完整请求：失败（\(elapsed)s）\(error.localizedDescription)")
        }

        return lines.joined(separator: "\n")
    }

    /// 只做握手、不发任何数据，报告耗时与结果。
    private func tlsProbe(ip: String, host: String, sni: String, timeout: TimeInterval) async -> String {
        let tlsOptions = Self.makeTLSOptions(host: host, sni: sni)
        let tcpOptions = NWProtocolTCP.Options()
        tcpOptions.connectionTimeout = Int(timeout)
        let parameters = NWParameters(tls: tlsOptions, tcp: tcpOptions)

        guard let nwPort = NWEndpoint.Port(rawValue: 443) else { return "端口错误" }
        let connection = NWConnection(host: NWEndpoint.Host(ip), port: nwPort, using: parameters)
        defer { connection.cancel() }

        let started = Date()
        do {
            try await waitUntilReady(connection, timeout: timeout)
            return String(format: "握手成功 %.2fs", Date().timeIntervalSince(started))
        } catch {
            return String(format: "%.2fs ", Date().timeIntervalSince(started)) + error.localizedDescription
        }
    }
    // MARK: - 单次连接

    private func roundTrip(
        _ request: URLRequest,
        url: URL,
        host: String,
        ip: String,
        port: Int,
        timeout: TimeInterval
    ) async throws -> (Data, HTTPURLResponse) {

        let tlsOptions = Self.makeTLSOptions(host: host)

        let tcpOptions = NWProtocolTCP.Options()
        tcpOptions.connectionTimeout = 8
        tcpOptions.noDelay = true

        let parameters = NWParameters(tls: tlsOptions, tcp: tcpOptions)
        parameters.serviceClass = .responsiveData

        guard let nwPort = NWEndpoint.Port(rawValue: UInt16(port)) else {
            throw TransportError.badURL
        }

        let connection = NWConnection(host: NWEndpoint.Host(ip), port: nwPort, using: parameters)
        defer { connection.cancel() }

        try await waitUntilReady(connection, timeout: min(timeout, 5))
        try await sendAll(connection, data: Self.serialize(request, url: url, host: host))
        let raw = try await readAll(connection, timeout: timeout)
        return try Self.parse(raw, url: url)
    }

    private func waitUntilReady(_ connection: NWConnection, timeout: TimeInterval) async throws {
        // 不依赖 cancel 后一定回调：超时由定时器直接 resume，避免 await 永久挂住。
        let note = WaiterNote()
        try await withCheckedThrowingContinuation { (cont: CheckedContinuation<Void, Error>) in
            let box = ResumeOnce(cont)
            connection.stateUpdateHandler = { state in
                switch state {
                case .ready:
                    box.resume()
                case .failed(let error):
                    box.resume(throwing: TransportError.connect(error.localizedDescription))
                case .waiting(let error):
                    // 路径不可用（无路由 / 被要求走别的接口）时停在这里，记下原因。
                    note.record(error.localizedDescription)
                case .cancelled:
                    box.resume(throwing: TransportError.connect("连接被取消"))
                default:
                    break
                }
            }
            connection.start(queue: self.queue)
            self.queue.asyncAfter(deadline: .now() + timeout) {
                connection.cancel()
                if let reason = note.value {
                    box.resume(throwing: TransportError.connect("等待路径：\(reason)"))
                } else {
                    box.resume(throwing: TransportError.timeout)
                }
            }
        }
    }

    private func sendAll(_ connection: NWConnection, data: Data) async throws {
        try await withCheckedThrowingContinuation { (cont: CheckedContinuation<Void, Error>) in
            connection.send(content: data, completion: .contentProcessed { error in
                if let error = error {
                    cont.resume(throwing: TransportError.connect(error.localizedDescription))
                } else {
                    cont.resume()
                }
            })
        }
    }

    private func readAll(_ connection: NWConnection, timeout: TimeInterval) async throws -> Data {
        let deadline = Date().addingTimeInterval(timeout)
        var buffer = Data()

        while true {
            let remaining = deadline.timeIntervalSinceNow
            guard remaining > 0 else { break }

            let (chunk, isComplete) = try await receiveOnce(connection, timeout: remaining)
            if let chunk = chunk { buffer.append(chunk) }
            if buffer.count > 12 * 1024 * 1024 { break }
            if isComplete { break }
        }

        guard !buffer.isEmpty else { throw TransportError.timeout }
        return buffer
    }

    private func receiveOnce(_ connection: NWConnection, timeout: TimeInterval) async throws -> (Data?, Bool) {
        try await withCheckedThrowingContinuation { (cont: CheckedContinuation<(Data?, Bool), Error>) in
            let box = ResumeResult(cont)
            connection.receive(minimumIncompleteLength: 1, maximumLength: 65_536) {
                data, _, isComplete, error in
                if let error = error {
                    box.fail(TransportError.connect(error.localizedDescription))
                } else {
                    box.ok((data, isComplete))
                }
            }
            self.queue.asyncAfter(deadline: .now() + timeout) {
                connection.cancel()
                box.fail(TransportError.timeout)
            }
        }
    }

    // MARK: - 报文编解码

    static func serialize(_ request: URLRequest, url: URL, host: String) -> Data {
        var headers = request.allHTTPHeaderFields ?? [:]
        headers["Host"] = host
        headers["Connection"] = "close"
        // 不声明压缩，就省掉 gzip/br 解压。
        headers.removeValue(forKey: "Accept-Encoding")

        var head = "\(request.httpMethod ?? "GET") \(pathWithQuery(url)) HTTP/1.1\r\n"
        if let body = request.httpBody {
            headers["Content-Length"] = String(body.count)
        }
        for (key, value) in headers {
            head += "\(key): \(value)\r\n"
        }
        head += "\r\n"

        var data = Data(head.utf8)
        if let body = request.httpBody { data.append(body) }
        return data
    }

    static func pathWithQuery(_ url: URL) -> String {
        guard var components = URLComponents(url: url, resolvingAgainstBaseURL: false) else {
            return "/"
        }
        components.scheme = nil
        components.host = nil
        components.port = nil
        components.user = nil
        components.password = nil

        let path = components.percentEncodedPath
        let query = components.percentEncodedQuery
        let safePath = path.isEmpty ? "/" : path
        if let query = query, !query.isEmpty {
            return "\(safePath)?\(query)"
        }
        return safePath
    }

    static func parse(_ raw: Data, url: URL) throws -> (Data, HTTPURLResponse) {
        guard let separator = raw.range(of: Data("\r\n\r\n".utf8)) else {
            throw TransportError.malformedResponse
        }
        let headerData = raw[raw.startIndex..<separator.lowerBound]
        let bodyData = Data(raw[separator.upperBound...])

        guard let headerText = String(data: headerData, encoding: .utf8) else {
            throw TransportError.malformedResponse
        }
        var lines = headerText.components(separatedBy: "\r\n")
        guard !lines.isEmpty else { throw TransportError.malformedResponse }

        let statusLine = lines.removeFirst()
        let statusParts = statusLine.split(separator: " ", maxSplits: 2)
        guard statusParts.count >= 2, let status = Int(statusParts[1]) else {
            throw TransportError.malformedResponse
        }

        var fields: [String: String] = [:]
        for line in lines {
            guard let colon = line.firstIndex(of: ":") else { continue }
            let key = String(line[line.startIndex..<colon]).trimmingCharacters(in: .whitespaces)
            let value = String(line[line.index(after: colon)...]).trimmingCharacters(in: .whitespaces)
            if !key.isEmpty { fields[key] = value }
        }

        var payload = bodyData
        let transferEncoding = fields.first { $0.key.lowercased() == "transfer-encoding" }?.value.lowercased()
        if let transferEncoding = transferEncoding, transferEncoding.contains("chunked") {
            payload = decodeChunked(bodyData)
        } else if let lengthText = fields.first(where: { $0.key.lowercased() == "content-length" })?.value,
                  let length = Int(lengthText), length <= bodyData.count {
            payload = bodyData.prefix(length)
        }

        guard let response = HTTPURLResponse(
            url: url,
            statusCode: status,
            httpVersion: "HTTP/1.1",
            headerFields: fields
        ) else {
            throw TransportError.malformedResponse
        }
        return (payload, response)
    }

    static func decodeChunked(_ data: Data) -> Data {
        var output = Data()
        var index = data.startIndex
        while index < data.endIndex {
            guard let lineEnd = data[index...].range(of: Data("\r\n".utf8)) else { break }
            let sizeText = String(data: data[index..<lineEnd.lowerBound], encoding: .utf8)?
                .split(separator: ";").first.map(String.init) ?? ""
            guard let size = Int(sizeText.trimmingCharacters(in: .whitespaces), radix: 16), size > 0 else {
                break
            }
            let start = lineEnd.upperBound
            guard let end = data.index(start, offsetBy: size, limitedBy: data.endIndex) else { break }
            output.append(data[start..<end])
            index = end
            if let next = data[index...].range(of: Data("\r\n".utf8)) {
                index = next.upperBound
            } else {
                break
            }
        }
        return output
    }
}

/// 保证 continuation 只被 resume 一次。
private final class ResumeOnce {
    private var continuation: CheckedContinuation<Void, Error>?
    private let lock = NSLock()

    init(_ continuation: CheckedContinuation<Void, Error>) {
        self.continuation = continuation
    }

    func resume() {
        lock.lock()
        let target = continuation
        continuation = nil
        lock.unlock()
        target?.resume()
    }

    func resume(throwing error: Error) {
        lock.lock()
        let target = continuation
        continuation = nil
        lock.unlock()
        target?.resume(throwing: error)
    }
}

/// 保证 `(Data?, Bool)` 的 continuation 只被 resume 一次。
private final class ResumeResult {
    private var continuation: CheckedContinuation<(Data?, Bool), Error>?
    private let lock = NSLock()

    init(_ continuation: CheckedContinuation<(Data?, Bool), Error>) {
        self.continuation = continuation
    }

    func ok(_ value: (Data?, Bool)) {
        take()?.resume(returning: value)
    }

    func fail(_ error: Error) {
        take()?.resume(throwing: error)
    }

    private func take() -> CheckedContinuation<(Data?, Bool), Error>? {
        lock.lock()
        defer { lock.unlock() }
        let target = continuation
        continuation = nil
        return target
    }
}

/// 记录 `NWConnection` 停在 `.waiting` 的原因，供超时报错使用。
private final class WaiterNote {
    private var reason: String?
    private let lock = NSLock()

    func record(_ text: String) {
        lock.lock()
        reason = text
        lock.unlock()
    }

    var value: String? {
        lock.lock()
        defer { lock.unlock() }
        return reason
    }
}
