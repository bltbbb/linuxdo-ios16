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

    func send(_ request: URLRequest, timeout: TimeInterval = 20) async throws -> (Data, HTTPURLResponse) {
        guard let url = request.url, let host = url.host else {
            throw TransportError.badURL
        }
        let port = url.port ?? 443
        let ips = try await DoHResolver.shared.resolve(host)

        var lastError: Error?
        for ip in ips {
            do {
                return try await roundTrip(
                    request, url: url, host: host, ip: ip, port: port, timeout: timeout
                )
            } catch {
                lastError = error
            }
        }
        throw lastError ?? TransportError.connect("解析到的 IP 全部不可用")
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

        let tlsOptions = NWProtocolTLS.Options()
        sec_protocol_options_set_tls_server_name(tlsOptions.securityProtocolOptions, host)
        sec_protocol_options_set_min_tls_protocol_version(
            tlsOptions.securityProtocolOptions, .TLSv12
        )

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

        try await waitUntilReady(connection, timeout: min(timeout, 10))
        try await sendAll(connection, data: Self.serialize(request, url: url, host: host))
        let raw = try await readAll(connection, timeout: timeout)
        return try Self.parse(raw, url: url)
    }

    private func waitUntilReady(_ connection: NWConnection, timeout: TimeInterval) async throws {
        // 不依赖 cancel 后一定回调：超时由定时器直接 resume，避免 await 永久挂住。
        try await withCheckedThrowingContinuation { (cont: CheckedContinuation<Void, Error>) in
            let box = ResumeOnce(cont)
            connection.stateUpdateHandler = { state in
                switch state {
                case .ready:
                    box.resume()
                case .failed(let error):
                    box.resume(throwing: TransportError.connect(error.localizedDescription))
                case .cancelled:
                    box.resume(throwing: TransportError.connect("连接被取消"))
                default:
                    break
                }
            }
            connection.start(queue: self.queue)
            self.queue.asyncAfter(deadline: .now() + timeout) {
                connection.cancel()
                box.resume(throwing: TransportError.timeout)
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
