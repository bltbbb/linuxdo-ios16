import Foundation
import Security

/// 用 CFNetwork 的 socket stream 建连，替代 `NWConnection`。
///
/// 起因：在部分网络环境下，`NWConnection` 对任何目标都会停在
/// `.waiting(.dns(0))` 直到超时——国内 IP、Cloudflare IP 都一样，
/// 而同一进程里 URLSession（同样走 CFNetwork）却能正常出网。
/// 所以这里改走 CFNetwork 的老栈，绕开 Network.framework 的路径判定。
///
/// 连接目标是**指定 IP**，SNI 仍写域名（带尾点，避开对 `linux.do` 的精确匹配），
/// 证书链在这之上手动校验，按去掉尾点的规范域名比对，安全性不减。
enum StreamTransport {

    enum StreamError: LocalizedError {
        case create
        case open(String)
        case tls(String)
        case timeout
        case io(String)

        var errorDescription: String? {
            switch self {
            case .create: return "stream 创建失败"
            case .open(let detail): return "建连失败：\(detail)"
            case .tls(let detail): return "证书校验失败：\(detail)"
            case .timeout: return "stream 超时"
            case .io(let detail): return "读写失败：\(detail)"
            }
        }
    }

    static func send(
        _ request: URLRequest,
        url: URL,
        host: String,
        ip: String,
        port: Int,
        timeout: TimeInterval
    ) async throws -> (Data, HTTPURLResponse) {
        try await withCheckedThrowingContinuation { continuation in
            DispatchQueue.global(qos: .userInitiated).async {
                do {
                    let result = try perform(
                        request, url: url, host: host, ip: ip, port: port, timeout: timeout
                    )
                    continuation.resume(returning: result)
                } catch {
                    continuation.resume(throwing: error)
                }
            }
        }
    }

    // MARK: - 同步实现（跑在后台队列）

    private static func perform(
        _ request: URLRequest,
        url: URL,
        host: String,
        ip: String,
        port: Int,
        timeout: TimeInterval
    ) throws -> (Data, HTTPURLResponse) {

        var readRef: Unmanaged<CFReadStream>?
        var writeRef: Unmanaged<CFWriteStream>?
        CFStreamCreatePairWithSocketToHost(
            kCFAllocatorDefault, ip as CFString, UInt32(port), &readRef, &writeRef
        )
        guard let rawRead = readRef?.takeRetainedValue(),
              let rawWrite = writeRef?.takeRetainedValue() else {
            throw StreamError.create
        }

        let input = rawRead as InputStream
        let output = rawWrite as OutputStream
        defer {
            input.close()
            output.close()
        }

        let settings: [String: Any] = [
            kCFStreamSSLLevel as String: kCFStreamSocketSecurityLevelNegotiatedSSL as String,
            kCFStreamSSLPeerName as String: host + ".",
            kCFStreamSSLValidatesCertificateChain as String: false
        ]
        CFReadStreamSetProperty(
            rawRead, kCFStreamPropertySSLSettings, settings as CFDictionary
        )

        let deadline = Date().addingTimeInterval(timeout)

        input.open()
        output.open()
        try waitUntilOpen(input, output, deadline: deadline)
        try verifyPeer(rawRead, host: host)

        try write(DirectTransport.serialize(request, url: url, host: host), to: output, deadline: deadline)
        let raw = try readAll(from: input, deadline: deadline)
        return try DirectTransport.parse(raw, url: url)
    }

    private static func waitUntilOpen(
        _ input: InputStream,
        _ output: OutputStream,
        deadline: Date
    ) throws {
        while true {
            let inStatus = input.streamStatus
            let outStatus = output.streamStatus
            if inStatus == .open, outStatus == .open { return }
            if inStatus == .error { throw StreamError.open(reason(input)) }
            if outStatus == .error { throw StreamError.open(reason(output)) }
            if inStatus == .closed { throw StreamError.open("连接被关闭") }
            if outStatus == .closed { throw StreamError.open("连接被关闭") }
            if Date() >= deadline { throw StreamError.timeout }
            Thread.sleep(forTimeInterval: 0.02)
        }
    }

    private static func reason(_ stream: Stream) -> String {
        guard let error = stream.streamError else { return "未知错误" }
        return error.localizedDescription
    }

    /// 手动校验证书链：SNI 带尾点，但比对用的是去掉尾点的规范域名。
    private static func verifyPeer(_ stream: CFReadStream, host: String) throws {
        guard let raw = CFReadStreamCopyProperty(stream, kCFStreamPropertySSLPeerCertificates),
              let certificates = raw as? [SecCertificate],
              !certificates.isEmpty else {
            throw StreamError.tls("服务器没有提供证书")
        }

        let policy = SecPolicyCreateSSL(true, host as CFString)
        var trust: SecTrust?
        let status = SecTrustCreateWithCertificates(certificates as CFArray, policy, &trust)
        guard status == errSecSuccess, let created = trust else {
            throw StreamError.tls("无法建立信任链（\(status)）")
        }

        var error: CFError?
        guard SecTrustEvaluateWithError(created, &error) else {
            let detail = (error as Error?)?.localizedDescription ?? "校验未通过"
            throw StreamError.tls(detail)
        }
    }

    private static func write(_ data: Data, to output: OutputStream, deadline: Date) throws {
        var offset = 0
        let bytes = [UInt8](data)
        while offset < bytes.count {
            if output.streamStatus == .error { throw StreamError.io(reason(output)) }
            if output.hasSpaceAvailable {
                let written = bytes.withUnsafeBufferPointer { buffer -> Int in
                    guard let base = buffer.baseAddress else { return -1 }
                    return output.write(base + offset, maxLength: bytes.count - offset)
                }
                if written < 0 { throw StreamError.io(reason(output)) }
                offset += written
            } else {
                if Date() >= deadline { throw StreamError.timeout }
                Thread.sleep(forTimeInterval: 0.01)
            }
        }
    }

    private static func readAll(from input: InputStream, deadline: Date) throws -> Data {
        var buffer = Data()
        var chunk = [UInt8](repeating: 0, count: 16 * 1024)

        while true {
            if input.hasBytesAvailable {
                let count = input.read(&chunk, maxLength: chunk.count)
                if count > 0 {
                    buffer.append(contentsOf: chunk[0..<count])
                    if isComplete(buffer) { break }
                    if buffer.count > 12 * 1024 * 1024 { break }
                    continue
                }
                if count == 0 { break }
                throw StreamError.io(reason(input))
            }

            let status = input.streamStatus
            if status == .atEnd || status == .closed { break }
            if status == .error { throw StreamError.io(reason(input)) }
            if Date() >= deadline {
                if buffer.isEmpty { throw StreamError.timeout }
                break
            }
            Thread.sleep(forTimeInterval: 0.01)
        }

        if buffer.isEmpty { throw StreamError.io("服务器没有返回数据") }
        return buffer
    }

    /// 只做一次便宜的判断：已经有完整头部，且 body 满足 Content-Length 或分块结束标记。
    private static func isComplete(_ data: Data) -> Bool {
        guard let separator = data.range(of: Data("\r\n\r\n".utf8)) else { return false }
        let head = data[data.startIndex..<separator.lowerBound]
        let body = data[separator.upperBound...]

        guard let text = String(data: head, encoding: .utf8) else { return false }
        for line in text.components(separatedBy: "\r\n") {
            let lower = line.lowercased()
            if lower.hasPrefix("content-length:") {
                let value = line.dropFirst("content-length:".count)
                    .trimmingCharacters(in: .whitespaces)
                if let length = Int(value) { return body.count >= length }
            }
            if lower.hasPrefix("transfer-encoding:"), lower.contains("chunked") {
                return data.suffix(5) == Data("0\r\n\r\n".utf8)
            }
        }
        // 没有长度信息：等到流关闭为止。
        return false
    }
}
