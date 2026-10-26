import Foundation
import Security
import UIKit

/// 基于 fluxdo_doh（Rust）的本地代理：DoH 解析 + ECH 加密 ClientHello + MITM。
///
/// 为什么要它：明文 SNI `linux.do` 会被中间设备直接 RST，换哪个 IP 都没用。
/// ECH 把 SNI 加密后带走，Cloudflare 照常路由，阻断点看不到域名。
/// MITM 则让上层的 URLSession / WKWebView 以为在跟真站点通信——
/// 它们看到的是本机 CA 签发的证书，上游由 Rust 用 ECH 出去。
final class DohProxyService {

    static let shared = DohProxyService()

    struct RootCA {
        let certPEM: String
        let keyPEM: String
    }

    /// 代理默认走的 DoH 端点：原版 app 自建的中转，实测返回真实 Cloudflare 地址。
    private let dohEndpoint = "https://ios-app.ddd.oaifree.com/query-dns"
    private let dohBootstrap = ["172.67.210.33", "104.21.16.56", "104.20.16.234"]

    private(set) var runningPort: Int?
    private var cachedCA: RootCA?

    var isRunning: Bool { doh_proxy_is_running() != 0 }

    // MARK: - CA

    /// 拿代理实际使用的根证书。
    ///
    /// 代理的 MITM 叶证书一律由**编译进静态库的内置 CA** 签发
    /// （fluxdo_doh 的 build.rs 在构建时生成 certs/ca.crt），
    /// 配置里的 ca_cert_pem / ca_key_pem 那个库并没有读取。
    /// 所以这里必须取内置的那张，否则装上的根证书和叶证书对不上，
    /// URLSession 会直接报「SSL error / 无法建立安全连接」。
    func rootCA() -> RootCA? {
        if let ca = cachedCA { return ca }

        guard let raw = doh_proxy_get_embedded_ca_pem() else { return nil }
        defer { doh_proxy_free_string(raw) }
        guard let pem = String(validatingUTF8: raw),
              pem.contains("BEGIN CERTIFICATE") else { return nil }

        let ca = RootCA(certPEM: pem, keyPEM: "")
        cachedCA = ca
        return ca
    }

    /// 生成可直接安装的 .mobileconfig（含根证书本体）。
    func makeProfile(ca: RootCA) -> URL? {
        guard let der = Self.der(fromPEM: ca.certPEM) else { return nil }

        let payload: [String: Any] = [
            "PayloadCertificateFileName": "linuxdo-ca.cer",
            "PayloadContent": der,
            "PayloadDescription": "LINUX DO 客户端本地代理根证书，仅用于解密本机发往 linux.do 的流量",
            "PayloadDisplayName": "LINUX DO CA",
            "PayloadIdentifier": "io.linuxdo.client.ca",
            "PayloadType": "com.apple.security.root",
            "PayloadUUID": UUID().uuidString,
            "PayloadVersion": 1
        ]
        let profile: [String: Any] = [
            "PayloadContent": [payload],
            "PayloadDisplayName": "LINUX DO 根证书",
            "PayloadIdentifier": "io.linuxdo.client.profile",
            "PayloadOrganization": "LinuxDoClient",
            "PayloadRemovalDisallowed": false,
            "PayloadType": "Configuration",
            "PayloadUUID": UUID().uuidString,
            "PayloadVersion": 1
        ]

        guard let data = try? PropertyListSerialization.data(
            fromPropertyList: profile, format: .xml, options: 0
        ) else { return nil }

        let url = FileManager.default.temporaryDirectory
            .appendingPathComponent("linuxdo-ca.mobileconfig")
        do {
            try data.write(to: url)
            return url
        } catch {
            return nil
        }
    }

    /// 生成系统级加密 DNS（DoH）描述文件。
    ///
    /// 装一次对整个系统生效，WiFi 与蜂窝都覆盖，WKWebView 也跟着走加密解析。
    /// 这是 WebView 加载 linux.do 超时的正解：它用系统明文 DNS，
    /// 被污染时解析到假 IP 就卡死；而 URLSession 走 App 内 DoH，所以能到 Cloudflare。
    func makeDNSProfile() -> URL? {
        let payload: [String: Any] = [
            "DNSSettings": [
                "DNSProtocol": "HTTPS",
                "ServerURL": "https://doh.pub/dns-query"
            ],
            "PayloadDescription": "用 DoH 加密解析域名，避免被污染",
            "PayloadDisplayName": "加密 DNS",
            "PayloadIdentifier": "io.linuxdo.client.doh",
            "PayloadType": "com.apple.dnsSettings.managed",
            "PayloadUUID": UUID().uuidString,
            "PayloadVersion": 1
        ]
        let profile: [String: Any] = [
            "PayloadContent": [payload],
            "PayloadDisplayName": "LINUX DO 加密 DNS",
            "PayloadDescription": "安装后系统 DNS 走 DoH，WiFi 与蜂窝都生效。",
            "PayloadIdentifier": "io.linuxdo.client.doh.profile",
            "PayloadOrganization": "LinuxDoClient",
            "PayloadRemovalDisallowed": false,
            "PayloadType": "Configuration",
            "PayloadUUID": UUID().uuidString,
            "PayloadVersion": 1
        ]
        guard let data = try? PropertyListSerialization.data(
            fromPropertyList: profile, format: .xml, options: 0
        ) else { return nil }

        let url = FileManager.default.temporaryDirectory
            .appendingPathComponent("linuxdo-doh.mobileconfig")
        do {
            try data.write(to: url)
            return url
        } catch {
            return nil
        }
    }

    // MARK: - 启停

    /// 启动代理。返回监听端口，失败返回 nil。
    @discardableResult
    func start(host: String) -> Int? {
        if isRunning, let port = runningPort { return port }
        guard let ca = rootCA() else { return nil }

        // 端口固定在 18888：Wi-Fi 代理只填一次，之后每次开关都不用再改。
        // 万一被占用，退回自动分配。
        doh_proxy_init_logging()
        for candidate in [18888, 0] {
            let config: [String: Any] = [
                "bind_addr": "127.0.0.1",
                "bind_port": candidate,
                "enable_doh": true,
                "doh_server": dohEndpoint,
                "doh_bootstrap_ips": dohBootstrap,
                "prefer_ipv6": false,
                "timeout_secs": 8,
                "mitm_connect": true,
                "mitm_hosts": [host],
                "h2_mitm": false
            ]
            guard let data = try? JSONSerialization.data(withJSONObject: config),
                  let json = String(data: data, encoding: .utf8) else { continue }
            let port = json.withCString { doh_proxy_start_with_config_json($0) }
            if port > 0 {
                runningPort = Int(port)
                return runningPort
            }
        }
        return nil
    }

    func stop() {
        doh_proxy_stop()
        runningPort = nil
    }

    // MARK: - 工具

    private static func der(fromPEM pem: String) -> Data? {
        let lines = pem.components(separatedBy: .newlines)
            .filter { !$0.hasPrefix("-----") && !$0.isEmpty }
        return Data(base64Encoded: lines.joined())
    }
}

/// 极简 Keychain 读写，只用来保存本地代理 CA。
enum Keychain {

    private static let service = "io.linuxdo.doh-proxy"

    static func set(_ value: String, for key: String) {
        guard let data = value.data(using: .utf8) else { return }
        let query: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: service,
            kSecAttrAccount as String: key
        ]
        SecItemDelete(query as CFDictionary)
        var attributes = query
        attributes[kSecValueData as String] = data
        attributes[kSecAttrAccessible as String] = kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly
        SecItemAdd(attributes as CFDictionary, nil)
    }

    static func get(_ key: String) -> String? {
        let query: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: service,
            kSecAttrAccount as String: key,
            kSecReturnData as String: true,
            kSecMatchLimit as String: kSecMatchLimitOne
        ]
        var item: CFTypeRef?
        guard SecItemCopyMatching(query as CFDictionary, &item) == errSecSuccess,
              let data = item as? Data else { return nil }
        return String(data: data, encoding: .utf8)
    }
}
