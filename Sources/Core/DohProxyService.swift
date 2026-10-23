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

    /// 取出或生成一份本机专属 CA。证书要装进系统信任，私钥只留在 Keychain。
    func rootCA() -> RootCA? {
        if let ca = cachedCA { return ca }
        if let cert = Keychain.get("doh-ca-cert"),
           let key = Keychain.get("doh-ca-key"),
           !cert.isEmpty, !key.isEmpty {
            let ca = RootCA(certPEM: cert, keyPEM: key)
            cachedCA = ca
            return ca
        }

        guard let raw = doh_proxy_generate_ca() else { return nil }
        defer { doh_proxy_free_string(raw) }
        guard let text = String(validatingUTF8: raw),
              let data = text.data(using: .utf8),
              let object = try? JSONSerialization.jsonObject(with: data) as? [String: Any],
              let cert = object["cert_pem"] as? String,
              let key = object["key_pem"] as? String else {
            return nil
        }

        Keychain.set(cert, for: "doh-ca-cert")
        Keychain.set(key, for: "doh-ca-key")
        let ca = RootCA(certPEM: cert, keyPEM: key)
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

    // MARK: - 启停

    /// 启动代理。返回监听端口，失败返回 nil。
    @discardableResult
    func start(host: String) -> Int? {
        if isRunning, let port = runningPort { return port }
        guard let ca = rootCA() else { return nil }

        let config: [String: Any] = [
            "bind_addr": "127.0.0.1",
            "bind_port": 0,
            "enable_doh": true,
            "doh_server": dohEndpoint,
            "doh_bootstrap_ips": dohBootstrap,
            "prefer_ipv6": false,
            "timeout_secs": 8,
            "mitm_connect": true,
            "mitm_hosts": [host],
            "h2_mitm": true,
            "ca_cert_pem": ca.certPEM,
            "ca_key_pem": ca.keyPEM
        ]

        guard let data = try? JSONSerialization.data(withJSONObject: config),
              let json = String(data: data, encoding: .utf8) else {
            return nil
        }

        doh_proxy_init_logging()
        let port = json.withCString { doh_proxy_start_with_config_json($0) }
        guard port > 0 else { return nil }
        runningPort = Int(port)
        return runningPort
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
