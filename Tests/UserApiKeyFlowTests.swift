import XCTest
import Security
@testable import LinuxDoClient

final class UserApiKeyFlowTests: XCTestCase {
    func testOriginalDeviceTokenFieldsAreDecoded() throws {
        let data = Data(#"{
          "sessionCookie": "_t=会话值",
          "registrationToken": "注册令牌",
          "username": "user",
          "name": "用户",
          "registrationRequired": false,
          "retryAfter": 7,
          "identityToken": "identity",
          "authorizationCode": "authorization",
          "nonce": "nonce"
        }"#.utf8)
        let response = try JSONDecoder().decode(DeviceTokenResponse.self, from: data)
        XCTAssertEqual(response.sessionCookie, "_t=会话值")
        XCTAssertEqual(response.registrationToken, "注册令牌")
        XCTAssertEqual(response.retryAfter, 7)
        XCTAssertEqual(response.identityToken, "identity")
        XCTAssertEqual(response.authorizationCode, "authorization")
        XCTAssertFalse(response.registrationRequired ?? true)
    }

    func testOriginalDeviceCodeAliasesAreDecoded() throws {
        let data = Data(#"{
          "deviceCode": "device",
          "userCode": "ABCD",
          "verificationURL": "https://example.com/activate",
          "expiresAt": "2099-01-01T00:00:00Z",
          "interval": 4,
          "client_id": "org.linuxdo.community",
          "registration_token": "registration"
        }"#.utf8)
        let response = try JSONDecoder().decode(DeviceCodeResponse.self, from: data)
        XCTAssertEqual(response.deviceCode, "device")
        XCTAssertEqual(response.userCode, "ABCD")
        XCTAssertEqual(response.verificationUri, "https://example.com/activate")
        XCTAssertEqual(response.interval, 4)
        XCTAssertEqual(response.clientId, "org.linuxdo.community")
        XCTAssertEqual(response.registrationToken, "registration")
    }

    func testComputerAuthorizationHasNoRedirect() throws {
        let url = try UserApiKeyAuthorization.makeURL(
            baseURL: XCTUnwrap(URL(string: "https://example.com")),
            applicationName: "测试客户端", publicKeyPEM: "测试公钥",
            nonce: "测试随机值", clientId: "测试设备", scopes: ["read", "session_info"],
            redirect: nil
        )
        let components = try XCTUnwrap(URLComponents(url: url, resolvingAgainstBaseURL: false))
        XCTAssertEqual(components.path, "/user-api-key/new")
        XCTAssertFalse(components.queryItems?.contains { $0.name == "auth_redirect" } == true)
    }

    func testComputerPayloadSurvivesPrivateKeyRestoration() throws {
        let material = try XCTUnwrap(RSAKeyPair.generate())
        let url = try callback(material, object: ["key": "测试密钥", "nonce": "正确随机值"])
        let components = try XCTUnwrap(URLComponents(url: url, resolvingAgainstBaseURL: false))
        let encrypted = try XCTUnwrap(components.queryItems?.first { $0.name == "payload" }?.value)
        var error: Unmanaged<CFError>?
        let exported = try XCTUnwrap(SecKeyCopyExternalRepresentation(material.privateKey, &error)) as Data
        let restored = try XCTUnwrap(RSAKeyPair.restore(privateKeyData: exported))
        XCTAssertEqual(restored.publicKeyPEM, material.publicKeyPEM)

        let json = try JSONSerialization.data(withJSONObject: ["payload": encrypted])
        for input in ["\n" + encrypted + "\n", String(decoding: json, as: UTF8.self)] {
            let payload = try UserApiKeyAuthorization.decodePayload(
                input, expectedNonce: "正确随机值", privateKey: restored.privateKey
            )
            XCTAssertEqual(payload.key, "测试密钥")
        }
        XCTAssertThrowsError(try UserApiKeyAuthorization.decodePayload(
            encrypted, expectedNonce: "另一授权", privateKey: restored.privateKey
        ))
        XCTAssertThrowsError(try UserApiKeyAuthorization.decodePayload(
            "明文密钥", expectedNonce: "正确随机值", privateKey: restored.privateKey
        ))
    }

    func testAuthorizationURLPreservesPublicKeyAndSubpath() throws {
        let publicKey = "-----BEGIN RSA PUBLIC KEY-----\nAB+C/DE==\n-----END RSA PUBLIC KEY-----"
        let url = try UserApiKeyAuthorization.makeURL(
            baseURL: XCTUnwrap(URL(string: "https://example.com/forum/")),
            applicationName: "测试客户端",
            publicKeyPEM: publicKey,
            nonce: "测试随机值",
            clientId: "测试设备",
            scopes: ["read", "session_info"],
            redirect: "discourse://auth_redirect"
        )
        let components = try XCTUnwrap(URLComponents(url: url, resolvingAgainstBaseURL: false))
        let items = try XCTUnwrap(components.queryItems)
        XCTAssertEqual(components.path, "/forum/user-api-key/new")
        XCTAssertEqual(items.first { $0.name == "public_key" }?.value, publicKey)
        XCTAssertEqual(items.first { $0.name == "scopes" }?.value, "read,session_info")
        XCTAssertEqual(items.first { $0.name == "auth_redirect" }?.value, "discourse://auth_redirect")
        XCTAssertFalse(items.contains { $0.name == "payload" })
        XCTAssertTrue(components.percentEncodedQuery?.contains("%2B") == true)
        XCTAssertFalse(components.percentEncodedQuery?.contains("+") == true)
    }

    func testValidEncryptedCallbackDoesNotNeedNonceInURL() throws {
        let material = try XCTUnwrap(RSAKeyPair.generate())
        let url = try callback(material, object: ["key": "测试密钥", "nonce": "正确随机值"])
        let payload = try decode(url, material: material)
        XCTAssertEqual(payload.key, "测试密钥")
        XCTAssertEqual(payload.nonce, "正确随机值")
    }

    func testURLNonceCannotOverrideEncryptedNonce() throws {
        let material = try XCTUnwrap(RSAKeyPair.generate())
        let url = try callback(
            material,
            object: ["key": "测试密钥", "nonce": "其他授权的随机值"],
            extraItems: [URLQueryItem(name: "nonce", value: "正确随机值")]
        )
        XCTAssertThrowsError(try decode(url, material: material))
    }

    func testMissingNonceAndEmptyKeyAreRejected() throws {
        let material = try XCTUnwrap(RSAKeyPair.generate())
        for object in [["key": "测试密钥"], ["key": "", "nonce": "正确随机值"]] {
            let url = try callback(material, object: object)
            XCTAssertThrowsError(try decode(url, material: material))
        }
    }

    func testUnexpectedCallbackAddressIsRejected() throws {
        let material = try XCTUnwrap(RSAKeyPair.generate())
        for redirect in ["other://auth_redirect", "discourse://other", "discourse://auth_redirect/other"] {
            let url = try callback(
                material,
                object: ["key": "测试密钥", "nonce": "正确随机值"],
                redirect: redirect
            )
            XCTAssertThrowsError(try decode(url, material: material))
        }
    }

    func testDuplicatePayloadAndWrongPrivateKeyAreRejected() throws {
        let material = try XCTUnwrap(RSAKeyPair.generate())
        let duplicate = try callback(
            material,
            object: ["key": "测试密钥", "nonce": "正确随机值"],
            extraItems: [URLQueryItem(name: "payload", value: "额外载荷")]
        )
        XCTAssertThrowsError(try decode(duplicate, material: material))
        let valid = try callback(material, object: ["key": "测试密钥", "nonce": "正确随机值"])
        let otherMaterial = try XCTUnwrap(RSAKeyPair.generate())
        XCTAssertThrowsError(try decode(valid, material: otherMaterial))
    }

    private func decode(_ url: URL, material: RSAKeyPair.Material) throws -> UserApiKeyAuthorization.Payload {
        try UserApiKeyAuthorization.decodeCallback(
            url,
            expectedRedirect: "discourse://auth_redirect",
            expectedNonce: "正确随机值",
            privateKey: material.privateKey
        )
    }

    /// 模拟服务器使用客户端公钥加密授权结果，不访问真实站点。
    private func callback(
        _ material: RSAKeyPair.Material,
        object: [String: String],
        redirect: String = "discourse://auth_redirect",
        extraItems: [URLQueryItem] = []
    ) throws -> URL {
        let publicKey = try XCTUnwrap(SecKeyCopyPublicKey(material.privateKey))
        let data = try JSONSerialization.data(withJSONObject: object)
        var error: Unmanaged<CFError>?
        let encrypted = try XCTUnwrap(SecKeyCreateEncryptedData(
            publicKey, .rsaEncryptionPKCS1, data as CFData, &error
        )) as Data
        var components = try XCTUnwrap(URLComponents(string: redirect))
        components.queryItems = [URLQueryItem(name: "payload", value: encrypted.base64EncodedString())] + extraItems
        components.percentEncodedQuery = components.percentEncodedQuery?.replacingOccurrences(of: "+", with: "%2B")
        return try XCTUnwrap(components.url)
    }
}
