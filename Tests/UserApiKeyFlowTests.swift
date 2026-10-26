import XCTest
import Security
@testable import LinuxDoClient

final class UserApiKeyFlowTests: XCTestCase {
    // MARK: - 设备授权协议

    /// 站点真实返回形状（取自 POST /user-api-key/device.json）。
    func testDeviceCodeResponseDecodesUpstreamShape() throws {
        let data = Data(#"""
        {
          "device_code": "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
          "user_code": "V3X5-NJHL",
          "verification_uri": "https://linux.do/user-api-key/activate",
          "verification_uri_with_request": "https://linux.do/user-api-key/activate?request=tok",
          "expires_in": 600,
          "interval": 5
        }
        """#.utf8)
        let response = try JSONDecoder().decode(DeviceCodeResponse.self, from: data)
        XCTAssertEqual(response.userCode, "V3X5-NJHL")
        XCTAssertEqual(response.expiresIn, 600)
        XCTAssertEqual(response.interval, 5)
        XCTAssertTrue(response.isUsable)
        XCTAssertEqual(
            response.activationURL?.absoluteString,
            "https://linux.do/user-api-key/activate?request=tok"
        )
    }

    /// 缺 verification_uri_with_request 时退回 verification_uri，其余字段走默认值。
    func testActivationURLFallsBackToBareVerificationURI() throws {
        let data = Data(#"""
        {
          "device_code": "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
          "user_code": "V3X5-NJHL",
          "verification_uri": "https://linux.do/user-api-key/activate"
        }
        """#.utf8)
        let response = try JSONDecoder().decode(DeviceCodeResponse.self, from: data)
        XCTAssertNil(response.verificationUriWithRequest)
        XCTAssertEqual(
            response.activationURL?.absoluteString,
            "https://linux.do/user-api-key/activate"
        )
        XCTAssertEqual(response.expiresIn, 600)
        XCTAssertEqual(response.interval, 5)
    }

    /// device_code 必须是 64 位十六进制，形状不对不应拿去做轮询。
    func testShortDeviceCodeIsNotUsable() throws {
        let data = Data(#"""
        {"device_code": "short", "user_code": "V3X5-NJHL"}
        """#.utf8)
        let response = try JSONDecoder().decode(DeviceCodeResponse.self, from: data)
        XCTAssertFalse(response.isUsable)
    }

    /// 轮询只有四种状态，且只有 authorized 带 payload。
    func testPollResponseDecodesAllStatuses() throws {
        let pending = try JSONDecoder().decode(
            DevicePollResponse.self,
            from: Data(#"{"status":"authorization_pending"}"#.utf8)
        )
        XCTAssertEqual(pending.status, .authorizationPending)
        XCTAssertTrue(pending.isPending)
        XCTAssertNil(pending.payload)

        let denied = try JSONDecoder().decode(
            DevicePollResponse.self,
            from: Data(#"{"status":"access_denied"}"#.utf8)
        )
        XCTAssertEqual(denied.status, .accessDenied)

        let expired = try JSONDecoder().decode(
            DevicePollResponse.self,
            from: Data(#"{"status":"expired_token"}"#.utf8)
        )
        XCTAssertEqual(expired.status, .expiredToken)

        let authorized = try JSONDecoder().decode(
            DevicePollResponse.self,
            from: Data(#"{"status":"authorized","payload":"cGF5bG9hZA=="}"#.utf8)
        )
        XCTAssertEqual(authorized.status, .authorized)
        XCTAssertFalse(authorized.isPending)
        XCTAssertEqual(authorized.payload, "cGF5bG9hZA==")
    }

    /// 未知状态必须报错，不能静默当成成功。
    func testUnknownPollStatusThrows() {
        XCTAssertThrowsError(try JSONDecoder().decode(
            DevicePollResponse.self,
            from: Data(#"{"status":"something_new"}"#.utf8)
        ))
    }

    /// scope 必须是最小集：多要一个站点不认的 scope 会让整个请求 403。
    func testDeviceAuthScopesStayMinimal() {
        // 只能申请站点放行的两项。
        // 实测加 read 会让创码请求直接 403 invalid_access，
        // 因此这把 key 读不了帖子内容，登录态要靠浏览器会话 cookie。
        XCTAssertEqual(DeviceAuthConfig.scopes, ["notifications", "session_info"])
        XCTAssertFalse(DeviceAuthConfig.scopes.contains("read"))
        XCTAssertFalse(DeviceAuthConfig.scopes.contains("write"))
    }

    /// 授权后拿到的 payload 必须能用同一把私钥解开。
    func testAuthorizedPayloadDecryptsWithDevicePrivateKey() throws {
        let material = try XCTUnwrap(RSAKeyPair.generate())
        let encrypted = try encrypt(material, object: ["key": "测试密钥", "nonce": "正确随机值"])
        let poll = try JSONDecoder().decode(
            DevicePollResponse.self,
            from: try JSONSerialization.data(withJSONObject: [
                "status": "authorized",
                "payload": encrypted
            ])
        )
        let payload = try UserApiKeyAuthorization.decodePayload(
            try XCTUnwrap(poll.payload),
            expectedNonce: "正确随机值",
            privateKey: material.privateKey
        )
        XCTAssertEqual(payload.key, "测试密钥")
        XCTAssertThrowsError(try UserApiKeyAuthorization.decodePayload(
            encrypted,
            expectedNonce: "另一授权",
            privateKey: material.privateKey
        ))
    }

    /// 用公钥加密 payload，模拟站点加密授权结果。
    private func encrypt(
        _ material: RSAKeyPair.Material,
        object: [String: String]
    ) throws -> String {
        let publicKey = try XCTUnwrap(SecKeyCopyPublicKey(material.privateKey))
        let data = try JSONSerialization.data(withJSONObject: object)
        var error: Unmanaged<CFError>?
        let encrypted = try XCTUnwrap(
            SecKeyCreateEncryptedData(publicKey, .rsaEncryptionPKCS1, data as CFData, &error)
        ) as Data
        return encrypted.base64EncodedString()
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
