import XCTest
@testable import LinuxDoClient

final class AuthResponseDiagnosticsTests: XCTestCase {
    func testDiscourseForbiddenIsNotAutomaticallyCloudflare() throws {
        let url = try XCTUnwrap(URL(string: "https://example.com/session"))
        var request = URLRequest(url: url)
        request.setValue("不应出现在日志的CSRF", forHTTPHeaderField: "X-CSRF-Token")
        request.setValue("不应出现在日志的密钥", forHTTPHeaderField: "User-Api-Key")
        request.setValue("https://example.com", forHTTPHeaderField: "Origin")
        let response = try XCTUnwrap(HTTPURLResponse(
            url: url, statusCode: 403, httpVersion: nil,
            headerFields: ["Content-Type": "application/json", "Server": "cloudflare"]
        ))
        let data = Data(#"{"error_type":"invalid_access","errors":["禁止访问"],"csrf":"不应出现在日志的CSRF","key":"不应出现在日志的密钥"}"#.utf8)
        let note = AuthResponseDiagnostics.summary(
            request: request, response: response, data: data, cookieNames: ["_forum_session"]
        )
        XCTAssertFalse(AuthResponseDiagnostics.isCloudflareChallenge(response))
        XCTAssertTrue(note.contains("错误类型=invalid_access"))
        XCTAssertTrue(note.contains("CSRF头=有"))
        XCTAssertTrue(note.contains("_forum_session"))
        XCTAssertFalse(note.contains("不应出现在日志"))
    }

    func testChallengeHeaderAndCSRFMarkerAreRecognized() throws {
        let url = try XCTUnwrap(URL(string: "https://example.com/session"))
        let challenge = try XCTUnwrap(HTTPURLResponse(
            url: url, statusCode: 403, httpVersion: nil,
            headerFields: ["cf-mitigated": "challenge", "Content-Type": "text/html"]
        ))
        XCTAssertTrue(AuthResponseDiagnostics.isCloudflareChallenge(challenge))
        let response = try XCTUnwrap(HTTPURLResponse(url: url, statusCode: 403, httpVersion: nil, headerFields: nil))
        let note = AuthResponseDiagnostics.summary(
            request: URLRequest(url: url), response: response,
            data: Data(#"["BAD CSRF"]"#.utf8), cookieNames: []
        )
        XCTAssertTrue(note.contains("CSRF校验失败"))
        XCTAssertFalse(AuthResponseDiagnostics.isCloudflareChallenge(response))
    }
}
