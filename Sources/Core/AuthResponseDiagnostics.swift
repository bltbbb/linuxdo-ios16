import Foundation

/// 认证诊断只记录协议特征，不记录响应正文或任何凭据值。
enum AuthResponseDiagnostics {
    static func isAuthenticationPath(_ path: String) -> Bool {
        path == "/session" || path.hasPrefix("/session/")
            || path.hasPrefix("/user-api-key") || path.hasPrefix("/login/")
    }

    static func isCloudflareChallenge(_ response: HTTPURLResponse) -> Bool {
        response.value(forHTTPHeaderField: "cf-mitigated")?.lowercased() == "challenge"
    }

    /// WebView 路径拿不到响应头，只能靠正文判断挑战页。
    static func isCloudflareChallenge(_ response: HTTPURLResponse, body: Data) -> Bool {
        if isCloudflareChallenge(response) { return true }
        guard response.statusCode == 403 || response.statusCode == 503 else { return false }
        let head = String(data: body.prefix(4000), encoding: .utf8)?.lowercased() ?? ""
        return head.contains("challenge-platform")
            || head.contains("just a moment")
            || head.contains("cf-chl")
    }

    static func summary(
        request: URLRequest,
        response: HTTPURLResponse,
        data: Data,
        cookieNames: [String]
    ) -> String {
        let object = (try? JSONSerialization.jsonObject(with: data)) as? [String: Any]
        let text = String(data: data.prefix(512), encoding: .utf8) ?? ""
        var fields = [
            "响应类型=\(response.mimeType ?? "未知")",
            "CF挑战=\(isCloudflareChallenge(response) ? "是" : "否")",
            "CSRF头=\(request.value(forHTTPHeaderField: "X-CSRF-Token") == nil ? "无" : "有")",
            "来源头=\(request.value(forHTTPHeaderField: "Origin") == nil ? "无" : "有")",
            "Cookie名=\(cookieNames.sorted().joined(separator: ","))"
        ]
        if let type = object?["error_type"] as? String,
           type.range(of: "^[a-zA-Z0-9_-]{1,64}$", options: .regularExpression) != nil {
            fields.append("错误类型=\(type)")
        }
        if text.uppercased().contains("BAD CSRF") {
            fields.append("CSRF校验失败")
        }
        if object?["error"] != nil || object?["errors"] != nil {
            fields.append("含站点错误信息")
        }
        return fields.joined(separator: "；")
    }
}
