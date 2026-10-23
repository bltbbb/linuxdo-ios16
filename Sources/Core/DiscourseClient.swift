import Foundation

enum DiscourseError: LocalizedError {
    case badURL
    case http(Int, String)
    case decoding(String)
    case transport(String)
    case unauthorized
    case cloudflare

    var errorDescription: String? {
        switch self {
        case .badURL:
            return "请求地址无效"
        case .http(let code, let msg):
            return msg.isEmpty ? "服务器返回 HTTP \(code)" : "\(msg)（HTTP \(code)）"
        case .decoding(let msg):
            return "数据解析失败：\(msg)"
        case .transport(let msg):
            return "网络错误：\(msg)"
        case .unauthorized:
            return "未登录或会话已过期"
        case .cloudflare:
            return "被 Cloudflare 拦截，请稍后重试"
        }
    }
}

/// 标准 Discourse REST 客户端。仅用 URLSession，无第三方依赖。
final class DiscourseClient {

    static let shared = DiscourseClient()

    let baseURL: URL
    private let session: URLSession
    private let decoder = JSONDecoder()
    private let csrfCache = CSRFCache()
    private let apiKeyBox = APIKeyBox()

    /// 登录后设置 user API key；之后所有请求自动带 `User-Api-Key` 头。
    func setApiKey(_ key: String?) {
        apiKeyBox.set(key)
    }

    init(baseURL: URL = AppConfig.baseURL) {
        self.baseURL = baseURL
        let cfg = URLSessionConfiguration.default
        cfg.httpCookieStorage = HTTPCookieStorage.shared
        cfg.httpShouldSetCookies = true
        cfg.httpCookieAcceptPolicy = .always
        cfg.timeoutIntervalForRequest = 30
        cfg.timeoutIntervalForResource = 60
        cfg.requestCachePolicy = .reloadIgnoringLocalCacheData
        cfg.urlCache = nil
        cfg.httpAdditionalHeaders = ["User-Agent": AppConfig.userAgent]
        self.session = URLSession(configuration: cfg)
    }

    // MARK: - URL / headers

    private func makeURL(_ path: String, query: [URLQueryItem] = []) -> URL? {
        guard var comps = URLComponents(url: baseURL, resolvingAgainstBaseURL: false) else { return nil }
        comps.path = path.hasPrefix("/") ? path : "/" + path
        if !query.isEmpty { comps.queryItems = query }
        return comps.url
    }

    private func decorate(_ req: inout URLRequest) {
        req.setValue(AppConfig.userAgent, forHTTPHeaderField: "User-Agent")
        req.setValue("application/json", forHTTPHeaderField: "Accept")
        req.setValue("XMLHttpRequest", forHTTPHeaderField: "X-Requested-With")
        if let key = apiKeyBox.get(), !key.isEmpty {
            req.setValue(key, forHTTPHeaderField: "User-Api-Key")
        }
        if let method = req.httpMethod, method != "GET", method != "HEAD" {
            var origin = URLComponents(url: baseURL, resolvingAgainstBaseURL: false)
            origin?.path = ""
            origin?.query = nil
            origin?.fragment = nil
            req.setValue(origin?.string, forHTTPHeaderField: "Origin")
            req.setValue(makeURL("/login")?.absoluteString, forHTTPHeaderField: "Referer")
        }
    }

    // MARK: - Cookie（由同一个 URLSession 自动接收和发送）

    private func currentCookies() -> [HTTPCookie] {
        HTTPCookieStorage.shared.cookies(for: baseURL) ?? []
    }

    /// 诊断用：列出当前 cookie 名。
    func cookieDiagnostics() -> String {
        let names = currentCookies().map { $0.name }.sorted()
        return names.isEmpty ? "无" : names.joined(separator: ",")
    }

    func resetCookies() {
        guard let host = baseURL.host?.lowercased() else { return }
        for cookie in HTTPCookieStorage.shared.cookies ?? [] {
            let domain = cookie.domain.trimmingCharacters(in: CharacterSet(charactersIn: ".")).lowercased()
            if host == domain || host.hasSuffix("." + domain) {
                HTTPCookieStorage.shared.deleteCookie(cookie)
            }
        }
    }

    private static func formEncode(_ fields: [String: String]) -> String {
        var allowed = CharacterSet.alphanumerics
        allowed.insert(charactersIn: "-._~")
        return fields.map { key, value in
            let k = key.addingPercentEncoding(withAllowedCharacters: allowed) ?? key
            let v = value.addingPercentEncoding(withAllowedCharacters: allowed) ?? value
            return "\(k)=\(v)"
        }.joined(separator: "&")
    }

    private static func message(from data: Data) -> String {
        if let obj = try? JSONSerialization.jsonObject(with: data) as? [String: Any] {
            if let errors = obj["errors"] as? [String], let first = errors.first { return first }
            if let error = obj["error"] as? String { return error }
        }
        return String(data: data.prefix(200), encoding: .utf8)?.trimmingCharacters(in: .whitespacesAndNewlines) ?? ""
    }

    // MARK: - transport

    private func send(_ req: URLRequest) async throws -> (Data, HTTPURLResponse) {
        let cookieNames = HTTPCookieStorage.shared.cookies(for: req.url ?? baseURL)?.map { $0.name } ?? []
        let result: (Data, URLResponse)
        do {
            result = try await session.data(for: req)
        } catch {
            await RequestLog.shared.record(
                method: req.httpMethod ?? "?",
                url: req.url?.path ?? "?",
                status: -1,
                note: error.localizedDescription
            )
            throw DiscourseError.transport(error.localizedDescription)
        }
        let data = result.0
        guard let http = result.1 as? HTTPURLResponse else {
            throw DiscourseError.transport("无 HTTP 响应")
        }
        await RequestLog.shared.record(
            method: req.httpMethod ?? "?",
            url: req.url?.path ?? "?",
            status: http.statusCode,
            note: AuthResponseDiagnostics.isAuthenticationPath(req.url?.path ?? "")
                ? AuthResponseDiagnostics.summary(request: req, response: http, data: data, cookieNames: cookieNames)
                : Self.message(from: data)
        )
        if AuthResponseDiagnostics.isCloudflareChallenge(http) {
            throw DiscourseError.cloudflare
        }
        return (data, http)
    }

    private func ensureOK(_ data: Data, _ http: HTTPURLResponse) throws {
        guard (200..<400).contains(http.statusCode) else {
            throw DiscourseError.http(http.statusCode, Self.message(from: data))
        }
    }

    // MARK: - GET

    func get<T: Decodable>(_ path: String, query: [URLQueryItem] = [], as type: T.Type) async throws -> T {
        guard let url = makeURL(path, query: query) else { throw DiscourseError.badURL }
        var req = URLRequest(url: url)
        req.httpMethod = "GET"
        decorate(&req)
        let (data, http) = try await send(req)
        try ensureOK(data, http)
        do {
            return try decoder.decode(T.self, from: data)
        } catch {
            throw DiscourseError.decoding(String(describing: error))
        }
    }

    // MARK: - CSRF

    func csrfToken(forceRefresh: Bool = false) async throws -> String {
        if let cached = await csrfCache.value, !forceRefresh, !cached.isEmpty { return cached }

        guard let url = makeURL("/session/csrf.json") else { throw DiscourseError.badURL }
        var req = URLRequest(url: url)
        req.httpMethod = "GET"
        decorate(&req)
        let (data, http) = try await send(req)
        try ensureOK(data, http)
        guard let parsed = try? decoder.decode(CSRFResponse.self, from: data) else {
            throw DiscourseError.decoding("csrf token 缺失")
        }
        await csrfCache.set(parsed.csrf)
        return parsed.csrf
    }

    // MARK: - POST form

    @discardableResult
    func postForm(_ path: String, fields: [String: String], withCSRF: Bool = true) async throws -> Data {
        let token: String?
        if withCSRF {
            token = try await csrfToken()
        } else {
            token = nil
        }
        guard let url = makeURL(path) else { throw DiscourseError.badURL }
        var req = URLRequest(url: url)
        req.httpMethod = "POST"
        decorate(&req)
        req.setValue("application/x-www-form-urlencoded; charset=utf-8", forHTTPHeaderField: "Content-Type")
        if let token = token {
            req.setValue(token, forHTTPHeaderField: "X-CSRF-Token")
        }
        req.httpBody = Self.formEncode(fields).data(using: .utf8)
        let (data, http) = try await send(req)
        if http.statusCode >= 400 { throw DiscourseError.http(http.statusCode, Self.message(from: data)) }
        return data
    }

    /// 发一篇回复等 JSON 接口。Discourse 需要 `X-CSRF-Token` + JSON body。
    func postJSON<T: Decodable>(_ path: String, body: [String: Any], as type: T.Type) async throws -> T {
        guard let url = makeURL(path) else { throw DiscourseError.badURL }
        var req = URLRequest(url: url)
        req.httpMethod = "POST"
        decorate(&req)
        req.setValue("application/json", forHTTPHeaderField: "Content-Type")
        req.setValue(try await csrfToken(), forHTTPHeaderField: "X-CSRF-Token")
        req.httpBody = try JSONSerialization.data(withJSONObject: body, options: [])
        let (data, http) = try await send(req)
        try ensureOK(data, http)
        do { return try decoder.decode(T.self, from: data) }
        catch { throw DiscourseError.decoding(String(describing: error)) }
    }

    // MARK: - session

    /// 刷新当前会话的 CSRF，不清空已有验证 Cookie 或两步验证会话。
    func warmUp() async throws {
        _ = try await csrfToken(forceRefresh: true)
    }

    func currentUser() async throws -> CurrentUser? {
        guard let url = makeURL("/session/current.json") else { throw DiscourseError.badURL }
        var req = URLRequest(url: url)
        req.httpMethod = "GET"
        decorate(&req)
        let (data, http) = try await send(req)
        // Discourse 在没有当前用户时返回 404；其他失败应保留真实错误。
        if http.statusCode == 404 || http.statusCode == 401 { return nil }
        try ensureOK(data, http)
        do {
            return try decoder.decode(SessionCurrentResponse.self, from: data).currentUser
        } catch {
            throw DiscourseError.decoding("当前用户响应格式不正确")
        }
    }

    struct LoginOutcome {
        let success: Bool
        let secondFactorRequired: Bool
        let message: String?
    }

    func login(account: String, password: String, secondFactorCode: String? = nil) async throws -> LoginOutcome {
        let previousKey = apiKeyBox.get()
        var succeeded = false
        defer { if !succeeded { setApiKey(previousKey) } }
        // 账号密码登录使用 Cookie 会话，避免旧 API Key 干扰认证。
        setApiKey(nil)
        try await warmUp()

        var fields: [String: String] = [
            "login": account, "password": password, "timezone": TimeZone.current.identifier
        ]
        if let code = secondFactorCode?.trimmingCharacters(in: .whitespaces), !code.isEmpty {
            fields["second_factor_method"] = "1"   // 1 = TOTP
            fields["second_factor_code"] = code
        }

        let data = try await postForm("/session", fields: fields)

        if let obj = try? JSONSerialization.jsonObject(with: data) as? [String: Any],
           let error = obj["error"] as? String, !error.isEmpty {
            let needs2FA = obj["second_factor_required"] as? Bool == true
                || obj["totp_enabled"] as? Bool == true
                || error.lowercased().contains("two factor")
                || error.lowercased().contains("second factor")
                || error.contains("验证码")
            return LoginOutcome(
                success: false,
                secondFactorRequired: needs2FA,
                message: "\(error)｜cookie=\(cookieDiagnostics())"
            )
        }

        if let user = try await currentUser() {
            succeeded = true
            return LoginOutcome(success: true, secondFactorRequired: false, message: user.username)
        }
        return LoginOutcome(
            success: false,
            secondFactorRequired: false,
            message: "登录请求已完成，但未取得用户会话｜cookie=\(cookieDiagnostics())"
        )
    }

    func logout() async throws {
        _ = try? await postForm("/logout", fields: [:])
        await csrfCache.set(nil)
        resetCookies()
    }

    // MARK: - 站点定制设备码登录（协议尚待验证）

    /// 第一步：申请设备码。用户拿 user_code 去浏览器授权。
    ///
    /// 关于 CSRF：Discourse 的 `/login/*` 命名空间并不总是豁免 CSRF。缺 token 时
    /// Rails 抛 `InvalidAuthenticityToken`，Discourse 把它渲染成
    /// 403「您没有权限查看请求的资源。」——所以先不带 token 试，403/422 再带 token 重试。
    func requestDeviceCode(clientId: String, scopes: [String]) async throws -> DeviceCodeResponse {
        let fields: [String: String] = [
            "client_id": clientId,
            "scopes": scopes.joined(separator: ","),
            "application_name": DeviceAuthConfig.applicationName
        ]

        var (data, http) = try await postFormRaw("/login/device/code", fields: fields, withCSRF: false)
        if http.statusCode == 403 || http.statusCode == 422 {
            (data, http) = try await postFormRaw("/login/device/code", fields: fields, withCSRF: true)
        }
        guard http.statusCode < 400 else {
            throw DiscourseError.http(http.statusCode, Self.message(from: data))
        }
        do {
            return try decoder.decode(DeviceCodeResponse.self, from: data)
        } catch {
            throw DiscourseError.decoding("响应不是设备码 JSON：" + Self.snippet(data))
        }
    }

    /// 第二步：轮询换 token。授权未完成时返回 `error = authorization_pending`。
    func pollDeviceToken(clientId: String, deviceCode: String) async throws -> DeviceTokenResponse {
        let fields: [String: String] = [
            "grant_type": "urn:ietf:params:oauth:grant-type:device_code",
            "device_code": deviceCode,
            "client_id": clientId
        ]

        var (data, http) = try await postFormRaw("/login/oauth/access_token", fields: fields, withCSRF: false)
        if http.statusCode == 403 {
            (data, http) = try await postFormRaw("/login/oauth/access_token", fields: fields, withCSRF: true)
        }
        // 轮询阶段 400 属正常语义（authorization_pending），必须解析而不是抛错
        if http.statusCode >= 500 {
            throw DiscourseError.http(http.statusCode, Self.message(from: data))
        }
        do {
            return try decoder.decode(DeviceTokenResponse.self, from: data)
        } catch {
            throw DiscourseError.decoding("轮询响应无法解析：" + Self.snippet(data))
        }
    }

    /// POST 表单，返回原始响应。4xx 不抛错——调用方要读 body 判断语义。
    /// `accept` 用于覆盖默认的 `application/json`：Discourse 有些 action 只渲染 HTML，
    /// 用 JSON 去协商会直接 404。
    func postFormRaw(
        _ path: String,
        fields: [String: String],
        withCSRF: Bool,
        accept: String? = nil
    ) async throws -> (Data, HTTPURLResponse) {
        guard let url = makeURL(path) else { throw DiscourseError.badURL }
        var req = URLRequest(url: url)
        req.httpMethod = "POST"
        decorate(&req)
        if let accept = accept {
            req.setValue(accept, forHTTPHeaderField: "Accept")
        }
        req.setValue(
            "application/x-www-form-urlencoded; charset=utf-8",
            forHTTPHeaderField: "Content-Type"
        )
        if withCSRF {
            req.setValue(try await csrfToken(), forHTTPHeaderField: "X-CSRF-Token")
        }
        req.httpBody = Self.formEncode(fields).data(using: .utf8)
        return try await send(req)
    }

    /// 响应体片段，用于把看不懂的解码错误变成人话。
    static func snippet(_ data: Data) -> String {
        let text = String(data: data.prefix(300), encoding: .utf8) ?? "（非文本响应）"
        return text.trimmingCharacters(in: .whitespacesAndNewlines)
    }

    // MARK: - User API Key（RSA，Discourse 经典方案）

    /// 只构造浏览器 GET 授权地址，不请求 CSRF，也不提前创建密钥。
    func requestUserApiKey(
        publicKeyPEM: String,
        nonce: String,
        clientId: String,
        scopes: [String],
        redirect: String?
    ) throws -> URL {
        try UserApiKeyAuthorization.makeURL(
            baseURL: baseURL,
            applicationName: AppConfig.clientName,
            publicKeyPEM: publicKeyPEM,
            nonce: nonce,
            clientId: clientId,
            scopes: scopes,
            redirect: redirect
        )
    }

    // MARK: - feeds

    struct FeedPage {
        let topics: [TopicSummary]
        let users: [Int: DiscourseUser]
        let hasMore: Bool
    }

    func feed(path: String, page: Int = 0) async throws -> FeedPage {
        let response = try await get(
            path,
            query: [
                URLQueryItem(name: "page", value: String(page)),
                URLQueryItem(name: "per_page", value: String(AppConfig.perPage))
            ],
            as: TopicListResponse.self
        )
        var map: [Int: DiscourseUser] = [:]
        for user in response.users ?? [] { map[user.id] = user }
        return FeedPage(
            topics: response.topicList.topics,
            users: map,
            hasMore: (response.topicList.moreTopicsUrl?.isEmpty == false)
        )
    }

    func topicDetail(id: Int) async throws -> TopicDetailResponse {
        try await get("/t/\(id).json", as: TopicDetailResponse.self)
    }

    /// 分页加载帖子正文，用于 detail 首屏之后的续读。
    func posts(inTopic id: Int, ids: [Int]) async throws -> [Post] {
        guard !ids.isEmpty else { return [] }
        let query = ids.map { URLQueryItem(name: "post_ids[]", value: String($0)) }
        let response = try await get("/t/\(id)/posts.json", query: query, as: PostStreamResponse.self)
        return response.postStream.posts
    }
}

/// 异步安全的 CSRF 缓存。替代 `NSLock`——后者在异步上下文中使用
/// 在 Swift 6 语言模式下会直接变成编译错误。
actor CSRFCache {

    private var token: String?

    var value: String? { token }

    func set(_ newValue: String?) {
        token = newValue
    }
}

/// 持有 user API key 的小容器。
/// `decorate` 是同步函数，所以这里用同步锁；不要在 async 上下文里直接调用 lock/unlock。
final class APIKeyBox: @unchecked Sendable {

    private let lock = NSLock()
    private var value: String?

    func get() -> String? {
        lock.lock()
        defer { lock.unlock() }
        return value
    }

    func set(_ newValue: String?) {
        lock.lock()
        value = newValue
        lock.unlock()
    }
}
