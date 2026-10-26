import Foundation


/// 记录最近一次请求实际协商到的 HTTP 版本。
///
/// Cloudflare 对 h3 与 h2 的处理可能不同，用户报「连不上」时，
/// 需要先确认到底有没有真的走 QUIC，否则会误判成网络不可达。
final class ProtocolCollector: NSObject, URLSessionTaskDelegate {

    static let shared = ProtocolCollector()

    private let lock = NSLock()
    private var stored: String?

    var lastProtocolName: String? {
        lock.lock()
        defer { lock.unlock() }
        return stored
    }

    func urlSession(
        _ session: URLSession,
        task: URLSessionTask,
        didFinishCollecting metrics: URLSessionTaskMetrics
    ) {
        guard let name = metrics.transactionMetrics.last?.networkProtocolName else { return }
        lock.lock()
        stored = name
        lock.unlock()
    }
}

enum DiscourseError: LocalizedError {
    case badURL
    case http(Int, String)
    case decoding(String)
    case transport(String)
    case unauthorized
    case cloudflare
    /// 429：被 Cloudflare 或站点限流。必须退避，继续重试只会把窗口越拉越长。
    case rateLimited

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
        case .rateLimited:
            return "请求过于频繁被限流，请等几分钟再试"
        }
    }
}

/// 标准 Discourse REST 客户端。仅用 URLSession，无第三方依赖。
final class DiscourseClient {

    static let shared = DiscourseClient()

    /// 实际使用的根地址：自定义反代优先，否则用默认站点。
    var baseURL: URL {
        NetworkSettings.customBaseURL ?? defaultBaseURL
    }
    private let defaultBaseURL: URL
    private var session: URLSession
    private let decoder = JSONDecoder()
    private let csrfCache = CSRFCache()
    private let apiKeyBox = APIKeyBox()
    private let directBox = DirectAvailabilityBox()

    /// 登录后设置 user API key；之后所有请求自动带 `User-Api-Key` 头。
    func setApiKey(_ key: String?) {
        apiKeyBox.set(key)
    }

    /// 走本地 DoH + ECH 代理时的端口；nil 表示不走代理。
    private var proxyPort: Int?

    init(baseURL: URL = AppConfig.baseURL) {
        self.defaultBaseURL = baseURL
        self.session = Self.makeSession(proxyPort: nil, preferQUIC: NetworkSettings.preferQUIC)
    }

    /// 切换本地代理：非 nil 时所有请求经 127.0.0.1:port，由 Rust 代理用 ECH 出去。
    func setProxyPort(_ port: Int?) {
        guard port != proxyPort else { return }
        proxyPort = port
        session.invalidateAndCancel()
        session = Self.makeSession(proxyPort: port, preferQUIC: NetworkSettings.preferQUIC)
    }

    /// 切换 QUIC 模式。需要用新配置重建 session 才生效。
    func setPreferQUIC(_ enabled: Bool) {
        NetworkSettings.preferQUIC = enabled
        session.invalidateAndCancel()
        session = Self.makeSession(proxyPort: proxyPort, preferQUIC: enabled)
    }


    /// 发一次最轻的请求，只为让 URLSession 走完一次真实连接，
    /// 好让 ProtocolCollector 记录到实际协商的协议。
    func latestForProtocolProbe() async throws -> Data {
        guard let url = makeURL("/session/csrf.json") else { throw DiscourseError.badURL }
        var req = URLRequest(url: url)
        req.httpMethod = "GET"
        decorate(&req)
        let (data, http) = try await send(req)
        if http.statusCode >= 400 {
            throw DiscourseError.http(http.statusCode, Self.message(from: data))
        }
        return data
    }
    var isUsingProxy: Bool { proxyPort != nil }

    private static func makeSession(proxyPort: Int?, preferQUIC: Bool) -> URLSession {
        let cfg = URLSessionConfiguration.default
        cfg.httpCookieStorage = HTTPCookieStorage.shared
        // 自动挂载关掉：直连和 stream 都绕开 URLSession，Cookie 统一由 decorate 手动加，
        // 打开自动挂载只会在 URLSession 路径上造成重复。
        cfg.httpShouldSetCookies = false
        cfg.httpCookieAcceptPolicy = .always
        cfg.timeoutIntervalForRequest = 12
        cfg.timeoutIntervalForResource = 20
        cfg.requestCachePolicy = .reloadIgnoringLocalCacheData
        cfg.urlCache = nil
        cfg.httpAdditionalHeaders = ["User-Agent": AppConfig.userAgent]
        // QUIC 由每个 URLRequest 的 assumesHTTP3Capable 控制（见 decorate），
        // URLSessionConfiguration 上没有这个开关。

        if let port = proxyPort {
            cfg.connectionProxyDictionary = [
                kCFNetworkProxiesHTTPEnable as String: true,
                kCFNetworkProxiesHTTPProxy as String: "127.0.0.1",
                kCFNetworkProxiesHTTPPort as String: port,
                "HTTPSEnable": true,
                "HTTPSProxy": "127.0.0.1",
                "HTTPSPort": port
            ]
        }
        return URLSession(
            configuration: cfg,
            delegate: preferQUIC ? ProtocolCollector.shared : nil,
            delegateQueue: nil
        )
    }

    // MARK: - URL / headers

    private func makeURL(_ path: String, query: [URLQueryItem] = []) -> URL? {
        guard var comps = URLComponents(url: baseURL, resolvingAgainstBaseURL: false) else { return nil }
        comps.path = path.hasPrefix("/") ? path : "/" + path
        if !query.isEmpty { comps.queryItems = query }
        return comps.url
    }
    private func decorate(_ req: inout URLRequest) {
        // 直接用 QUIC 出网，不等 Alt-Svc 发现。
        //
        // 这是原版的做法：它的连接统计是 100% HTTP/3、0% HTTP/2，一次 TCP 都没用。
        // 走 TCP 时 TLS ClientHello 的 SNI 是明文，部分网络会直接 RST；
        // QUIC 的握手在加密帧里，中间设备看不到域名，也就拦不住。
        // 且这条路走的是 Apple 自己的 TLS 栈，指纹与 Safari 一致。
        if NetworkSettings.preferQUIC {
            req.assumesHTTP3Capable = true
        }
        req.setValue(AppConfig.userAgent, forHTTPHeaderField: "User-Agent")
        req.setValue("application/json", forHTTPHeaderField: "Accept")
        req.setValue("zh-CN,zh;q=0.9", forHTTPHeaderField: "Accept-Language")
        req.setValue("XMLHttpRequest", forHTTPHeaderField: "X-Requested-With")
        // 浏览器都会带这几个，缺了容易拉低 Cloudflare 的机器人评分。
        req.setValue("same-origin", forHTTPHeaderField: "Sec-Fetch-Site")
        req.setValue("cors", forHTTPHeaderField: "Sec-Fetch-Mode")
        req.setValue("empty", forHTTPHeaderField: "Sec-Fetch-Dest")
        if req.value(forHTTPHeaderField: "Referer") == nil {
            req.setValue("https://\(baseURL.host ?? "linux.do")/", forHTTPHeaderField: "Referer")
        }

        // 直连和 stream 两条路都绕开 URLSession，自动 Cookie 不生效，
        // 所以这里统一手动挂上；URLSession 侧也关掉了自动挂载，避免重复。
        if let cookie = currentCookieHeader() {
            req.setValue(cookie, forHTTPHeaderField: "Cookie")
        }

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
        let all = HTTPCookieStorage.shared.cookies(for: baseURL) ?? []
        // 同名 Cookie 只保留一枚：WebView 抓取和导入可能产生域名不同的重复项，
        // 重复的 cf_clearance / _t 会让服务端会话判定出错，表现为莫名的 403。
        var seen = Set<String>()
        var unique: [HTTPCookie] = []
        for cookie in all.sorted(by: { $0.domain.count > $1.domain.count }) where !cookie.name.isEmpty {
            if seen.insert(cookie.name).inserted {
                unique.append(cookie)
            } else {
                HTTPCookieStorage.shared.deleteCookie(cookie)
            }
        }
        return unique
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

    /// 是否已有登录会话 cookie。
    var hasSessionCookie: Bool {
        currentCookies().contains { $0.name == "_t" && !$0.value.isEmpty }
    }

    /// 当前 cookie 的请求头形式，用于存进 Keychain。
    func currentCookieHeader() -> String? {
        let cookies = currentCookies()
        guard !cookies.isEmpty else { return nil }
        return HTTPCookie.requestHeaderFields(with: cookies)["Cookie"]
    }

    // MARK: - transport

    /// - Parameter allowKeyFallback: 403 时是否允许去掉 `User-Api-Key` 重试一次。
    ///   公开内容（列表、主题、搜索）游客也能读，但带一个 scope 不足的 key 时
    ///   Discourse 会判定无权限直接 403。原版就是这么做的：公开请求不带 key。
    ///   只对 GET/HEAD 回退，POST 重试会有重复副作用。
    private func send(
        _ req: URLRequest,
        allowKeyFallback: Bool = true
    ) async throws -> (Data, HTTPURLResponse) {
        let cookieNames = HTTPCookieStorage.shared.cookies(for: req.url ?? baseURL)?.map { $0.name } ?? []

        // 优先走 DoH + IP 直连（绕 DNS 污染）；失败就回退系统 DNS 的 URLSession。
        var directFailure: String?
        // QUIC 模式下不能走手写 HTTP/1.1 直连：那条路是 TCP，
        // 正好是会被 RST 的那条。要让 URLSession 自己用 h3 出网。
        if directBox.isAvailable && proxyPort == nil && !NetworkSettings.preferQUIC {
            do {
                let direct = try await DirectTransport.shared.send(req)
                await RequestLog.shared.record(
                    method: req.httpMethod ?? "?",
                    url: (req.url?.path ?? "?") + " [DoH直连]",
                    status: direct.1.statusCode,
                    note: AuthResponseDiagnostics.isAuthenticationPath(req.url?.path ?? "")
                        ? AuthResponseDiagnostics.summary(
                            request: req, response: direct.1, data: direct.0, cookieNames: cookieNames
                        )
                        : Self.message(from: direct.0)
                )

                if AuthResponseDiagnostics.isCloudflareChallenge(direct.1, body: direct.0) {
                    // 直连被 Cloudflare 挑战：本机网络需要浏览器校验，直连这条路走不通。
                    // 不要直接失败——回退到 URLSession，有梯子时那边是通的。
                    directBox.markFailed()
                    directFailure = "Cloudflare 挑战"
                    await RequestLog.shared.record(
                        method: req.httpMethod ?? "?",
                        url: (req.url?.path ?? "?") + " [直连被挑战]",
                        status: direct.1.statusCode,
                        note: "回退系统网络"
                    )
                } else {
                    directBox.markSucceeded()
                    // DoH 直连此前在这里提前返回，绕过了下方 URLSession 分支的
                    // 403 无 API Key 重试；scope 不含 read 时，公开主题接口因此一直 403。
                    if direct.1.statusCode == 403,
                       allowKeyFallback,
                       req.value(forHTTPHeaderField: "User-Api-Key") != nil,
                       (req.httpMethod == "GET" || req.httpMethod == "HEAD") {
                        var publicReq = req
                        publicReq.setValue(nil, forHTTPHeaderField: "User-Api-Key")
                        return try await send(publicReq, allowKeyFallback: false)
                    }
                    return direct
                }
            } catch {
                directBox.markFailed()
                directFailure = error.localizedDescription
                await RequestLog.shared.record(
                    method: req.httpMethod ?? "?",
                    url: (req.url?.path ?? "?") + " [直连失败]",
                    status: -1,
                    note: error.localizedDescription
                )
            }
        }

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
            let detail = directFailure.map { "｜直连诊断：\($0)" } ?? ""
            throw DiscourseError.transport(error.localizedDescription + detail)
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
        // 429 与普通挑战分开：它是限流，重试只会把窗口拉得更长，
        // 调用方必须长退避而不是立刻重来。
        if http.statusCode == 429 {
            throw DiscourseError.rateLimited
        }
        if AuthResponseDiagnostics.isCloudflareChallenge(http, body: data) {
            throw DiscourseError.cloudflare
        }
        // 403 且不是 Cloudflare 挑战、且请求带了 key：说明是 scope 不足被站点拒绝。
        // 公开内容去掉 key 用游客身份重试一次——这正是原版的做法，
        // 它只申请 notifications/session_info，读列表时不带 key。
        if http.statusCode == 403,
           allowKeyFallback,
           req.value(forHTTPHeaderField: "User-Api-Key") != nil,
           req.httpMethod == "GET",
           !AuthResponseDiagnostics.isCloudflareChallenge(http, body: data) {
            var publicReq = req
            publicReq.setValue(nil, forHTTPHeaderField: "User-Api-Key")
            return try await send(publicReq, allowKeyFallback: false)
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
        // 这里必须带 key：回退成游客会让接口返回匿名，把已登录状态误判成未登录。
        let (data, http) = try await send(req, allowKeyFallback: false)
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

    // MARK: - 设备授权（Discourse 原生 user-api-key device flow）

    /// 第一步：创建设备码。用户拿 `userCode` 去浏览器输入。
    ///
    /// `ensure_json_request!` 要求 Content-Type 与 Accept 都是 JSON，
    /// 不满足就在业务逻辑之前被判 InvalidAccess（403 + invalid_access）。
    func requestDeviceCode(
        publicKeyPEM: String,
        nonce: String,
        clientId: String,
        scopes: [String],
        applicationName: String
    ) async throws -> DeviceCodeResponse {
        let body: [String: Any] = [
            "client_id": clientId,
            "scopes": scopes.joined(separator: ","),
            "nonce": nonce,
            "public_key": publicKeyPEM,
            "application_name": applicationName
        ]
        let data = try await postJSONRaw("/user-api-key/device.json", body: body)
        do {
            let code = try decoder.decode(DeviceCodeResponse.self, from: data)
            guard code.isUsable else {
                throw DiscourseError.decoding("设备码形状异常：" + Self.snippet(data))
            }
            return code
        } catch let error as DiscourseError {
            throw error
        } catch {
            throw DiscourseError.decoding("响应不是设备码 JSON：" + Self.snippet(data))
        }
    }

    /// 第二步：轮询。授权成功后 `payload` 只返回一次，必须当场解密。
    ///
    /// 待授权时站点回 200 + `{"status":"authorization_pending"}`，
    /// 所以不能按 HTTP 状态码判失败。
    func pollDeviceAuthorization(deviceCode: String) async throws -> DevicePollResponse {
        let data = try await postJSONRaw(
            "/user-api-key/device/poll.json",
            body: ["device_code": deviceCode]
        )
        do {
            return try decoder.decode(DevicePollResponse.self, from: data)
        } catch let error as DiscourseError {
            throw error
        } catch {
            throw DiscourseError.decoding("轮询响应无法解析：" + Self.snippet(data))
        }
    }

    /// 发 JSON 请求体、不带 CSRF。设备授权这两个端点在 Discourse 里
    /// `skip_before_action :verify_authenticity_token`，提前取 token 只是多一次请求。
    func postJSONRaw(_ path: String, body: [String: Any]) async throws -> Data {
        guard let url = makeURL(path) else { throw DiscourseError.badURL }
        var req = URLRequest(url: url)
        req.httpMethod = "POST"
        decorate(&req)
        req.setValue("application/json", forHTTPHeaderField: "Content-Type")
        req.setValue("application/json", forHTTPHeaderField: "Accept")
        req.httpBody = try JSONSerialization.data(withJSONObject: body, options: [])
        let (data, http) = try await send(req)
        if http.statusCode >= 400 {
            throw DiscourseError.http(http.statusCode, Self.message(from: data))
        }
        return data
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

    func feed(path: String, page: Int = 0, categoryId: Int? = nil) async throws -> FeedPage {
        var query = [
            URLQueryItem(name: "page", value: String(page)),
            URLQueryItem(name: "per_page", value: String(AppConfig.perPage))
        ]
        if let categoryId = categoryId {
            query.append(URLQueryItem(name: "category", value: String(categoryId)))
        }
        let response = try await get(
            path,
            query: query,
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

    /// 点赞。Discourse 的通用动作接口：POST /post_actions.json
    @discardableResult
    func like(postId: Int) async throws -> Data {
        try await postForm("/post_actions.json", fields: [
            "id": String(postId),
            "post_action_type_id": "2",
            "flag_topic": "false"
        ])
    }

    /// 取消点赞。DELETE /post_actions/:id，:id 是动作记录 id 而非帖子 id。
    @discardableResult
    func unlike(postActionId: Int) async throws -> Data {
        guard let url = makeURL("/post_actions/\(postActionId).json") else {
            throw DiscourseError.badURL
        }
        var req = URLRequest(url: url)
        req.httpMethod = "DELETE"
        decorate(&req)
        req.setValue(try await csrfToken(), forHTTPHeaderField: "X-CSRF-Token")
        let (data, http) = try await send(req)
        if http.statusCode >= 400 { throw DiscourseError.http(http.statusCode, Self.message(from: data)) }
        return data
    }

    /// 站点分类列表。
    func categories() async throws -> [Category] {
        let response = try await get("/categories.json", as: CategoryListResponse.self)
        return response.categoryList.categories
    }

    /// 搜索主题。
    func search(term: String, page: Int = 0) async throws -> [TopicSummary] {
        let response = try await get(
            "/search.json",
            query: [
                URLQueryItem(name: "q", value: term),
                URLQueryItem(name: "page", value: String(page))
            ],
            as: SearchResponse.self
        )
        return response.topics ?? []
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

/// 直连可用性开关：DoH 失败后冷却一段时间，避免每个请求都白等一次超时。
final class DirectAvailabilityBox: @unchecked Sendable {

    private let lock = NSLock()
    private var disabledUntil = Date.distantPast

    var isAvailable: Bool {
        lock.lock()
        defer { lock.unlock() }
        return Date() >= disabledUntil
    }

    func markSucceeded() {
        lock.lock()
        disabledUntil = Date.distantPast
        lock.unlock()
    }

    func markFailed() {
        lock.lock()
        // 5 分钟内不再重试直连：被挑战时每次重试都要白等几秒。
        disabledUntil = Date().addingTimeInterval(300)
        lock.unlock()
    }
}
