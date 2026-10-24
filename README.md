# LinuxDoClient —— iOS 16 原生客户端（重写）

[![iOS Build](https://github.com/bltbbb/linuxdo-ios16/actions/workflows/ios-build.yml/badge.svg)](https://github.com/bltbbb/linuxdo-ios16/actions/workflows/ios-build.yml)

目标：在 **iOS 16.3** 上获得 LINUX DO 的原生使用体验。

静态分析表明，原版 `org.linuxdo.community-1.0.2` 强依赖 SwiftData、Observation 等新系统接口，
无法仅靠修改最低版本号支持 iOS 16.3。本工程使用 iOS 16 可用接口重新实现客户端。
论坛基于 Discourse，但站点可能扩展认证协议，不能将上游文档视为全部站点行为。

## 登录：在电脑上授权，手机不加载论坛网页

iOS 16.3 上的论坛前端存在浏览器内核兼容问题，换成系统认证浏览器并不能解决。
登录主路径现为电脑完成一次网站授权、手机接收加密结果：

1. 手机点“生成电脑授权链接”，生成 RSA 密钥对、随机 nonce 和本机 client ID。
2. 将链接复制或分享到电脑，在电脑浏览器打开并登录论坛。
3. 确认只读授权后，复制网页显示的整段加密结果。
4. 回到手机，粘贴结果，点“完成授权并登录”。手机解密并校验 nonce，再请求当前用户信息。
5. 验证成功后，用户密钥保存在钥匙串中，后续启动直接恢复。

链接使用 `GET /user-api-key/new`，参数不包含 `auth_redirect`。
上游 Discourse 在这种模式下支持直接显示可复制的 payload；无需手机接收浏览器回调，
也不需要从电脑导出 Cookie 或明文 API Key。电脑确认授权时仍由网站处理正常的验证与权限检查。
权限为 `read,session_info`；公钥中的加号编码成 `%2B`。

待完成授权的私钥及 nonce 保存在仅限本机的钥匙串记录中，恢复或导入时检查 24 小时有效期。
切换应用、进程重启后可以继续；取消或完成后删除记录。复制错误或网络失败允许重试同一结果。
输入支持纯 Base64 或带 `payload` 字段的 JSON，不接受明文密钥。

账号密码登录仍作为备用入口，但网站拒绝原生请求时不会自动转到手机浏览器。
设备码并不意味着无需浏览器：申请和轮询可以走 HTTP，用户授权通常仍需另一设备打开网页。
原版 IPA 的设备授权模型还包含 `sessionCookie`、`registrationToken`、`registrationRequired`、
`identityToken`、`authorizationCode`、`nonce` 等字段。轮询令牌请求使用的固定 `client_id` 是
`discourse-ios`，与申请设备码时的应用标识分开；当前实现已按这个差异修正。
轮询优先接收 `sessionCookie` 并恢复 `_t` 会话，只有没有 Cookie 时才使用 `access_token`。
设备码初始请求的完整字段和站点是否要求设备注册仍需真实响应验证，不能仅凭字符串推断已经完整复刻。

## 设备码 403 的根因

对原版 IPA 的进一步静态分析发现，设备授权服务不是普通 OAuth 设备码客户端：

- `DeviceAuthorizationService` 持有 `prepare`、`deviceCheckTokenProvider` 和设备 ID。
- API 请求模型包含 `requiresAttest`、`requiresClientCertificate`。
- 原版包含 `AttestationService`、`DeviceCertificateManager`、`SystemAppAttestDevice`、`DCAppAttestService`。
- 二进制中有 `/attest/challenge`、`X-App-Attest-Assertion`、`X-Device-Check-Token`、`mtls_certificate_pem`。
- 签名权限包含原版的 App Attest entitlement 和原始 App ID。

因此，`POST /login/device/code` 返回 `403 invalid_access` 且 `CF挑战=否`，与 Cloudflare、CSRF 或 DoH 无关，
最符合“缺少原版的 App Attest / DeviceCheck / mTLS 设备证书”。当前复刻即使把 JSON、`client_id` 和响应字段全部对齐，
也不能在一个不同 Bundle ID、不同签名团队的 iOS 16 应用里生成原版服务器认可的设备证明。Apple 的 App Attest 设计本身就是让服务器验证 App 身份和一次性挑战，[官方说明](https://developer.apple.com/documentation/devicecheck/establishing-your-app-s-integrity)。

当前日志说明 DoH 链路已经正常：`GET /latest.json → 200`，认证接口也到达论坛应用层；继续安装证书、切换代理或调整 CSRF 不会解决这个 403。
可行的登录路线是导入完整浏览器会话 Cookie，或在原版签名环境中完成设备授权后复用其会话。仅凭当前 IPA 和 iOS 16 重写工程无法独立复刻这套设备证明。

## 原生登录 403 的诊断

已有日志只能证明 `/session` 请求遭拒，不能证明密码错误、CSRF 错误或 Cloudflare 挑战：

- `/session/current.json` 的匿名 404 是未登录状态。
- `/session/csrf.json` 的 200 表示取得 CSRF 令牌，不代表登录已完成。
- 不能仅凭一个 403 或 `Server: cloudflare` 判断存在交互式挑战。

此次修正了原生请求流程：不再每次登录都清空 Cookie；统一由同一 URLSession 接收和发送 Cookie；
刷新 CSRF 后再组装表单请求；补充同源 Origin 和 Referer；登录时不携带旧 API Key；
两步验证重试保留会话，并读取结构化的二次验证标记。
这些改动解决客户端会话处理问题，不代表已确定该设备 403 的唯一原因。

新诊断保留响应 MIME 类型、`error_type`、`cf-mitigated: challenge`、`BAD CSRF` 标记、
请求是否带 CSRF/Origin，以及发送前存储中的 Cookie 名称，不输出值或响应正文。
若再出现拒绝，可以依据这些特征区分站点拒绝与挑战响应。

站点仍需允许用户 API Key 和读取权限；电脑授权成功也不保证手机网络请求不受 Cloudflare 限制。
当前未验证 linux.do 的实际站点授权策略，也没有进行真机登录。

回归用例位于 `Tests/UserApiKeyFlowTests.swift` 和 `Tests/AuthResponseDiagnosticsTests.swift`，
包括无回调授权链接、私钥恢复、加密结果导入、nonce 校验、错误密钥以及诊断脱敏。
按要求未进行本地构建或测试执行。验收时还需检查取消重试、应用重启、授权被撤销和网络失败后的行为。

依据：[Discourse 授权实现](https://github.com/discourse/discourse/blob/main/app/controllers/user_api_keys_controller.rb)、
[会话处理](https://github.com/discourse/discourse/blob/main/app/controllers/session_controller.rb)、
[CSRF 与拒绝访问处理](https://github.com/discourse/discourse/blob/main/app/controllers/application_controller.rb)。

---

## 原 app 依赖 → 本工程替换

| 原 app 1.0.2（iOS 17+） | 本工程（iOS 16+） |
|---|---|
| SwiftData（ModelContainer / ModelContext / @Query） | Core Data，代码构建 `NSManagedObjectModel` |
| Observation 框架（`@Observable`、`withObservationTracking`） | `ObservableObject` + `@Published` |
| SwiftUI `Bindable` | 直接 `@StateObject` / `@ObservedObject` |
| `ContentUnavailableView` | 自定义空态视图 |
| `containerRelativeFrame` | 常规布局 |
| `sensoryFeedback` | 无（可后续用 `UIImpactFeedbackGenerator`） |
| TipKit | 无 |
| Symbols framework | 无 |
| User API Key + Device 授权流 | 电脑授权后将加密结果交回手机；原生账号密码登录作为备用 |
| MessageBus 实时推送 | **未实现**（见「未实现」） |

三个 SwiftData 实体逐字段还原为 Core Data 实体：
`SiteCacheEntity`、`TopicListCacheEntity`、`DraftEntity`。

---

## 目录

```
LinuxDoClient/
├── project.yml                       XcodeGen 工程定义（target iOS 16.0）
└── Sources/
    ├── App/
    │   ├── LinuxDoClientApp.swift    @main + RootView
    │   └── AppConfig.swift           baseURL / UA / 缓存键
    ├── Core/
    │   └── DiscourseClient.swift     REST 客户端（GET / POST form / CSRF / 登录）
    ├── Auth/
    │   ├── AuthStore.swift            会话状态机
    │   └── WebLoginView.swift        WKWebView 登录 + cookie 桥接
    ├── Models/
    │   └── Models.swift              Decodable 模型（列表 / 详情 / 会话）
    ├── Store/
    │   └── Persistence.swift         Core Data 栈 + CacheRepository
    ├── Features/
    │   ├── LoginView.swift
    │   ├── TopicListView.swift       列表 + 分页 + 下拉刷新
    │   └── TopicDetailView.swift     详情 + 续读
    └── Support/
        └── RichTextWebView.swift     渲染 Discourse `cooked` HTML
```

零第三方依赖。使用 Foundation / SwiftUI / UIKit / WebKit / CoreData / Security。

---

## 构建

需要 macOS + Xcode 15 或更新。

```bash
# 1) 安装 XcodeGen（一次性）
brew install xcodegen

# 2) 生成工程
cd LinuxDoClient
xcodegen generate

# 3) 打开并运行
open LinuxDoClient.xcodeproj
```

在 Xcode 里：

1. 选中 `LinuxDoClient` target → **Signing & Capabilities**
2. 勾选 *Automatically manage signing*，填你的 **Team**
3. 把 Bundle Identifier 从 `com.example.linuxdoclient` 改成你自己的唯一值
4. 连接 iOS 16.3 设备 → Run

> 如果不用 XcodeGen：新建一个 iOS App 工程（Interface: SwiftUI，最低版本 16.0），
> 把 `Sources/` 整个拖进去，并在 Info 里加 `NSAppTransportSecurity →
> NSAllowsArbitraryLoadsInWebContent = YES`（正文 WKWebView 加载图片/外链需要）。

## 装到 iOS 16.3 上

代码能编译 ≠ 能装上。iOS 16.3 只有这几条路：

- **免费 Apple ID 签名**（Sideloadly / AltStore）：7 天过期，需重签
- **付费开发者账号**：1 年有效期
- **TrollStore**：能否用取决于你的机型和系统补丁状态，需自行确认
- **越狱**：palera1n 仅 A11 及以下机型

---

## 已实现

- 电脑完成 User API Key 授权、手机导入加密结果（待真机验证）
- Cookie 会话登录（含 TOTP 二次验证分支）
- 冷启动会话恢复（`/session/current.json`）
- 列表：最新 / 热门 / 未读，分页加载，下拉刷新
- 详情：帖子流首屏 + 分批续读，正文 HTML 原生容器内渲染
- 离线缓存：列表与站点信息落 Core Data，TTL 10 分钟，先出缓存再刷新
- 草稿：本地 Core Data 草稿（`saveDraft` / `drafts` / `deleteDraft`）
- Cloudflare 403 与常见错误的中文提示
- 登录入口不依赖手机 WebKit；旧网页登录辅助代码保留但不在登录页展示

## 未实现（按优先级）

1. **MessageBus 实时推送** —— 原 app 的核心特性之一。需要 WebSocket/长轮询客户端，
   协议是 Discourse 的 `/__status` 轮询 + channel 订阅；工作量约等于再写一个模块。
2. **发帖 / 回复 / 编辑** —— `postJSON` 已经铺好，缺编辑器 UI 与 Markdown 预览。
3. **搜索** —— 端点 `/search.json` 已知，缺 UI。
4. **通知 / 私信 / 聊天** —— 端点已知（`/notifications.json`、`/chat/api/channels.json`）。
5. **APNs 推送** —— 需要自建推送服务端，成本最高。
6. **图片灯箱、代码高亮、MathJax** —— 正文当前只做基础 CSS 排版。

## 已知风险

- **未在真机编译验证**：本工程是在 Windows 上按 iOS 16 可用 API 静态书写，
  没有 Xcode 参与。首次 `xcodegen generate` + 编译时可能需要修少量编译错误。
- **Cloudflare 校验**：交互式挑战可能阻止原生 `URLSession` 请求，用户 API Key 不保证免除挑战。
  网页登录的 Cookie 同步也不保证通过跨客户端校验，具体需要设备和网络环境验证。
- **直接登录的可用性**：`/session` + CSRF 表单登录仅在未触发挑战时可用。
  若站点强制 passkey / 社交登录，应在网站授权页面完成对应交互；
  经典 User API Key 回调和设备码授权是不同协议，不能混用端点及响应结构。
- **`@MainActor` 与 `@StateObject` 默认值**：Swift 6 严格并发模式下会报
  main-actor 隔离错误。本工程已在 `project.yml` 里设 `SWIFT_VERSION = 5.0`、
  `SWIFT_STRICT_CONCURRENCY = minimal` 规避。
- **正文高度测量**：`WKWebView` 用 JS 量 `scrollHeight`，图片加载完成后高度可能
  二次跳变，属已知表现。若要彻底解决，改成单 WebView 承载整帖。
- **不做逆向**：本工程不包含、不修改、不依赖原 IPA 的任何二进制内容，
  只用公开的 Discourse HTTP 接口。

---

## 构建状态（CI 实测，非推测）

GitHub Actions · `macos-15` · Xcode 16.4 · Swift 6.1.2 · iPhoneOS 18.5 SDK · 无签名编译：

```
** BUILD SUCCEEDED **

Info.plist MinimumOSVersion = 16.0
LC_BUILD_VERSION  platform 2 (iOS)  minos 16.0  sdk 18.5
otool -L 中的 SwiftData / TipKit / Symbols / swiftObservation → (none)
```

工作流里有一条硬断言：`MinimumOSVersion` 必须等于 `16.0`，否则 job 直接失败。
作用是不让构建悄悄漂到更高系统版本——这正是原 1.0.2 包踩的坑。

`iOS Build` 只做编译验证；要出可安装的包，用 `Package IPA` 工作流（见下一节）。

---

## 安装（TrollStore / 巨魔）

工作流 `Package IPA` 产出 `LinuxDoClient-<版本>-unsigned.ipa`，已做 ad-hoc 伪签名
（`CodeDirectory flags = 0x2`），巨魔可直接安装。

1. 打开仓库 **Actions → Package IPA → 最近一次运行**，页面底部下载 `LinuxDoClient-ipa`
2. 解压得到 `.ipa`，传到手机（AirDrop / 文件 App / 局域网都行）
3. 用 **TrollStore** 打开这个 ipa → **Install**

巨魔走 CoreTrust 绕过，**不需要证书、不会 7 天掉签、永久有效**。
没装巨魔的话用 Sideloadly + 免费 Apple ID，代价是每 7 天重签。

### 为什么这个包能被巨魔接受

| 检查项 | 结果 |
|---|---|
| `MinimumOSVersion` | 16.0 |
| `LC_BUILD_VERSION` | `platform 2 (iOS)` / `minos 16.0` / `sdk 18.5` |
| 强链接 iOS 17 独有库 | 无（`strong=13 / weak=12`，全部弱链接） |
| Debug dylib | 无（Release 构建） |
| 代码签名 | ad-hoc（`_CodeSignature/CodeResources` 存在） |

CI 每次打包都会跑 `Scripts/check_ios16_links.py` 复核最后一项——一旦有人引入
SwiftData / TipKit / Symbols / Observation 的强链接，构建直接失败。

### 已知限制

- 没配任何 entitlement，**收不到 APNs 推送**（推送要真实证书 + 服务端）
- 无 App 图标与启动图（尚未加资源）
- 只读 MVP：不能回帖、没有已读位置同步
