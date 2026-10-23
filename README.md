# LinuxDoClient —— iOS 16 原生客户端（重写）

[![iOS Build](https://github.com/bltbbb/linuxdo-ios16/actions/workflows/ios-build.yml/badge.svg)](https://github.com/bltbbb/linuxdo-ios16/actions/workflows/ios-build.yml)

目标：在 **iOS 16.3** 上获得 LINUX DO 的原生使用体验。

静态分析表明，原版 `org.linuxdo.community-1.0.2` 强依赖 SwiftData、Observation 等新系统接口，
无法仅靠修改最低版本号支持 iOS 16.3。本工程使用 iOS 16 可用接口重新实现客户端。
论坛基于 Discourse，但站点可能扩展认证协议，不能将上游文档视为全部站点行为。

## 浏览器授权登录修复

原实现将授权入口写成 `POST /user-api-key/new`，随后尝试从 HTML 提取 payload，
再跳转到 `/user-api-key/authorize`。这与标准 Discourse 的经典 User API Key 流程不符：

1. 客户端生成 RSA 密钥对、随机 nonce 和每个安装实例独立的 client ID。
2. 系统认证浏览器 `ASWebAuthenticationSession` 打开 `GET /user-api-key/new`，查询参数携带公钥、nonce、权限和回调地址。
3. 用户在网站登录并确认授权，由网页向 `POST /user-api-key` 提交。
4. 系统认证会话接收 `discourse://auth_redirect?payload=...`，客户端解密 payload 并校验其中的 nonce。
5. 使用返回的用户密钥查询 `/session/current.json`，成功后保存密钥并进入列表。

当前主流程申请 `read,session_info`，不申请依赖推送地址的 `notifications`。
公钥中的 `+` 编码为 `%2B`，避免服务器按表单规则将其解释成空格。
认证会话直接接收回调，不使用 `UIApplication.open` 加自定义 URL 注册来争抢回调。
私钥和待验证 nonce 只在内存保留，授权中途应用进程被系统终止后需要重新发起。

日志含义：

- `/session/current.json` 的匿名 404 是未登录状态，不表示该接口不存在。
- `/session/csrf.json` 返回 200 只表示取到了防跨站请求令牌，不表示登录成功。
- 浏览器授权入口不需要先从原生网络会话取 CSRF，也不会再由客户端 POST 到 `/user-api-key/new`。
- 认证端点正文不写入诊断日志；授权结果解码错误也不输出解密后的内容。

站点仍需允许用户 API Key、所申请权限和回调地址。`discourse://auth_redirect` 是 Discourse 默认允许的地址，
并不代表已经验证 linux.do 当前部署的允许列表。若网页提示回调不允许或用户无权授权，需要查看具体站点提示。
系统认证浏览器与原生 URLSession 不共享全部浏览器状态；获得用户密钥也不保证绕过站点的 Cloudflare 校验。

回归用例位于 `Tests/UserApiKeyFlowTests.swift`，覆盖公钥查询参数编码、正确回调、nonce 不匹配或缺失、
错误回调地址、重复 payload 和错误私钥。此次仅进行了静态检查，按要求未执行本地构建、测试或真机登录。
原版 IPA 中存在 `/login/device/code` 和 `/login/oauth/access_token` 字符串，
但备用设备码实现的请求字段及响应结构尚未核实，本次没有将其当作已经可用的登录方案。

真机验收顺序：打开“浏览器授权登录” → 网站登录和确认授权 → 自动返回应用 → 当前用户查询成功 → 进入主题列表。
还需检查取消后重新授权、重启恢复，以及权限被撤销后的行为。

依据：[Discourse 授权规范](https://meta.discourse.org/t/user-api-keys-specification/48536)、
[上游路由](https://github.com/discourse/discourse/blob/main/config/routes.rb)、
[匿名会话处理](https://github.com/discourse/discourse/blob/main/app/controllers/session_controller.rb)、
[苹果系统认证会话](https://developer.apple.com/documentation/authenticationservices/aswebauthenticationsession)。

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
| User API Key + Device 授权流 | 系统浏览器 User API Key 授权；另保留网页登录备用入口 |
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

零第三方依赖。使用 Foundation / SwiftUI / UIKit / WebKit / CoreData / Security / AuthenticationServices。

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

- 系统浏览器 User API Key 授权链路（此次修正，待真机验证）
- Cookie 会话登录（含 TOTP 二次验证分支）
- 冷启动会话恢复（`/session/current.json`）
- 列表：最新 / 热门 / 未读，分页加载，下拉刷新
- 详情：帖子流首屏 + 分批续读，正文 HTML 原生容器内渲染
- 离线缓存：列表与站点信息落 Core Data，TTL 10 分钟，先出缓存再刷新
- 草稿：本地 Core Data 草稿（`saveDraft` / `drafts` / `deleteDraft`）
- Cloudflare 403 与常见错误的中文提示
- 网页登录：内嵌 WKWebView 通过 Cloudflare 挑战，cookie 自动同步给原生请求

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
