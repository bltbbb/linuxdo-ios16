# LinuxDoClient —— iOS 16 原生客户端（重写）

[![iOS Build](https://github.com/bltbbb/linuxdo-ios16/actions/workflows/ios-build.yml/badge.svg)](https://github.com/bltbbb/linuxdo-ios16/actions/workflows/ios-build.yml)

目标：在 **iOS 16.3** 上获得 LINUX DO 的原生使用体验。

前提结论（已用静态分析证实）：`org.linuxdo.community-1.0.2` 这个包**无法**降版本运行。
它强加载 SwiftData / TipKit / Symbols / libswiftObservation（均为 iOS 17+），
持久化 100% 建立在 SwiftData 上（`NSManagedObject = 0`、`sqlite = 0`），
且 Swift 静态分发让这些调用点无法用 stub 替换。
但它的后端是**标准 Discourse REST API**（`https://linux.do`），没有任何私有协议，
因此可以另写一个客户端 —— 就是这个工程。

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
| User API Key + Device 授权流 | 网页登录（WKWebView 过 Cloudflare）→ cookie 复用 |
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

零第三方依赖。仅用 Foundation / SwiftUI / WebKit / CoreData。

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
- **Cloudflare 校验（已实测确认）**：从数据中心网络请求 `https://linux.do/latest.json`
  返回 `403` + `Cf-Mitigated: challenge`。站点启用了交互式 JS 挑战，纯 `URLSession`
  请求无法通过。因此登录必须走 `WebLoginView`（WKWebView 完成校验，再把 cookie
  灌进 `HTTPCookieStorage` 供原生请求复用）。手机蜂窝网络下是否同样触发挑战，
  取决于站点策略，需真机确认。
- **直接登录的可用性**：`/session` + CSRF 表单登录仅在未触发挑战时可用。
  若站点强制 passkey / 社交登录，需要实现 Discourse User API Key
  （device_code 授权，原 app 用的正是这条）。
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
