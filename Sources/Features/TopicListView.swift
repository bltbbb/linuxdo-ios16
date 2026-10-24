import SwiftUI

@MainActor
final class TopicListViewModel: ObservableObject {

    enum Feed: String, CaseIterable, Identifiable {
        case latest, top, unread

        var id: String { rawValue }

        var title: String {
            switch self {
            case .latest: return "最新"
            case .top: return "热门"
            case .unread: return "未读"
            }
        }

        var path: String {
            switch self {
            case .latest: return "/latest.json"
            case .top: return "/top.json"
            case .unread: return "/unread.json"
            }
        }
    }

    @Published private(set) var topics: [TopicSummary] = []
    @Published private(set) var users: [Int: DiscourseUser] = [:]
    @Published private(set) var isLoading = false
    @Published private(set) var hasMore = false
    @Published private(set) var feed: Feed = .latest
    @Published var errorMessage: String?

    private let client: DiscourseClient
    private let cache: CacheRepository
    private var page = 0

    init(client: DiscourseClient = .shared, cache: CacheRepository? = nil) {
        self.client = client
        self.cache = cache ?? .shared
    }

    func select(_ newFeed: Feed) async {
        guard newFeed != feed else { return }
        feed = newFeed
        page = 0
        topics = []
        users = [:]
        hasMore = false
        await load(reset: true)
    }

    func load(reset: Bool) async {
        if reset { page = 0 }
        isLoading = true
        defer { isLoading = false }

        let key = AppConfig.CacheKey.topicList(feed.rawValue, page: page)

        if reset, let cached = cache.cachedTopicList(key: key), !cached.isEmpty {
            topics = cached
            errorMessage = nil
        }

        do {
            let result = try await client.feed(path: feed.path, page: page)
            if reset {
                topics = result.topics
            } else {
                let known = Set(topics.map { $0.id })
                topics.append(contentsOf: result.topics.filter { !known.contains($0.id) })
            }
            users.merge(result.users) { _, new in new }
            hasMore = result.hasMore
            cache.storeTopicList(key: key, topics: result.topics)
            errorMessage = nil
        } catch {
            if topics.isEmpty {
                errorMessage = error.localizedDescription
            }
        }
    }

    func loadNextPageIfNeeded(current topic: TopicSummary) async {
        guard hasMore, !isLoading else { return }
        let threshold = max(topics.count - 5, 0)
        guard let index = topics.firstIndex(where: { $0.id == topic.id }), index >= threshold else { return }
        page += 1
        await load(reset: false)
    }
}

struct TopicListView: View {

    @EnvironmentObject private var auth: AuthStore
    @StateObject private var viewModel = TopicListViewModel()
    @State private var showsNetworkSettings = false

    var body: some View {
        NavigationStack {
            List {
                ForEach(viewModel.topics) { topic in
                    NavigationLink {
                        TopicDetailView(topic: topic)
                    } label: {
                        TopicRow(topic: topic, users: viewModel.users)
                    }
                    .task {
                        await viewModel.loadNextPageIfNeeded(current: topic)
                    }
                }
            }
            .listStyle(.plain)
            .safeAreaInset(edge: .top, spacing: 0) {
                Picker("分区", selection: Binding(
                    get: { viewModel.feed },
                    set: { newValue in Task { await viewModel.select(newValue) } }
                )) {
                    ForEach(TopicListViewModel.Feed.allCases) { feed in
                        Text(feed.title).tag(feed)
                    }
                }
                .pickerStyle(.segmented)
                .padding(.horizontal, 16)
                .padding(.vertical, 8)
                .background(.bar)
            }
            .refreshable {
                await viewModel.load(reset: true)
            }
            .navigationTitle(viewModel.feed.title)
            .navigationBarTitleDisplayMode(.inline)
            .toolbar {
                ToolbarItem(placement: .navigationBarTrailing) {
                    Menu {
                        Text(auth.displayName)
                        Button {
                            showsNetworkSettings = true
                        } label: {
                            Label("网络设置", systemImage: "network")
                        }
                        Button("退出登录", role: .destructive) {
                            Task { await auth.signOut() }
                        }
                    } label: {
                        Image(systemName: "person.crop.circle")
                    }
                }
            }
            .overlay {
                if viewModel.isLoading && viewModel.topics.isEmpty {
                    ProgressView("加载中…")
                } else if viewModel.topics.isEmpty, let message = viewModel.errorMessage {
                    VStack(spacing: 12) {
                        Text(message).font(.footnote).foregroundColor(.secondary)
                            .multilineTextAlignment(.center)
                        Button("重试") {
                            Task { await viewModel.load(reset: true) }
                        }
                    }
                    .padding(24)
                }
            }
            .task {
                if viewModel.topics.isEmpty {
                    await viewModel.load(reset: true)
                }
            }
            .sheet(isPresented: $showsNetworkSettings) {
                NetworkSettingsView()
                    .environmentObject(auth)
            }
        }
    }
}

struct TopicRow: View {

    let topic: TopicSummary
    let users: [Int: DiscourseUser]

    var body: some View {
        VStack(alignment: .leading, spacing: 6) {
            HStack(alignment: .top, spacing: 6) {
                if topic.pinned == true {
                    Image(systemName: "pin.fill")
                        .font(.caption2)
                        .foregroundColor(.orange)
                }
                Text(topic.title)
                    .font(.subheadline)
                    .lineLimit(3)
                    .multilineTextAlignment(.leading)
            }

            HStack(spacing: 10) {
                Label("\(topic.postsCount)", systemImage: "bubble.right")
                if let views = topic.views {
                    Label("\(views)", systemImage: "eye")
                }
                if topic.closed == true {
                    Image(systemName: "lock.fill")
                }
                if let firstPoster = topic.posters?.first?.userId, let user = users[firstPoster] {
                    Text(user.username)
                        .lineLimit(1)
                }
            }
            .font(.caption2)
            .foregroundColor(.secondary)
        }
        .padding(.vertical, 4)
    }
}
