import SwiftUI

@MainActor
final class TopicDetailViewModel: ObservableObject {

    let topicID: Int
    let fallbackTitle: String

    @Published private(set) var detail: TopicDetailResponse?
    @Published private(set) var posts: [Post] = []
    @Published private(set) var isLoading = false
    @Published private(set) var isLoadingMore = false
    @Published var errorMessage: String?

    private let client: DiscourseClient

    init(topicID: Int, fallbackTitle: String, client: DiscourseClient = .shared) {
        self.topicID = topicID
        self.fallbackTitle = fallbackTitle
        self.client = client
    }

    var title: String {
        detail?.title ?? fallbackTitle
    }

    var remainingCount: Int {
        guard let stream = detail?.postStream.stream else { return 0 }
        let loaded = Set(posts.map { $0.id })
        return stream.filter { !loaded.contains($0) }.count
    }

    func loadIfNeeded() async {
        guard posts.isEmpty, !isLoading else { return }
        isLoading = true
        errorMessage = nil
        defer { isLoading = false }

        do {
            let response = try await client.topicDetail(id: topicID)
            detail = response
            posts = response.postStream.posts.sorted { $0.postNumber < $1.postNumber }
        } catch {
            errorMessage = error.localizedDescription
        }
    }

    func loadNextBatch() async {
        guard !isLoadingMore, let stream = detail?.postStream.stream else { return }
        let loaded = Set(posts.map { $0.id })
        let pending = stream.filter { !loaded.contains($0) }
        guard !pending.isEmpty else { return }

        isLoadingMore = true
        defer { isLoadingMore = false }

        do {
            let batch = Array(pending.prefix(20))
            let more = try await client.posts(inTopic: topicID, ids: batch)
            let existing = Set(posts.map { $0.id })
            posts.append(contentsOf: more.filter { !existing.contains($0.id) })
            posts.sort { $0.postNumber < $1.postNumber }
            errorMessage = nil
        } catch {
            errorMessage = error.localizedDescription
        }
    }
}

struct TopicDetailView: View {

    @StateObject private var viewModel: TopicDetailViewModel
    @State private var heights: [Int: CGFloat] = [:]

    init(topic: TopicSummary) {
        _viewModel = StateObject(
            wrappedValue: TopicDetailViewModel(topicID: topic.id, fallbackTitle: topic.title)
        )
    }

    var body: some View {
        ScrollView {
            LazyVStack(alignment: .leading, spacing: 0) {
                header

                ForEach(viewModel.posts) { post in
                    postCard(post)
                }

                if viewModel.remainingCount > 0 {
                    Button {
                        Task { await viewModel.loadNextBatch() }
                    } label: {
                        HStack {
                            Spacer()
                            if viewModel.isLoadingMore {
                                ProgressView()
                            } else {
                                Text("加载更多（剩余 \(viewModel.remainingCount)）")
                            }
                            Spacer()
                        }
                    }
                    .padding(.vertical, 16)
                }
            }
            .padding(.horizontal, 16)
        }
        .navigationTitle(viewModel.title)
        .navigationBarTitleDisplayMode(.inline)
        .task {
            await viewModel.loadIfNeeded()
        }
        .overlay {
            if viewModel.isLoading {
                ProgressView("加载中…")
            } else if viewModel.posts.isEmpty, let message = viewModel.errorMessage {
                Text(message)
                    .font(.footnote)
                    .foregroundColor(.secondary)
                    .multilineTextAlignment(.center)
                    .padding(24)
            }
        }
    }

    private var header: some View {
        VStack(alignment: .leading, spacing: 6) {
            Text(viewModel.title)
                .font(.title3).bold()
                .fixedSize(horizontal: false, vertical: true)

            HStack(spacing: 10) {
                if let count = viewModel.detail?.postsCount {
                    Label("\(count)", systemImage: "bubble.right")
                }
                if let views = viewModel.detail?.views {
                    Label("\(views)", systemImage: "eye")
                }
                if let tags = viewModel.detail?.tagNames, !tags.isEmpty {
                    Text(tags.prefix(3).map { "#\($0)" }.joined(separator: " "))
                }
            }
            .font(.caption2)
            .foregroundColor(.secondary)

            Divider().padding(.top, 4)
        }
        .padding(.vertical, 8)
    }

    private func postCard(_ post: Post) -> some View {
        VStack(alignment: .leading, spacing: 8) {
            HStack(spacing: 8) {
                AsyncImage(url: post.avatarURL()) { phase in
                    switch phase {
                    case .success(let image):
                        image.resizable().aspectRatio(contentMode: .fill)
                    default:
                        Circle().fill(Color.secondary.opacity(0.2))
                    }
                }
                .frame(width: 28, height: 28)
                .clipShape(Circle())

                VStack(alignment: .leading, spacing: 1) {
                    Text(displayName(post))
                        .font(.subheadline).bold()
                    Text("#\(post.postNumber) · \(post.username)")
                        .font(.caption2)
                        .foregroundColor(.secondary)
                }

                Spacer()
            }

            RichTextWebView(
                html: post.cooked,
                height: Binding(
                    get: { heights[post.id] ?? 120 },
                    set: { heights[post.id] = $0 }
                )
            )
            .frame(height: heights[post.id] ?? 120)

            Divider()
        }
        .padding(.vertical, 8)
    }

    private func displayName(_ post: Post) -> String {
        if let name = post.name, !name.isEmpty { return name }
        return post.username
    }
}
