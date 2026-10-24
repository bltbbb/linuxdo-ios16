import SwiftUI

/// 主题搜索。走 /search.json，结果复用列表行样式。
struct SearchView: View {

    @Environment(\.dismiss) private var dismiss

    @State private var term = ""
    @State private var results: [TopicSummary] = []
    @State private var loading = false
    @State private var errorMessage: String?

    var body: some View {
        NavigationStack {
            List(results) { topic in
                NavigationLink {
                    TopicDetailView(topic: topic)
                } label: {
                    TopicRow(topic: topic, users: [:])
                }
            }
            .listStyle(.plain)
            .searchable(text: $term, placement: .navigationBarDrawer(displayMode: .always), prompt: "搜索帖子、用户")
            .onSubmit(of: .search) {
                Task { await run() }
            }
            .navigationTitle("搜索")
            .navigationBarTitleDisplayMode(.inline)
            .toolbar {
                ToolbarItem(placement: .cancellationAction) {
                    Button("关闭") { dismiss() }
                }
            }
            .overlay {
                if loading {
                    ProgressView()
                } else if let message = errorMessage {
                    VStack(spacing: 10) {
                        Text(message)
                            .font(.footnote)
                            .foregroundColor(.secondary)
                            .multilineTextAlignment(.center)
                        Button("重试") { Task { await run() } }
                    }
                    .padding(24)
                } else if results.isEmpty {
                    Text(term.isEmpty ? "输入关键词后回车" : "没有结果")
                        .font(.footnote)
                        .foregroundColor(.secondary)
                }
            }
        }
    }

    private func run() async {
        let query = term.trimmingCharacters(in: .whitespacesAndNewlines)
        guard !query.isEmpty else { return }
        loading = true
        errorMessage = nil
        do {
            results = try await DiscourseClient.shared.search(term: query)
        } catch {
            errorMessage = error.localizedDescription
        }
        loading = false
    }
}
