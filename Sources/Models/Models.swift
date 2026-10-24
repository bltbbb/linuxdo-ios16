import Foundation

// MARK: - 用户

struct DiscourseUser: Codable, Identifiable, Hashable {
    let id: Int
    let username: String
    let name: String?
    let avatarTemplate: String?

    enum CodingKeys: String, CodingKey {
        case id, username, name
        case avatarTemplate = "avatar_template"
    }

    func avatarURL(size: Int = 96) -> URL? {
        guard let tpl = avatarTemplate else { return nil }
        let path = tpl.replacingOccurrences(of: "{size}", with: "\(size)")
        if path.hasPrefix("http") { return URL(string: path) }
        return URL(string: AppConfig.baseURL.absoluteString + path)
    }
}

// MARK: - 主题列表

struct TopicListResponse: Decodable {
    let users: [DiscourseUser]?
    let topicList: TopicListPayload

    enum CodingKeys: String, CodingKey {
        case users
        case topicList = "topic_list"
    }
}

struct TopicListPayload: Decodable {
    let topics: [TopicSummary]
    let moreTopicsUrl: String?
    let perPage: Int?

    enum CodingKeys: String, CodingKey {
        case topics
        case moreTopicsUrl = "more_topics_url"
        case perPage = "per_page"
    }
}

struct TopicPoster: Codable, Hashable {
    let userId: Int?
    let description: String?

    enum CodingKeys: String, CodingKey {
        case userId = "user_id"
        case description
    }
}

struct TopicSummary: Codable, Identifiable, Hashable {
    let id: Int
    let title: String
    let slug: String?
    let postsCount: Int
    let replyCount: Int?
    let views: Int?
    let likeCount: Int?
    let categoryId: Int?
    let createdAt: String?
    let bumpedAt: String?
    let pinned: Bool?
    let closed: Bool?
    let posters: [TopicPoster]?

    enum CodingKeys: String, CodingKey {
        case id, title, slug, posters, views, pinned, closed
        case postsCount = "posts_count"
        case replyCount = "reply_count"
        case likeCount = "like_count"
        case categoryId = "category_id"
        case createdAt = "created_at"
        case bumpedAt = "bumped_at"
    }
}

// MARK: - 主题详情

struct TopicDetailResponse: Decodable {
    let id: Int
    let title: String
    let postsCount: Int
    let views: Int?
    let categoryId: Int?
    let tags: [TagValue]?
    let postStream: PostStream

    enum CodingKeys: String, CodingKey {
        case id, title, tags, views
        case postsCount = "posts_count"
        case categoryId = "category_id"
        case postStream = "post_stream"
    }

    /// 只取标签名，屏蔽不同站点的结构差异。
    var tagNames: [String] {
        (tags ?? []).map(\.name).filter { !$0.isEmpty }
    }
}

struct PostStream: Decodable {
    let posts: [Post]
    let stream: [Int]?
}

struct Post: Codable, Identifiable, Hashable {
    let id: Int
    let username: String
    let name: String?
    let cooked: String
    let createdAt: String?
    let postNumber: Int
    let avatarTemplate: String?

    enum CodingKeys: String, CodingKey {
        case id, username, name, cooked
        case createdAt = "created_at"
        case postNumber = "post_number"
        case avatarTemplate = "avatar_template"
    }

    func avatarURL(size: Int = 72) -> URL? {
        guard let tpl = avatarTemplate else { return nil }
        let path = tpl.replacingOccurrences(of: "{size}", with: "\(size)")
        if path.hasPrefix("http") { return URL(string: path) }
        return URL(string: AppConfig.baseURL.absoluteString + path)
    }
}

// MARK: - 会话

struct SessionCurrentResponse: Decodable {
    let currentUser: CurrentUser?

    enum CodingKeys: String, CodingKey {
        case currentUser = "current_user"
    }
}

struct CurrentUser: Codable, Identifiable, Hashable {
    let id: Int
    let username: String
    let name: String?
    let admin: Bool?
    let moderator: Bool?
    let trustLevel: Int?

    enum CodingKeys: String, CodingKey {
        case id, username, name, admin, moderator
        case trustLevel = "trust_level"
    }
}

struct CSRFResponse: Decodable {
    let csrf: String
}

/// `/t/{id}/posts.json` 的响应外层包裹。
struct PostStreamResponse: Decodable {
    let postStream: PostStream

    enum CodingKeys: String, CodingKey {
        case postStream = "post_stream"
    }
}

/// Discourse 的 `tags` 在部分站点/插件下返回对象数组
/// （`{"id":1,"name":"tag","slug":"tag"}`），而不是字符串数组。两种都接受。
struct TagValue: Decodable, Hashable {
    let name: String

    private struct TagObject: Decodable {
        let name: String?
        let slug: String?
    }

    init(from decoder: Decoder) throws {
        let single = try decoder.singleValueContainer()
        if let text = try? single.decode(String.self) {
            name = text
            return
        }
        if let object = try? single.decode(TagObject.self) {
            name = object.name ?? object.slug ?? ""
            return
        }
        name = ""
    }
}

// MARK: - 分类

struct CategoryListResponse: Decodable {
    let categoryList: CategoryList

    enum CodingKeys: String, CodingKey {
        case categoryList = "category_list"
    }
}

struct CategoryList: Decodable {
    let categories: [Category]
}

struct Category: Codable, Identifiable, Hashable {
    let id: Int
    let name: String
    let slug: String?
    let color: String?
    let topicCount: Int?
    let parentCategoryId: Int?

    enum CodingKeys: String, CodingKey {
        case id, name, slug, color
        case topicCount = "topic_count"
        case parentCategoryId = "parent_category_id"
    }
}

/// /search.json 的响应：只取主题列表，足够列表展示。
struct SearchResponse: Decodable {
    let topics: [TopicSummary]?
}
