import XCTest
@testable import LinuxDoClient

/// 新增模型（分类、搜索、点赞状态）的解码测试。
final class ModelsDecodingTests: XCTestCase {

    func testPostLikeStateIsDecoded() throws {
        let json = """
        {"id":11,"username":"neo","cooked":"<p>x</p>","post_number":1,
         "like_count":7,"actions_summary":[{"id":2,"count":7,"acted":true}]}
        """.data(using: .utf8)!
        let post = try JSONDecoder().decode(Post.self, from: json)
        XCTAssertTrue(post.isLiked)
        XCTAssertEqual(post.displayLikeCount, 7)
        XCTAssertEqual(post.postNumber, 1)
    }

    func testPostWithoutActionsSummaryIsNotLiked() throws {
        let json = """
        {"id":12,"username":"bob","cooked":"<p>y</p>","post_number":2}
        """.data(using: .utf8)!
        let post = try JSONDecoder().decode(Post.self, from: json)
        XCTAssertFalse(post.isLiked)
        XCTAssertEqual(post.displayLikeCount, 0)
    }

    func testPostActionNotActedIsNotLiked() throws {
        let json = """
        {"id":13,"username":"amy","cooked":"<p>z</p>","post_number":3,
         "actions_summary":[{"id":2,"count":3,"acted":false}]}
        """.data(using: .utf8)!
        let post = try JSONDecoder().decode(Post.self, from: json)
        XCTAssertFalse(post.isLiked)
        XCTAssertEqual(post.displayLikeCount, 3)
    }

    func testCategoryListIsDecoded() throws {
        let json = """
        {"category_list":{"categories":[
          {"id":4,"name":"开发调优","slug":"dev","color":"0088CC",
           "topic_count":42,"parent_category_id":null},
          {"id":9,"name":"搞七捻三","slug":"chat","topic_count":7,"parent_category_id":4}
        ]}}
        """.data(using: .utf8)!
        let response = try JSONDecoder().decode(CategoryListResponse.self, from: json)
        let categories = response.categoryList.categories
        XCTAssertEqual(categories.count, 2)
        XCTAssertEqual(categories[0].id, 4)
        XCTAssertEqual(categories[0].name, "开发调优")
        XCTAssertEqual(categories[0].topicCount, 42)
        XCTAssertNil(categories[0].parentCategoryId)
        XCTAssertEqual(categories[1].parentCategoryId, 4)
    }

    func testSearchResponseIsDecoded() throws {
        let json = """
        {"topics":[{"id":88,"title":"测试主题","posts_count":3,
          "category_id":4,"pinned":false,"closed":false}],
         "posts":[],"users":[]}
        """.data(using: .utf8)!
        let response = try JSONDecoder().decode(SearchResponse.self, from: json)
        XCTAssertEqual(response.topics?.count, 1)
        XCTAssertEqual(response.topics?.first?.title, "测试主题")
        XCTAssertEqual(response.topics?.first?.categoryId, 4)
    }

    func testEmptySearchResponseIsAllowed() throws {
        let json = "{}".data(using: .utf8)!
        let response = try JSONDecoder().decode(SearchResponse.self, from: json)
        XCTAssertNil(response.topics)
    }
}
