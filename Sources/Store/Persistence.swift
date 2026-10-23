import CoreData
import Foundation

// MARK: - 实体（对应原 app 的 SwiftData 模型）

/// 对应原 app `SiteCacheEntity`：站点 JSON、缓存键、刷新时间。
@objc(SiteCacheEntity)
public final class SiteCacheEntity: NSManagedObject {
    @NSManaged public var key: String?
    @NSManaged public var payload: Data?
    @NSManaged public var refreshedAt: Date?
}

/// 对应原 app `TopicListCacheEntity`：主题 JSON、分页地址、时间戳。
@objc(TopicListCacheEntity)
public final class TopicListCacheEntity: NSManagedObject {
    @NSManaged public var key: String?
    @NSManaged public var payload: Data?
    @NSManaged public var pageURL: String?
    @NSManaged public var fetchedAt: Date?
}

/// 对应原 app `DraftEntity`：账号范围、主题、标题、内容、分类、标签、草稿类型、同步序列。
@objc(DraftEntity)
public final class DraftEntity: NSManagedObject {
    @NSManaged public var draftKey: String?
    @NSManaged public var accountScope: String?
    @NSManaged public var topicID: Int64
    @NSManaged public var title: String?
    @NSManaged public var body: String?
    @NSManaged public var categoryID: Int64
    @NSManaged public var tagsJSON: Data?
    @NSManaged public var draftType: String?
    @NSManaged public var syncSequence: Int64
    @NSManaged public var updatedAt: Date?
}

// MARK: - 栈

final class PersistenceController {

    static let shared = PersistenceController()

    let container: NSPersistentContainer

    init(inMemory: Bool = false) {
        let model = PersistenceController.makeModel()
        container = NSPersistentContainer(name: "LinuxDoCache", managedObjectModel: model)

        if inMemory {
            let description = NSPersistentStoreDescription()
            description.type = NSInMemoryStoreType
            container.persistentStoreDescriptions = [description]
        }

        container.loadPersistentStores { _, error in
            if let error = error {
                NSLog("[Persistence] 存储加载失败：\(error.localizedDescription)")
            }
        }
        container.viewContext.automaticallyMergesChangesFromParent = true
        container.viewContext.mergePolicy = NSMergeByPropertyObjectTrumpMergePolicy
        container.viewContext.undoManager = nil
    }

    // MARK: - 手工构建模型（避免依赖 .xcdatamodeld 二进制资源）

    private static func attr(
        _ name: String,
        _ type: NSAttributeType,
        optional: Bool = true,
        defaultValue: Any? = nil
    ) -> NSAttributeDescription {
        let a = NSAttributeDescription()
        a.name = name
        a.attributeType = type
        a.isOptional = optional
        if let defaultValue { a.defaultValue = defaultValue }
        return a
    }

    private static func entity(
        _ name: String,
        _ properties: [NSAttributeDescription],
        uniqueBy: [String]? = nil
    ) -> NSEntityDescription {
        let e = NSEntityDescription()
        e.name = name
        e.managedObjectClassName = name
        e.properties = properties
        if let uniqueBy { e.uniquenessConstraints = [uniqueBy] }
        return e
    }

    static func makeModel() -> NSManagedObjectModel {
        let model = NSManagedObjectModel()

        let site = entity("SiteCacheEntity", [
            attr("key", .stringAttributeType, optional: false),
            attr("payload", .binaryDataAttributeType),
            attr("refreshedAt", .dateAttributeType)
        ], uniqueBy: ["key"])

        let topicList = entity("TopicListCacheEntity", [
            attr("key", .stringAttributeType, optional: false),
            attr("payload", .binaryDataAttributeType),
            attr("pageURL", .stringAttributeType),
            attr("fetchedAt", .dateAttributeType)
        ], uniqueBy: ["key"])

        let draft = entity("DraftEntity", [
            attr("draftKey", .stringAttributeType, optional: false),
            attr("accountScope", .stringAttributeType),
            attr("topicID", .integer64AttributeType, optional: false, defaultValue: 0),
            attr("title", .stringAttributeType),
            attr("body", .stringAttributeType),
            attr("categoryID", .integer64AttributeType, optional: false, defaultValue: 0),
            attr("tagsJSON", .binaryDataAttributeType),
            attr("draftType", .stringAttributeType),
            attr("syncSequence", .integer64AttributeType, optional: false, defaultValue: 0),
            attr("updatedAt", .dateAttributeType)
        ], uniqueBy: ["draftKey"])

        model.entities = [site, topicList, draft]
        return model
    }
}

// MARK: - 读写封装

@MainActor
final class CacheRepository {

    static let shared = CacheRepository()

    private let context: NSManagedObjectContext
    private let encoder = JSONEncoder()
    private let decoder = JSONDecoder()

    init(context: NSManagedObjectContext = PersistenceController.shared.container.viewContext) {
        self.context = context
    }

    private func persist() {
        guard context.hasChanges else { return }
        do {
            try context.save()
        } catch {
            NSLog("[Cache] 保存失败：\(error.localizedDescription)")
            context.rollback()
        }
    }

    // MARK: 主题列表

    func storeTopicList(key: String, topics: [TopicSummary], pageURL: String? = nil) {
        do {
            let data = try encoder.encode(topics)
            let record = try fetchTopicList(key: key) ?? TopicListCacheEntity(context: context)
            record.key = key
            record.payload = data
            record.pageURL = pageURL
            record.fetchedAt = Date()
            persist()
        } catch {
            NSLog("[Cache] 写入主题列表失败：\(error.localizedDescription)")
        }
    }

    func cachedTopicList(key: String, maxAge: TimeInterval = AppConfig.cacheTTL) -> [TopicSummary]? {
        guard let record = try? fetchTopicList(key: key), let data = record.payload else { return nil }
        if let fetchedAt = record.fetchedAt, Date().timeIntervalSince(fetchedAt) > maxAge { return nil }
        return try? decoder.decode([TopicSummary].self, from: data)
    }

    private func fetchTopicList(key: String) throws -> TopicListCacheEntity? {
        let request = NSFetchRequest<TopicListCacheEntity>(entityName: "TopicListCacheEntity")
        request.predicate = NSPredicate(format: "key == %@", key)
        request.fetchLimit = 1
        return try context.fetch(request).first
    }

    // MARK: 站点

    func storeSiteInfo(_ data: Data, key: String = AppConfig.CacheKey.site) {
        do {
            let record = try fetchSite(key: key) ?? SiteCacheEntity(context: context)
            record.key = key
            record.payload = data
            record.refreshedAt = Date()
            persist()
        } catch {
            NSLog("[Cache] 写入站点信息失败：\(error.localizedDescription)")
        }
    }

    func cachedSiteInfo(key: String = AppConfig.CacheKey.site) -> Data? {
        (try? fetchSite(key: key))?.payload
    }

    private func fetchSite(key: String) throws -> SiteCacheEntity? {
        let request = NSFetchRequest<SiteCacheEntity>(entityName: "SiteCacheEntity")
        request.predicate = NSPredicate(format: "key == %@", key)
        request.fetchLimit = 1
        return try context.fetch(request).first
    }

    // MARK: 草稿

    @discardableResult
    func saveDraft(
        title: String,
        body: String,
        categoryID: Int,
        tags: [String],
        draftType: String,
        accountScope: String = "default",
        topicID: Int = 0
    ) -> Bool {
        let key = "draft.\(accountScope).\(draftType).\(topicID)"
        do {
            let record = try fetchDraft(key: key) ?? DraftEntity(context: context)
            record.draftKey = key
            record.accountScope = accountScope
            record.topicID = Int64(topicID)
            record.title = title
            record.body = body
            record.categoryID = Int64(categoryID)
            record.tagsJSON = try? encoder.encode(tags)
            record.draftType = draftType
            record.syncSequence = (record.syncSequence) + 1
            record.updatedAt = Date()
            persist()
            return true
        } catch {
            NSLog("[Cache] 保存草稿失败：\(error.localizedDescription)")
            return false
        }
    }

    func drafts(accountScope: String = "default") -> [DraftEntity] {
        let request = NSFetchRequest<DraftEntity>(entityName: "DraftEntity")
        request.predicate = NSPredicate(format: "accountScope == %@", accountScope)
        request.sortDescriptors = [NSSortDescriptor(key: "updatedAt", ascending: false)]
        return (try? context.fetch(request)) ?? []
    }

    func deleteDraft(_ draft: DraftEntity) {
        context.delete(draft)
        persist()
    }

    private func fetchDraft(key: String) throws -> DraftEntity? {
        let request = NSFetchRequest<DraftEntity>(entityName: "DraftEntity")
        request.predicate = NSPredicate(format: "draftKey == %@", key)
        request.fetchLimit = 1
        return try context.fetch(request).first
    }
}
