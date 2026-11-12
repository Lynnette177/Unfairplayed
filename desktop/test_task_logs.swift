import Foundation

@main
struct TaskLogTests {
    static func main() throws {
        let root = FileManager.default.temporaryDirectory.appendingPathComponent("task-log-test-" + UUID().uuidString)
        defer { try? FileManager.default.removeItem(at: root) }
        let logs = root.appendingPathComponent("logs")
        let state = root.appendingPathComponent("state/log.json")
        let store = TaskLogStore(directory: logs, stateURL: state)
        try store.begin("失败任务", append: false, preservePrevious: false)
        let first = store.currentURL!
        let text = "START-OF-LOG\n" + String(repeating: "long build output\n", count: 20_000) + "FAILED-DETAIL\n"
        try store.append(text)
        let snapshot = root.appendingPathComponent("in-progress.log")
        try store.saveFull(to: snapshot)
        let interrupted = TaskLogStore(directory: logs, stateURL: state)
        precondition(interrupted.unfinished && interrupted.currentURL == first)
        precondition(interrupted.tail().contains("FAILED-DETAIL"))
        let snapshotText = try String(contentsOf: snapshot, encoding: .utf8)
        precondition(snapshotText == text)
        precondition(store.tail().utf8.count < text.utf8.count)
        try store.finish(1)
        let restored = TaskLogStore(directory: logs, stateURL: state)
        precondition(restored.unfinished && restored.currentURL == first)
        precondition(restored.tail().contains("FAILED-DETAIL"))
        try restored.begin("下一任务", append: false, preservePrevious: true)
        let second = restored.currentURL!
        precondition(first != second)
        try restored.append("RETRY-OUTPUT\n")
        let full = root.appendingPathComponent("saved-full.log")
        try restored.saveFull(to: full)
        let fullText = try String(contentsOf: full, encoding: .utf8)
        precondition(fullText == text + "RETRY-OUTPUT\n")
        let originalText = try String(contentsOf: first, encoding: .utf8)
        precondition(originalText == text)
        try restored.begin("继续导出", append: true, preservePrevious: true)
        precondition(restored.currentURL == second)
        try restored.append("EXPORT-DONE\n"); try restored.finish(0)
        let complete = TaskLogStore(directory: logs, stateURL: state)
        precondition(!complete.unfinished)
        try complete.begin("新的独立任务", append: false, preservePrevious: false)
        precondition(complete.currentURL != second && complete.tail().isEmpty)
        precondition(FileManager.default.fileExists(atPath: first.path))
        precondition(FileManager.default.fileExists(atPath: second.path))
        print("Full in-progress save, restart restoration, failed-log preservation and workflow append checks passed")
    }
}
