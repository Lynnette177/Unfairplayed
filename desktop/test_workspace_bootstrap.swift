import Foundation
import CryptoKit
import Darwin

@main
struct BootstrapTests {
    static func main() throws {
        if CommandLine.arguments.count == 3 {
            try WorkspaceBootstrap.prepare(template: URL(fileURLWithPath: CommandLine.arguments[1]), directory: URL(fileURLWithPath: CommandLine.arguments[2]))
            print("Standalone workspace prepared")
            return
        }
        let fm = FileManager.default
        let root = fm.temporaryDirectory.appendingPathComponent("bootstrap-test-" + UUID().uuidString)
        defer { try? fm.removeItem(at: root) }
        let template = root.appendingPathComponent("template")
        let workspace = root.appendingPathComponent("private workspace")
        try fm.createDirectory(at: template, withIntermediateDirectories: true)
        func manifest(_ version: String, _ path: String = "desktop/backend.py", _ text: String = "original") throws {
            let source = template.appendingPathComponent(path)
            try fm.createDirectory(at: source.deletingLastPathComponent(), withIntermediateDirectories: true)
            let bytes = Data(text.utf8); try bytes.write(to: source)
            let hash = SHA256.hash(data: bytes).map { String(format: "%02x", $0) }.joined()
            let value: [String: Any] = ["version": version, "files": [["path": path, "sha256": hash, "executable": false]]]
            try JSONSerialization.data(withJSONObject: value).write(to: template.appendingPathComponent("manifest.json"))
        }
        try manifest("one")
        try WorkspaceBootstrap.prepare(template: template, directory: workspace)
        let backend = workspace.appendingPathComponent("desktop/backend.py")
        let installed = try String(contentsOf: backend, encoding: .utf8)
        precondition(installed == "original")
        let config = workspace.appendingPathComponent(".unfairplayed.env")
        try "USER_SETTINGS".write(to: config, atomically: true, encoding: .utf8)
        let build = workspace.appendingPathComponent("iOS/build/keep")
        try fm.createDirectory(at: build.deletingLastPathComponent(), withIntermediateDirectories: true)
        try Data("USER_BUILD".utf8).write(to: build)
        try manifest("two", "desktop/backend.py", "updated")
        try WorkspaceBootstrap.prepare(template: template, directory: workspace)
        let updated = try String(contentsOf: backend, encoding: .utf8)
        let retainedConfig = try String(contentsOf: config, encoding: .utf8)
        let retainedBuild = try String(contentsOf: build, encoding: .utf8)
        precondition(updated == "updated" && retainedConfig == "USER_SETTINGS" && retainedBuild == "USER_BUILD")
        let lock = open(workspace.appendingPathComponent(".unfairplayed.lock").path, O_RDWR)
        precondition(lock >= 0 && flock(lock, LOCK_EX | LOCK_NB) == 0)
        var rejected = false
        do { try WorkspaceBootstrap.prepare(template: template, directory: workspace) } catch { rejected = true }
        precondition(rejected); flock(lock, LOCK_UN); close(lock)
        try manifest("bad", ".unfairplayed.env", "must-not-overwrite")
        rejected = false
        do { try WorkspaceBootstrap.prepare(template: template, directory: workspace) } catch { rejected = true }
        let stillPrivate = try String(contentsOf: config, encoding: .utf8)
        precondition(rejected && stillPrivate == "USER_SETTINGS")
        try manifest("three")
        try Data("tampered".utf8).write(to: template.appendingPathComponent("desktop/backend.py"))
        rejected = false
        do { try WorkspaceBootstrap.prepare(template: template, directory: root.appendingPathComponent("fresh")) } catch { rejected = true }
        precondition(rejected)
        try manifest("four")
        let link = root.appendingPathComponent("link")
        try fm.createSymbolicLink(at: link, withDestinationURL: root.appendingPathComponent("target"))
        try fm.createDirectory(at: root.appendingPathComponent("target"), withIntermediateDirectories: true)
        rejected = false
        do { try WorkspaceBootstrap.prepare(template: template, directory: link) } catch { rejected = true }
        precondition(rejected)
        print("Bootstrap, private-data preservation, hash, task lock and path checks passed")
    }
}
