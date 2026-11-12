import Foundation
import CryptoKit
import Darwin

/// Materializes only shipped runtime files; configuration and generated data stay private.
enum WorkspaceBootstrap {
    struct Manifest: Decodable {
        struct Entry: Decodable { let path: String; let sha256: String; let executable: Bool }
        let version: String
        let files: [Entry]
    }
    enum Failure: LocalizedError {
        case invalid(String)
        var errorDescription: String? { if case let .invalid(message) = self { return message }; return nil }
    }

    static func prepare(template: URL, directory: URL) throws {
        let fm = FileManager.default
        let bytes = try Data(contentsOf: template.appendingPathComponent("manifest.json"))
        let manifest = try JSONDecoder().decode(Manifest.self, from: bytes)
        guard !manifest.files.isEmpty else { throw Failure.invalid("安装包缺少运行资源，请重新安装。") }
        try fm.createDirectory(at: directory, withIntermediateDirectories: true, attributes: [.posixPermissions: 0o700])
        guard (try directory.resourceValues(forKeys: [.isSymbolicLinkKey])).isSymbolicLink != true else {
            throw Failure.invalid("工作目录不能是符号链接。")
        }
        let lockURL = directory.appendingPathComponent(".unfairplayed.lock")
        let fd = open(lockURL.path, O_CREAT | O_RDWR | O_NOFOLLOW, 0o600)
        guard fd >= 0 else { throw Failure.invalid("无法打开工作目录任务锁。") }
        defer { close(fd) }
        guard flock(fd, LOCK_EX | LOCK_NB) == 0 else {
            throw Failure.invalid("已有任务正在运行，请在任务完成后重新打开应用。")
        }
        defer { flock(fd, LOCK_UN) }
        let marker = directory.appendingPathComponent(".runtime-version")
        var entries: [(Manifest.Entry, URL, URL)] = []
        var seen = Set<String>()
        for entry in manifest.files {
            let parts = entry.path.components(separatedBy: "/")
            guard !entry.path.isEmpty, !parts.contains(where: { $0.isEmpty || $0 == "." || $0 == ".." || $0.contains("\\") }),
                  !parts.contains(where: { ["build", "payload", "debug-signing-build", ".unfairplayed.env", ".unfairplayed.lock"].contains($0) }),
                  seen.insert(entry.path).inserted else {
                throw Failure.invalid("安装包包含无效运行资源路径。")
            }
            var ancestor = directory
            for part in parts {
                ancestor.appendPathComponent(part)
                if let values = try? ancestor.resourceValues(forKeys: [.isSymbolicLinkKey]), values.isSymbolicLink == true {
                    throw Failure.invalid("工作目录资源不能经过符号链接。")
                }
            }
            entries.append((entry, template.appendingPathComponent(entry.path), directory.appendingPathComponent(entry.path)))
        }
        let config = directory.appendingPathComponent(".unfairplayed.env")
        if !fm.fileExists(atPath: config.path) {
            let identifier = "dev.unfairplayed.helper." + UUID().uuidString.replacingOccurrences(of: "-", with: "").lowercased()
            try ("UNFAIRPLAYED_BUNDLE_ID=" + identifier + "\n").write(to: config, atomically: true, encoding: .utf8)
            try fm.setAttributes([.posixPermissions: 0o600], ofItemAtPath: config.path)
        }
        if (try? String(contentsOf: marker, encoding: .utf8)) == manifest.version,
           entries.allSatisfy({ fm.fileExists(atPath: $0.2.path) }) { return }
        // Check all resources before replacing any file in the user's workspace.
        var verified: [(Manifest.Entry, Data, URL)] = []
        for (entry, source, target) in entries {
            let data = try Data(contentsOf: source)
            let digest = SHA256.hash(data: data).map { String(format: "%02x", $0) }.joined()
            guard digest == entry.sha256 else { throw Failure.invalid("安装包运行资源校验失败：" + entry.path) }
            verified.append((entry, data, target))
        }
        for (entry, data, target) in verified {
            try fm.createDirectory(at: target.deletingLastPathComponent(), withIntermediateDirectories: true, attributes: [.posixPermissions: 0o700])
            try data.write(to: target, options: .atomic)
            try fm.setAttributes([.posixPermissions: entry.executable ? 0o700 : 0o600], ofItemAtPath: target.path)
        }
        try manifest.version.write(to: marker, atomically: true, encoding: .utf8)
        try fm.setAttributes([.posixPermissions: 0o600], ofItemAtPath: marker.path)
    }
}
