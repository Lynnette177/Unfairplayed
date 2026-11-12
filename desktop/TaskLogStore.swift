import Foundation

// Full task output lives on disk. The UI may retain only a tail for responsiveness.
final class TaskLogStore {
    private struct State: Codable { let path: String; let unfinished: Bool }
    let directory: URL
    private let stateURL: URL
    private var handle: FileHandle?
    private(set) var currentURL: URL?
    private(set) var unfinished = false

    init(directory: URL, stateURL: URL) {
        self.directory = directory
        self.stateURL = stateURL
        if let bytes = try? Data(contentsOf: stateURL), let state = try? JSONDecoder().decode(State.self, from: bytes) {
            let candidate = URL(fileURLWithPath: state.path)
            if candidate.deletingLastPathComponent().resolvingSymlinksInPath() == directory.resolvingSymlinksInPath(),
               FileManager.default.fileExists(atPath: candidate.path) {
                currentURL = candidate; unfinished = state.unfinished
            }
        }
    }

    deinit { try? handle?.close() }

    private func saveState() throws {
        guard let currentURL else { return }
        try FileManager.default.createDirectory(at: stateURL.deletingLastPathComponent(), withIntermediateDirectories: true, attributes: [.posixPermissions: 0o700])
        try JSONEncoder().encode(State(path: currentURL.path, unfinished: unfinished)).write(to: stateURL, options: .atomic)
        try FileManager.default.setAttributes([.posixPermissions: 0o600], ofItemAtPath: stateURL.path)
    }

    func begin(_ title: String, append: Bool, preservePrevious: Bool) throws {
        try handle?.synchronize(); try handle?.close(); handle = nil
        let previous = currentURL
        try FileManager.default.createDirectory(at: directory, withIntermediateDirectories: true, attributes: [.posixPermissions: 0o700])
        if !append || previous == nil || !FileManager.default.fileExists(atPath: previous!.path) {
            let formatter = DateFormatter(); formatter.locale = Locale(identifier: "en_US_POSIX")
            formatter.dateFormat = "yyyyMMdd-HHmmss"
            let safe = title.map { $0.isLetter || $0.isNumber || $0 == "-" ? $0 : "-" }
            let filename = formatter.string(from: Date()) + "-" + String(safe.prefix(48)) + "-" + UUID().uuidString.prefix(8) + ".log"
            let next = directory.appendingPathComponent(filename)
            if preservePrevious, let previous, FileManager.default.fileExists(atPath: previous.path) {
                try FileManager.default.copyItem(at: previous, to: next)
            } else { try Data().write(to: next, options: .atomic) }
            currentURL = next
        }
        guard let currentURL else { return }
        try FileManager.default.setAttributes([.posixPermissions: 0o600], ofItemAtPath: currentURL.path)
        handle = try FileHandle(forWritingTo: currentURL)
        try handle?.seekToEnd()
        unfinished = true
        try saveState()
    }

    func append(_ value: String) throws {
        guard let handle else { return }
        try handle.write(contentsOf: Data(value.utf8))
    }

    func finish(_ code: Int32) throws {
        try handle?.synchronize()
        unfinished = code != 0
        try saveState()
    }

    func tail(limit: UInt64 = 150_000) -> String {
        guard let currentURL, let input = try? FileHandle(forReadingFrom: currentURL) else { return "" }
        defer { try? input.close() }
        do {
            let size = try input.seekToEnd()
            try input.seek(toOffset: size > limit ? size - limit : 0)
            return String(decoding: try input.readToEnd() ?? Data(), as: UTF8.self)
        } catch { return "" }
    }

    func saveFull(to destination: URL) throws {
        guard let currentURL else { return }
        if destination.resolvingSymlinksInPath() == currentURL.resolvingSymlinksInPath() { return }
        try handle?.synchronize()
        // Called on the same actor as append, so this is a complete snapshot of
        // all output received so far, even while the child task is still running.
        try Data(contentsOf: currentURL).write(to: destination, options: .atomic)
        try FileManager.default.setAttributes([.posixPermissions: 0o600], ofItemAtPath: destination.path)
    }
}
