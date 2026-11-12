import SwiftUI
import AppKit
import UniformTypeIdentifiers

let brandTint = Color(red: 0.12, green: 0.43, blue: 0.37)

struct StoreApp: Decodable, Identifiable, Hashable {
    let id: String
    let bundle: String
    let name: String
    let artist: String
    let version: String
    let price: String
    let artwork: String
    let storeURL: String
}

struct LocalIPA: Decodable, Identifiable {
    let id: String
    let path: String
    let name: String
    let bundle: String
    let version: String
    let size: Int64
    let modified: Double
    let icon: String
    let kind: String
    let state: String
    let error: String
    let partial: Bool
    let signed: Bool
    var reusable: Bool { error.isEmpty && !partial && state == "decrypted" }
    var badge: String {
        if !error.isEmpty { return "读取失败" }
        if partial { return "未完成" }
        if kind == "decrypted" { return signed ? "已重签" : "已脱壳" }
        return state == "encrypted" ? "已下载" : "待校验"
    }
}

struct IPAArtwork: View {
    let item: LocalIPA
    var body: some View {
        Group {
            if !item.icon.isEmpty, let icon = NSImage(contentsOfFile: item.icon) {
                Image(nsImage: icon).resizable().scaledToFit()
            } else {
                ZStack {
                    brandTint.opacity(0.1)
                    Text(String(item.name.prefix(1))).font(.title2.weight(.medium)).foregroundStyle(brandTint)
                }
            }
        }.frame(width: 54, height: 54).clipShape(RoundedRectangle(cornerRadius: 12))
    }
}

struct Phone: Decodable, Identifiable {
    let id: String
    let name: String
    let state: String
    let wired: Bool?
    var available: Bool { state != "unavailable" && state != "unknown" }
}

struct USBStatus: Decodable { let wiredDevices: [String] }

struct DevelopmentTeam: Decodable, Identifiable {
    let id: String
    let name: String
    let source: String
}

struct SigningOption: Decodable, Identifiable {
    let id: String
    let name: String
    let team: String
    let source: String
    let devices: [String]
    let allDevices: Bool
    let expires: String
    let certificateExpires: String
    let debuggable: Bool
    let profileName: String?

    func reason(device: String, debug: Bool) -> String {
        if source == "xcode" { return "" }
        let formatter = ISO8601DateFormatter()
        for value in [expires, certificateExpires] {
            guard let date = formatter.date(from: value) else { return "无法确认有效期" }
            if date <= Date() { return "证书或描述文件已过期" }
        }
        if device.isEmpty { return "请先连接并选择设备" }
        if !allDevices && !devices.contains(device) { return "不包含当前设备 UDID" }
        if debug && !debuggable { return "描述文件未授权调试权限" }
        return ""
    }
    var label: String {
        source == "xcode" ? "\(name) · \(team)" : "\(name) · \(profileName ?? team)"
    }
}

struct FridaEnvironment: Decodable, Identifiable {
    let id: String
    let name: String
    let available: Bool
}

struct BundleHistory: Decodable {
    let bundle: String
    let name: String
}

struct LocalAppID: Decodable, Identifiable {
    var id: String { team + ":" + bundle }
    let team: String
    let bundle: String
    let name: String
    let expires: String
    let devices: [String]
    let allDevices: Bool
}

struct BundleReady: Decodable { let bundle: String; let name: String }
struct BundleAction: Decodable { let reason: String; let message: String; let bundle: String? }

struct BundleIDField: View {
    @Binding var text: String
    let suggestions: [String]
    var body: some View {
        HStack(spacing: 4) {
            TextField("输入或选择最近使用的 Bundle ID", text: $text).textFieldStyle(.plain)
            Menu {
                ForEach(suggestions, id: \.self) { id in Button(id) { text = id } }
            } label: { Image(systemName: "chevron.down").font(.caption).frame(width: 18) }
                .menuStyle(.borderlessButton).menuIndicator(.hidden).fixedSize()
                .disabled(suggestions.isEmpty).accessibilityLabel("最近使用的 Bundle ID")
        }.padding(.horizontal, 8).padding(.vertical, 5)
            .background(Color(nsColor: .textBackgroundColor), in: RoundedRectangle(cornerRadius: 5))
            .overlay(RoundedRectangle(cornerRadius: 5).strokeBorder(.secondary.opacity(0.25)))
    }
}

struct DebugSession: Decodable {
    let device: String
    let bundle: String
    let ipa: String
    let session: String
    let debuggable: Bool
    let frida: String
}

struct EnvironmentStatus: Decodable {
    let config: [String: String]
    let ipatool: String?
    let devices: [Phone]
    let teams: [DevelopmentTeam]
    let signers: [SigningOption]
    let fridaEnvironments: [FridaEnvironment]
    let fridaPath: String
    let fridaVersion: String
    let debugBundleHistory: [BundleHistory]
    let localAppIDs: [LocalAppID]
    let lastDebugSession: DebugSession?
    let loggedIn: Bool
    let errors: [String]
}

struct ExportRetry: Decodable {
    let device: String
    let bundle: String
    let name: String
}

struct CompletedExport: Decodable {
    let device: String
    let bundle: String
    let name: String
    let ipa: String
}

@MainActor
final class Workspace: ObservableObject {
    @Published var page = 0
    @Published var query = ""
    @Published var country = "cn"
    @Published var results: [StoreApp] = []
    @Published var selected: StoreApp?
    @Published var searching = false
    @Published var searched = false
    @Published var searchError = ""
    @Published var busy = false
    @Published var refreshing = false
    @Published var stage = "准备就绪"
    @Published var log = "任务日志会显示在这里。"
    @Published var activeLogPath = ""
    @Published var logPersistenceError = ""
    private var logSavingAvailable = false
    private let taskLogs: TaskLogStore
    @Published var failed = false
    @Published var localIPA = ""
    @Published var libraryItems: [LocalIPA] = []
    @Published var libraryLoading = false
    @Published var libraryError = ""
    @Published var libraryQuery = ""
    @Published var libraryFilter = "downloaded"
    private var libraryRefreshQueued = false
    private var pendingLibraryPaths: Set<String> = []
    private var revealLibrarySelection = false
    @Published var team = ""
    @Published var bundle = ""
    @Published var deviceID = ""
    @Published var phones: [Phone] = []
    @Published var wiredDevices: Set<String> = []
    private var checkingUSB = false
    @Published var teams: [DevelopmentTeam] = []
    @Published var signers: [SigningOption] = []
    @Published var helperSigner = ""
    @Published var debugSigner = ""
    @Published var debugIPA = ""
    @Published var debugMode = "helper"
    @Published var reuseHelperSigning = true
    @Published var customBundle = ""
    @Published var bundleHistory: [BundleHistory] = []
    @Published var localAppIDs: [LocalAppID] = []
    @Published var keepExtensions = false
    @Published var injectionEnabled = false
    @Published var injectionDylibs: [String] = []
    @Published var injectionSubstrate = true
    @Published var injectionCompatibility = "modern"
    @Published var debugEnabled = true
    @Published var autoDebug = false
    @Published var debugFrida = true
    @Published var fridaMode = "attach"
    @Published var lldbMode = "attach"
    @Published var fridaPath = ""
    @Published var fridaVersion = ""
    @Published var fridaEnvironments: [FridaEnvironment] = []
    @Published var debugSession: DebugSession?
    @Published var bundleSheet = false
    private var newBundleForExtension = false
    @Published var newBundleValue = ""
    @Published var newBundleName = ""
    @Published var newBundleError = ""
    @Published var newBundleNeedsAccount = false
    @Published var importSheet = false
    @Published var importFolder = ""
    @Published var importPassword = ""
    @Published var importError = ""
    private var pendingAutoIPA: String?
    @Published var loggedIn = false
    @Published var hasIpatool = false
    @Published var waitingForTrust = false
    @Published private(set) var pendingExport: ExportRetry?
    @Published var askingToUninstall = false
    @Published private(set) var completedExport: CompletedExport?
    @Published var acquireLicense = true
    @Published var platform = "iphone"
    @Published var notice = ""
    @Published var statusErrors = ""
    private var worker: Process?
    let root: URL
    let backend: String
    let python: String

    init() {
        root = FileManager.default.homeDirectoryForCurrentUser.appendingPathComponent("Library/Application Support/Unfairplayed/Workspace", isDirectory: true)
        backend = root.appendingPathComponent("desktop/backend.py").path
        python = ["/opt/homebrew/bin/python3", "/usr/local/bin/python3", "/usr/bin/python3"].first { FileManager.default.isExecutableFile(atPath: $0) } ?? "/usr/bin/python3"
        let home = FileManager.default.homeDirectoryForCurrentUser
        let logDirectory = home.appendingPathComponent("Downloads/Unfairplayed-Output/logs", isDirectory: true)
        let identifier = Bundle.main.bundleIdentifier ?? "desktop"
        let stateDirectory = home.appendingPathComponent("Library/Application Support/Unfairplayed/TaskLogs")
        let stateFile = stateDirectory.appendingPathComponent(identifier + ".json")
        taskLogs = TaskLogStore(directory: logDirectory,
            stateURL: stateFile)
        if let previous = taskLogs.currentURL {
            activeLogPath = previous.resolvingSymlinksInPath().path; log = taskLogs.tail()
            if taskLogs.unfinished { failed = true; stage = "上次任务未完成，日志已恢复" }
        }
        do {
            guard let resources = Bundle.main.resourceURL else { throw WorkspaceBootstrap.Failure.invalid("安装包资源缺失。") }
            try WorkspaceBootstrap.prepare(template: resources.appendingPathComponent("WorkspaceTemplate"), directory: root)
        } catch {
            failed = true; stage = "运行环境初始化失败"
            notice = error.localizedDescription
            return
        }
        refresh()
        refreshLibrary()
    }

    var output: URL {
        FileManager.default.homeDirectoryForCurrentUser
            .appendingPathComponent("Downloads/Unfairplayed-Output", isDirectory: true)
    }
    var selectedPhone: Phone? {
        if !deviceID.isEmpty { return phones.first { $0.id == deviceID } }
        let available = phones.filter(\.available)
        return available.count == 1 ? available.first : nil
    }
    private func normalizedDevice(_ id: String) -> String {
        id.lowercased().filter { $0.isASCII && ($0.isLetter || $0.isNumber) }
    }
    var fridaWired: Bool {
        let target = debugSession?.device ?? selectedPhone?.id ?? ""
        return !target.isEmpty && wiredDevices.contains(normalizedDevice(target))
    }
    func connectionLabel(_ phone: Phone) -> String {
        if !phone.available { return "未连接" }
        return wiredDevices.contains(normalizedDevice(phone.id)) ? "USB 有线" : "无线"
    }
    func refreshConnections() {
        guard !checkingUSB else { return }
        checkingUSB = true
        launch(["usb-status"]) { [weak self] code, text in
            guard let self else { return }
            self.checkingUSB = false
            if code == 0, let status = try? JSONDecoder().decode(USBStatus.self, from: Data(text.utf8)) {
                let next = Set(status.wiredDevices)
                if self.wiredDevices != next { self.wiredDevices = next }
            } else { self.wiredDevices = [] }
        }
    }
    var visibleLibraryItems: [LocalIPA] {
        let query = libraryQuery.trimmingCharacters(in: .whitespacesAndNewlines)
        return libraryItems.filter {
            $0.kind == libraryFilter && (query.isEmpty || $0.name.localizedCaseInsensitiveContains(query) || $0.bundle.localizedCaseInsensitiveContains(query) || URL(fileURLWithPath: $0.path).lastPathComponent.localizedCaseInsensitiveContains(query))
        }
    }
    func libraryCount(_ kind: String) -> Int { libraryItems.filter { $0.kind == kind }.count }
    func refreshLibrary(adding paths: [String] = [], reveal: Bool = false) {
        pendingLibraryPaths.formUnion(paths)
        if reveal {
            libraryQuery = ""
            if !localIPA.isEmpty { localIPA = URL(fileURLWithPath: localIPA).resolvingSymlinksInPath().path }
        }
        revealLibrarySelection = revealLibrarySelection || reveal
        libraryRefreshQueued = true
        guard !libraryLoading else { return }
        libraryLoading = true; libraryRefreshQueued = false; libraryError = ""
        var args = ["library"]
        for path in pendingLibraryPaths.sorted() { args += ["--add", path] }
        pendingLibraryPaths.removeAll()
        launch(args) { [weak self] code, text in
            guard let self else { return }
            self.libraryLoading = false
            if code == 0, let items = try? JSONDecoder().decode([LocalIPA].self, from: Data(text.utf8)) {
                self.libraryItems = items
                if self.revealLibrarySelection, let selected = items.first(where: { $0.path == self.localIPA }) {
                    self.libraryFilter = selected.kind; self.revealLibrarySelection = false
                }
            } else { self.libraryError = String(text.suffix(1200)) }
            if self.libraryRefreshQueued { self.refreshLibrary() }
        }
    }
    func chooseLibraryIPAs() {
        let panel = NSOpenPanel()
        panel.allowedContentTypes = [UTType(filenameExtension: "ipa") ?? .zip]
        panel.allowsMultipleSelection = true; panel.canChooseDirectories = false
        if panel.runModal() == .OK, let first = panel.urls.first {
            localIPA = first.path; page = 1
            refreshLibrary(adding: panel.urls.map(\.path), reveal: true)
        }
    }
    func reuseLibraryIPA(_ item: LocalIPA) {
        localIPA = item.path
        if item.reusable { debugIPA = item.path; page = 2 }
        else if item.error.isEmpty && !item.partial && item.state == "encrypted" { decrypt() }
    }
    func revealIPA(_ item: LocalIPA) { NSWorkspace.shared.activateFileViewerSelecting([URL(fileURLWithPath: item.path)]) }
    func verifyLibraryIPA(_ item: LocalIPA) { localIPA = item.path; verify() }

    var suggestedBundle: String { "dev.unfairplayed.helper" }
    var canCreateBundle: Bool {
        !busy && !refreshing && signers.contains { $0.id == debugSigner } &&
        (debugSigner.hasPrefix("imported:") || selectedPhone?.available == true) &&
        newBundleValue.range(of: "^[A-Za-z0-9-]+(?:\\.[A-Za-z0-9-]+)+$", options: .regularExpression) != nil
    }
    var debugTeam: String { signers.first { $0.id == debugSigner }?.team ?? "" }
    var reusableAppIDs: [LocalAppID] {
        localAppIDs.filter { $0.team == debugTeam && ($0.allDevices || $0.devices.contains(selectedPhone?.id ?? "")) }
    }
    var appIDQuotaMessage: String { quotaMessage(for: debugSigner) }
    func quotaMessage(for signerID: String) -> String {
        guard signerID.hasPrefix("xcode:") else { return "" }
        let signerTeam = signers.first { $0.id == signerID }?.team ?? ""
        let name = teams.first { $0.id == signerTeam }?.name ?? ""
        return name.localizedCaseInsensitiveContains("Personal Team") ? "个人团队：App ID 最多 10 个，有效期 7 天；每台设备最多安装 3 个 App。" : ""
    }

    var canEnableDebugging: Bool { signers.first(where: { $0.id == debugSigner })?.debuggable == true }
    var debugPermissionDenied: Bool { signers.first(where: { $0.id == debugSigner })?.debuggable == false }
    private func enforceDebugPermission() {
        if !canEnableDebugging { debugEnabled = false }
    }
    func selectDebugSigner(_ id: String) {
        debugSigner = id
        enforceDebugPermission()
    }

    func signingReason(_ id: String, debug: Bool = false) -> String {
        guard let signer = signers.first(where: { $0.id == id }) else { return "请选择签名身份" }
        return signer.reason(device: selectedPhone?.available == true ? selectedPhone!.id : "", debug: debug)
    }
    var canDecrypt: Bool { !busy && !refreshing && selectedPhone?.available == true && !bundle.isEmpty && signingReason(helperSigner).isEmpty }
    var canDebugInstall: Bool { !busy && !refreshing && selectedPhone?.available == true && !debugIPA.isEmpty && signingReason(debugSigner, debug: debugEnabled).isEmpty && (!injectionEnabled || !injectionDylibs.isEmpty) && (debugMode != "custom" || customBundle.range(of: "^[A-Za-z0-9-]+(?:\\.[A-Za-z0-9-]+)+$", options: .regularExpression) != nil) }

    @discardableResult
    private func launch(_ args: [String], input: Data? = nil, stream: ((String) -> Void)? = nil,
                        done: @escaping (Int32, String) -> Void) -> Process {
        let process = Process()
        process.executableURL = URL(fileURLWithPath: python)
        process.arguments = ["-B", "-u", backend, "--root", root.path] + args
        process.currentDirectoryURL = root
        var env = ProcessInfo.processInfo.environment
        env["PATH"] = "/opt/homebrew/bin:/usr/local/bin:/usr/bin:/bin:/usr/sbin:/sbin"
        env["PYTHONUNBUFFERED"] = "1"
        env["PYTHONDONTWRITEBYTECODE"] = "1"
        env["LANG"] = "en_US.UTF-8"
        process.environment = env
        let inputPipe = input == nil ? nil : Pipe()
        process.standardInput = inputPipe ?? FileHandle.nullDevice as Any
        let pipe = Pipe()
        process.standardOutput = pipe
        process.standardError = pipe
        do {
            try process.run()
        } catch {
            stream?(error.localizedDescription + "\n")
            done(1, error.localizedDescription)
            return process
        }
        if let input, let inputPipe {
            inputPipe.fileHandleForWriting.write(input)
            try? inputPipe.fileHandleForWriting.close()
        }
        DispatchQueue.global(qos: .userInitiated).async {
            var all = Data()
            var pending = Data()
            while true {
                let data = pipe.fileHandleForReading.availableData
                if data.isEmpty { break }
                all.append(data)
                pending.append(data)
                if let end = pending.lastIndex(of: 10) {
                    let chunk = String(decoding: pending[...end], as: UTF8.self)
                    pending.removeSubrange(...end)
                    if let stream { DispatchQueue.main.async { stream(chunk) } }
                }
            }
            if !pending.isEmpty, let stream {
                let chunk = String(decoding: pending, as: UTF8.self)
                DispatchQueue.main.async { stream(chunk) }
            }
            process.waitUntilExit()
            let code = process.terminationStatus
            let output = String(decoding: all, as: UTF8.self)
            DispatchQueue.main.async { done(code, output) }
        }
        return process
    }

    func refresh() {
        guard !busy && !refreshing else { return }
        refreshing = true
        launch(["status"]) { [weak self] code, text in
            guard let self else { return }
            self.refreshing = false
            guard code == 0, let value = try? JSONDecoder().decode(EnvironmentStatus.self, from: Data(text.utf8)) else {
                self.notice = "环境检查失败：\(text)"; return
            }
            self.phones = value.devices
            self.wiredDevices = Set(value.devices.filter { $0.wired == true }.map { self.normalizedDevice($0.id) })
            self.teams = value.teams
            self.signers = value.signers
            self.fridaEnvironments = value.fridaEnvironments
            self.fridaMode = value.config["FRIDA_MODE"] ?? "attach"
            self.lldbMode = value.config["LLDB_MODE"] ?? "attach"
            self.fridaPath = value.fridaPath
            self.fridaVersion = value.fridaVersion
            self.bundleHistory = value.debugBundleHistory
            self.localAppIDs = value.localAppIDs
            self.debugSession = value.lastDebugSession
            self.loggedIn = value.loggedIn
            self.hasIpatool = value.ipatool != nil
            self.team = value.config["TEAM_ID"] ?? value.teams.first?.id ?? ""
            self.bundle = value.config["UNFAIRPLAYED_BUNDLE_ID"] ?? self.suggestedBundle
            self.deviceID = value.config["DEVICE"] ?? value.devices.first?.id ?? ""
            self.helperSigner = value.config["HELPER_SIGNER_ID"].flatMap { $0.isEmpty ? nil : $0 } ?? "xcode:" + self.team
            self.debugSigner = value.config["DEBUG_SIGNER_ID"].flatMap { $0.isEmpty ? nil : $0 } ?? self.helperSigner
            let savedMode = value.config["DEBUG_BUNDLE_MODE"] ?? "helper"
            let savedID = value.config["DEBUG_CUSTOM_BUNDLE_ID"] ?? ""
            self.debugMode = savedMode == "custom" && !savedID.isEmpty && savedID != self.bundle ? "custom" : "helper"
            self.reuseHelperSigning = self.debugSigner == self.helperSigner
            self.customBundle = value.config["DEBUG_CUSTOM_BUNDLE_ID"] ?? ""
            self.autoDebug = value.config["AUTO_DEBUG"] == "1"
            self.debugEnabled = value.config["DEBUG_ENABLED"] != "0"
            self.keepExtensions = value.config["KEEP_EXTENSIONS"] == "1"
            self.injectionEnabled = value.config["INJECTION_ENABLED"] == "1"
            self.injectionSubstrate = value.config["INJECTION_SUBSTRATE"] != "0"
            self.injectionCompatibility = value.config["INJECTION_COMPATIBILITY"] ?? "modern"
            self.injectionDylibs = (value.config["INJECTION_DYLIBS"].flatMap { try? JSONDecoder().decode([String].self, from: Data($0.utf8)) }) ?? []
            self.debugFrida = value.config["DEBUG_FRIDA"] != "0"
            self.enforceDebugPermission()
            self.statusErrors = value.errors.joined(separator: "\n")
        }
    }

    func search() {
        let term = query.trimmingCharacters(in: .whitespacesAndNewlines)
        guard !term.isEmpty && !searching else { return }
        searching = true
        searchError = ""
        selected = nil
        launch(["search", term, "--country", country]) { [weak self] code, text in
            guard let self else { return }
            self.searching = false
            self.searched = true
            if code == 0, let apps = try? JSONDecoder().decode([StoreApp].self, from: Data(text.utf8)) {
                self.results = apps
                self.selected = apps.first
            } else {
                self.results = []
                self.searchError = text
            }
        }
    }

    func save() {
        guard !busy && !refreshing else { return }
        refreshing = true
        launch(configArgs) { [weak self] code, text in
            guard let self else { return }
            self.refreshing = false
            self.notice = code == 0 ? "签名与设备配置已保存。" : text
        }
    }

    private var configArgs: [String] {
        var args = ["configure", "--team", team, "--bundle", bundle, "--device", deviceID,
                    "--helper-signer", helperSigner, "--debug-signer", debugSigner,
                    "--debug-mode", debugMode, "--debug-bundle", customBundle, "--frida-path", fridaPath, "--frida-mode", fridaMode, "--lldb-mode", lldbMode]
        if autoDebug { args.append("--auto-debug") }
        if debugFrida { args.append("--debug-frida") }
        if !debugEnabled { args.append("--no-debug") }
        if keepExtensions { args.append("--keep-extensions") }
        if injectionEnabled { args.append("--injection-enabled") }
        for path in injectionDylibs { args += ["--dylib", path] }
        if !injectionSubstrate { args.append("--no-injection-substrate") }
        args += ["--injection-compatibility", injectionCompatibility]
        return args
    }

    func login() {
        launch(["login"]) { [weak self] code, text in
            self?.notice = code == 0 ? "已打开终端。按提示完成 Apple ID、密码和双重认证，再点击刷新。" : text
        }
    }

    func selectHelperSigner(_ id: String) {
        helperSigner = id
        if let signer = signers.first(where: { $0.id == id }) { team = signer.team }
        if reuseHelperSigning { selectDebugSigner(id) }
    }

    func setReuseHelperSigning(_ value: Bool) {
        reuseHelperSigning = value
        if value { selectDebugSigner(helperSigner) }
    }

    func showNewBundle() {
        newBundleValue = "dev.unfairplayed.debug." + UUID().uuidString.replacingOccurrences(of: "-", with: "").prefix(8).lowercased()
        newBundleName = ""; newBundleError = ""; newBundleNeedsAccount = false; newBundleForExtension = false; bundleSheet = true
    }

    func openXcode() {
        launch(["open-xcode"]) { [weak self] code, text in if code != 0 { self?.newBundleError = text } }
    }

    private func beginTaskLog(_ title: String, append: Bool = false) {
        let preserve = failed || taskLogs.unfinished
        logPersistenceError = ""
        do {
            try taskLogs.begin(title, append: append, preservePrevious: preserve)
            logSavingAvailable = true; activeLogPath = taskLogs.currentURL?.path ?? ""
            log = taskLogs.tail()
        } catch {
            logSavingAvailable = false
            logPersistenceError = "日志自动保存失败：" + error.localizedDescription
        }
        appendTaskLog("\n── \(title) · \(Date().formatted(date: .numeric, time: .standard)) ──\n")
    }

    private func appendTaskLog(_ value: String) {
        log += value
        if logSavingAvailable {
            do { try taskLogs.append(value) }
            catch { logSavingAvailable = false; logPersistenceError = "日志自动保存失败：" + error.localizedDescription }
        }
        if logSavingAvailable && log.count > 180_000 { log = String(log.suffix(150_000)) }
    }

    private func finishTaskLog(_ code: Int32) {
        appendTaskLog("\n── 任务结束，退出码 \(code) ──\n")
        if logSavingAvailable {
            do { try taskLogs.finish(code) }
            catch { logSavingAvailable = false; logPersistenceError = "日志自动保存失败：" + error.localizedDescription }
        }
    }

    func revealTaskLogs() {
        try? FileManager.default.createDirectory(at: taskLogs.directory, withIntermediateDirectories: true)
        NSWorkspace.shared.open(taskLogs.directory)
    }

    func createBundle() {
        guard canCreateBundle else { return }
        beginTaskLog("新建 Bundle ID · " + newBundleValue)
        busy = true; failed = false; newBundleError = ""; newBundleNeedsAccount = false
        stage = "正在准备 Bundle ID"
        let args = ["create-bundle", "--bundle", newBundleValue.trimmingCharacters(in: .whitespaces),
                    "--signer", debugSigner, "--device", selectedPhone?.id ?? "", "--name", newBundleName]
        worker = launch(args, stream: { [weak self] chunk in self?.appendTaskLog(chunk) }) { [weak self] code, text in
            guard let self else { return }
            self.finishTaskLog(code)
            self.busy = false; self.worker = nil; self.failed = code != 0
            if code == 0,
               let line = text.components(separatedBy: .newlines).last(where: { $0.hasPrefix("FPD_BUNDLE_READY=") }),
               let value = try? JSONDecoder().decode(BundleReady.self, from: Data(line.dropFirst("FPD_BUNDLE_READY=".count).utf8)) {
                if !self.newBundleForExtension {
                    self.debugMode = value.bundle == self.bundle ? "helper" : "custom"; self.customBundle = value.bundle
                }
                self.bundleHistory.removeAll { $0.bundle == value.bundle }
                self.bundleHistory.insert(BundleHistory(bundle: value.bundle, name: value.name), at: 0)
                self.bundleHistory = Array(self.bundleHistory.prefix(10))
                self.bundleSheet = false; self.stage = "Bundle ID 已准备好"; self.page = 2
            } else {
                self.stage = code == 130 ? "申请已停止" : "Bundle ID 尚未准备好"
                if let line = text.components(separatedBy: .newlines).last(where: { $0.hasPrefix("FPD_BUNDLE_ACTION=") }),
                   let action = try? JSONDecoder().decode(BundleAction.self, from: Data(line.dropFirst("FPD_BUNDLE_ACTION=".count).utf8)) {
                    self.newBundleError = action.message; self.newBundleNeedsAccount = action.reason == "account"
                } else { self.newBundleError = text.isEmpty ? "申请未完成，请重试。" : String(text.suffix(1600)) }
            }
        }
    }

    func chooseImportFolder() {
        let panel = NSOpenPanel()
        panel.canChooseDirectories = true; panel.canChooseFiles = false
        panel.allowsMultipleSelection = false
        panel.message = "选择包含 P12 证书和 mobileprovision 描述文件的文件夹，可同时导入多组。"
        if panel.runModal() == .OK, let url = panel.url {
            importFolder = url.path; importPassword = ""; importError = ""; importSheet = true
        }
    }

    func importSigning() {
        guard !busy && !refreshing else { return }
        refreshing = true; importError = ""
        let data = try? JSONSerialization.data(withJSONObject: ["password": importPassword])
        importPassword = ""
        launch(["import-signing", "--folder", importFolder], input: data) { [weak self] code, text in
            guard let self else { return }
            self.refreshing = false
            if code == 0 {
                self.importSheet = false; self.refresh()
                self.notice = "签名材料已导入，可在两个签名下拉框中选择。\n\n" + text
            } else { self.importError = text }
        }
    }

    func chooseDebugIPA() {
        let panel = NSOpenPanel()
        panel.allowedContentTypes = [UTType(filenameExtension: "ipa") ?? .zip]
        panel.allowsMultipleSelection = false; panel.canChooseDirectories = false
        if panel.runModal() == .OK, let url = panel.url { debugIPA = url.path; refreshLibrary(adding: [url.path]) }
    }

    func selectFrida(_ path: String) {
        fridaPath = path; fridaVersion = ""
        launch(["frida-info", "--path", path]) { [weak self] code, text in
            guard let self, self.fridaPath == path else { return }
            if code == 0, let value = try? JSONSerialization.jsonObject(with: Data(text.utf8)) as? [String: String] {
                self.fridaVersion = value["version"] ?? ""
            }
        }
    }

    func chooseFrida() {
        let panel = NSOpenPanel()
        panel.canChooseDirectories = false; panel.allowsMultipleSelection = false
        panel.showsHiddenFiles = true; panel.message = "选择所需环境 bin 目录中的 frida 可执行文件。"
        if panel.runModal() == .OK, let url = panel.url { selectFrida(url.path) }
    }

    func debugInstall(append: Bool = false) {
        guard canDebugInstall, let phone = selectedPhone else { return }
        var args = ["debug-install", "--ipa", debugIPA, "--signer", debugSigner, "--device", phone.id,
                    "--mode", debugMode, "--bundle", debugMode == "helper" ? bundle : customBundle, "--frida-path", fridaPath]
        if debugEnabled && debugFrida { args.append("--frida") }
        if !debugEnabled { args.append("--no-debug") }
        if keepExtensions { args.append("--keep-extensions") }
        if injectionEnabled {
            for path in injectionDylibs { args += ["--dylib", path] }
            if !injectionSubstrate { args.append("--no-injection-substrate") }
            args += ["--injection-compatibility", injectionCompatibility]
        }
        start(debugEnabled ? "重签名并安装调试版" : "重签名并安装", args: args, append: append)
    }

    func chooseInjectionDylibs() {
        let panel = NSOpenPanel()
        panel.allowedContentTypes = [UTType(filenameExtension: "dylib") ?? .data]
        panel.allowsMultipleSelection = true; panel.canChooseDirectories = false
        panel.message = "选择要注入主 App 的 iOS 真机 dylib，可同时添加依赖库。"
        if panel.runModal() == .OK {
            for url in panel.urls where !injectionDylibs.contains(url.path) && injectionDylibs.count < 64 {
                injectionDylibs.append(url.path)
            }
        }
    }

    func openDebugger(_ tool: String) {
        guard let session = debugSession, !busy else { return }
        if tool == "frida" && !fridaWired {
            notice = "Frida 仅支持 USB 有线连接，请用数据线连接并解锁目标设备。LLDB 可继续使用无线连接。"
            return
        }
        launch(["open-debugger", "--session", session.session, "--tool", tool, "--frida-path", fridaPath, "--frida-mode", fridaMode, "--lldb-mode", lldbMode]) { [weak self] code, text in
            if code != 0 { self?.notice = text }
        }
    }

    func keepHelper() {
        askingToUninstall = false
        continueAutoDebug()
    }

    private func continueAutoDebug() {
        guard let ipa = pendingAutoIPA else { return }
        pendingAutoIPA = nil; debugIPA = ipa
        DispatchQueue.main.asyncAfter(deadline: .now() + 0.25) { [weak self] in
            guard let self else { return }
            if self.canDebugInstall { self.debugInstall(append: true) }
            else { self.page = 2; self.notice = "IPA 已导出。请在设备与签名页检查证书、设备及 Bundle ID，然后安装。" }
        }
    }

    func chooseIPA() {
        let panel = NSOpenPanel()
        panel.allowedContentTypes = [UTType(filenameExtension: "ipa") ?? .zip]
        panel.allowsMultipleSelection = false
        panel.canChooseDirectories = false
        if panel.runModal() == .OK, let url = panel.url {
            localIPA = url.path
            page = 1
            refreshLibrary(adding: [url.path], reveal: true)
        }
    }

    func acceptDrop(_ providers: [NSItemProvider]) -> Bool {
        guard !busy && !providers.isEmpty else { return false }
        for provider in providers {
            _ = provider.loadObject(ofClass: URL.self) { [weak self] url, _ in
                guard let url, url.pathExtension.lowercased() == "ipa" else { return }
                DispatchQueue.main.async {
                    self?.localIPA = url.path; self?.page = 1
                    self?.refreshLibrary(adding: [url.path], reveal: true)
                }
            }
        }
        return true
    }

    func revealOutput() {
        try? FileManager.default.createDirectory(at: output, withIntermediateDirectories: true)
        NSWorkspace.shared.open(output)
    }

    func download(decryptAfter: Bool) {
        guard let app = selected, loggedIn else { return }
        var args = ["download", app.bundle, "--app-id", app.id, "--platform", platform]
        if acquireLicense { args.append("--purchase") }
        start("下载 IPA", args: args) { [weak self] text in
            guard let self else { return }
            if let line = text.components(separatedBy: .newlines).last(where: { $0.hasPrefix("FPD_RESULT=") }) {
                self.localIPA = String(line.dropFirst("FPD_RESULT=".count))
                self.refreshLibrary(adding: [self.localIPA])
                if decryptAfter { self.decrypt(append: true) }
                else { self.libraryFilter = "downloaded"; self.libraryQuery = ""; self.page = 1 }
            }
        }
    }

    func decrypt(append: Bool = false) {
        guard canDecrypt && !localIPA.isEmpty else { return }
        start("砸壳并导出", args: ["decrypt", localIPA], append: append)
    }

    func retryExport() {
        guard let retry = pendingExport, !busy && !refreshing else { return }
        start("重试启动并导出", args: ["resume-export", "--device", retry.device,
                                 "--bundle", retry.bundle, "--name", retry.name], append: true)
    }

    func uninstallHelper() {
        guard let completed = completedExport, !busy && !refreshing else { return }
        start("卸载辅助 App", args: ["uninstall-helper", "--device", completed.device,
                                  "--bundle", completed.bundle], append: true)
    }

    var uninstallMessage: String {
        guard let completed = completedExport else { return "" }
        let phone = phones.first { $0.id == completed.device }?.name ?? completed.device
        return "IPA 已导出并通过校验。是否卸载 \(phone) 上的 Unfairplayed 辅助 App？\n\n卸载会清除辅助 App 在手机上的数据，Mac 上的 IPA 和日志会保留。\n\n导出文件：\(completed.ipa)"
    }

    func build() { start("构建并签名辅助 App", args: ["build"]) }
    func install() { start("安装辅助 App", args: ["install"]) }
    func verify() {
        guard !localIPA.isEmpty else { return }
        start("校验 IPA", args: ["verify", localIPA])
    }

    private func start(_ title: String, args: [String], append: Bool = false,
                       success: ((String) -> Void)? = nil) {
        guard !busy && !refreshing else { return }
        let uninstallRequest = args.first == "uninstall-helper" ? completedExport : nil
        beginTaskLog(title, append: append)
        busy = true
        if args.first == "debug-install" { debugSession = nil }
        waitingForTrust = false
        pendingExport = nil
        askingToUninstall = false
        completedExport = nil
        failed = false
        stage = title
        page = 3
        // Save the exact values visible in Settings before starting a task.
        let execute = { [weak self] in
            guard let self else { return }
            self.worker = self.launch(args, stream: { [weak self] chunk in
                guard let self else { return }
                self.appendTaskLog(chunk)
                if chunk.contains("==> Embedding") { self.stage = "嵌入 IPA" }
                if chunk.contains("==> Building") { self.stage = "构建并签名" }
                if chunk.contains("==> Installing") { self.stage = "安装到 iPhone" }
                if chunk.contains("==> Decrypting") { self.stage = "设备砸壳中" }
                if chunk.contains("==> Pulling") { self.stage = "导出并校验 IPA" }
                if chunk.contains("==> Injecting") { self.stage = "注入自定义动态库" }
            }) { [weak self] code, text in
                guard let self else { return }
                self.finishTaskLog(code)
                self.busy = false
                self.worker = nil
                self.failed = code != 0
                self.stage = code == 0 ? "\(title)完成" : code == 130 || code == 15 ? "任务已停止" : "任务未完成"
                if code == 78,
                   let line = text.components(separatedBy: .newlines).last(where: { $0.hasPrefix("FPD_TRUST_REQUIRED=") }),
                   let retry = try? JSONDecoder().decode(ExportRetry.self, from: Data(line.dropFirst("FPD_TRUST_REQUIRED=".count).utf8)) {
                    self.pendingExport = retry
                    self.failed = false
                    self.stage = "等待在手机上信任开发者证书"
                    self.waitingForTrust = true
                }
                if code == 79,
                   let line = text.components(separatedBy: .newlines).last(where: { $0.hasPrefix("FPD_BUNDLE_ACTION=") }),
                   let action = try? JSONDecoder().decode(BundleAction.self, from: Data(line.dropFirst("FPD_BUNDLE_ACTION=".count).utf8)) {
                    self.newBundleForExtension = action.bundle?.isEmpty == false
                    self.newBundleValue = action.bundle?.isEmpty == false ? action.bundle! : (self.debugMode == "helper" ? self.bundle : self.customBundle)
                    self.newBundleName = ""
                    self.newBundleError = action.message; self.newBundleNeedsAccount = action.reason == "account"
                    self.page = 2; self.bundleSheet = true
                }
                if code == 0, ["decrypt", "resume-export"].contains(args.first ?? ""),
                   let line = text.components(separatedBy: .newlines).last(where: { $0.hasPrefix("FPD_EXPORT_COMPLETE=") }),
                   let completed = try? JSONDecoder().decode(CompletedExport.self, from: Data(line.dropFirst("FPD_EXPORT_COMPLETE=".count).utf8)) {
                    self.completedExport = completed
                    self.debugIPA = completed.ipa
                    self.libraryFilter = "decrypted"
                    self.libraryQuery = ""
                    self.refreshLibrary()
                    self.pendingAutoIPA = self.autoDebug ? completed.ipa : nil
                    self.askingToUninstall = true
                }
                if let uninstallRequest {
                    if code == 0 {
                        self.stage = "导出成功，辅助 App 已卸载"
                        if self.pendingAutoIPA != nil { self.continueAutoDebug() }
                        else { self.notice = "辅助 App 已卸载。\n\n导出的 IPA 保存在 Mac：\n\(uninstallRequest.ipa)" }
                    } else {
                        self.stage = "导出成功，辅助 App 未卸载"
                        self.completedExport = uninstallRequest
                        self.notice = "辅助 App 未能卸载，请确认手机已连接并解锁，可在任务日志中重试。\n\n导出的 IPA 仍保存在 Mac：\n\(uninstallRequest.ipa)\n\n具体错误请查看任务日志。"
                    }
                }
                if code == 0, args.first == "debug-install",
                   let line = text.components(separatedBy: .newlines).last(where: { $0.hasPrefix("FPD_DEBUG_READY=") }),
                   let session = try? JSONDecoder().decode(DebugSession.self, from: Data(line.dropFirst("FPD_DEBUG_READY=".count).utf8)) {
                    self.debugSession = session
                    self.bundleHistory.removeAll { $0.bundle == session.bundle }
                    self.bundleHistory.insert(BundleHistory(bundle: session.bundle, name: URL(fileURLWithPath: session.ipa).deletingPathExtension().lastPathComponent), at: 0)
                    self.bundleHistory = Array(self.bundleHistory.prefix(10))
                    self.page = 4
                }
                if code == 0 { success?(text) }
            }
        }
        if ["decrypt", "build", "install", "debug-install"].contains(args.first ?? "") {
            worker = launch(configArgs) { [weak self] code, text in
                guard let self else { return }
                guard code == 0 else {
                    self.appendTaskLog(text); self.finishTaskLog(code); self.busy = false; self.failed = true
                    self.stage = "配置无效"; self.worker = nil; return
                }
                execute()
            }
        } else {
            execute()
        }
    }

    func stop() {
        guard let worker, worker.isRunning else { return }
        stage = "正在停止…"
        worker.terminate()
    }

    func exportLog() {
        let panel = NSSavePanel()
        panel.nameFieldStringValue = "Unfairplayed-\(Int(Date().timeIntervalSince1970)).log"
        if panel.runModal() == .OK, let url = panel.url {
            do {
                if taskLogs.currentURL != nil && logPersistenceError.isEmpty { try taskLogs.saveFull(to: url) }
                else { try log.write(to: url, atomically: true, encoding: .utf8) }
            } catch { notice = "日志保存失败：" + error.localizedDescription }
        }
    }
}

struct AppArtwork: View {
    let app: StoreApp
    var size: CGFloat = 48
    var body: some View {
        AsyncImage(url: URL(string: app.artwork)) { image in
            image.resizable().scaledToFit()
        } placeholder: {
            ZStack { Color.secondary.opacity(0.1); Image(systemName: "app.dashed").foregroundStyle(.secondary) }
        }
        .frame(width: size, height: size)
        .clipShape(RoundedRectangle(cornerRadius: size * 0.21))
    }
}

struct ContentView: View {
    @EnvironmentObject var model: Workspace
    private let sections = [("应用搜索", "magnifyingglass"), ("本地 IPA", "shippingbox"),
                            ("设备与签名", "iphone"), ("任务日志", "terminal"), ("调试", "ladybug")]

    var body: some View {
        HStack(spacing: 0) {
            sidebar
            Divider()
            VStack(spacing: 0) {
                HStack {
                    VStack(alignment: .leading, spacing: 5) {
                        Text(sections[model.page].0).font(.system(size: 25, weight: .semibold))
                        Text(subtitle).font(.callout).foregroundStyle(.secondary)
                    }
                    Spacer()
                    if model.page == 2 || model.page == 4 {
                        Button("保存设置") { model.save() }.disabled(model.busy || model.refreshing)
                    }
                    Button { model.revealOutput() } label: { Label("输出目录", systemImage: "folder") }
                }.padding(.horizontal, 30).padding(.top, 26).padding(.bottom, 23)
                Divider()
                Group {
                    switch model.page {
                    case 0: searchPage
                    case 1: localPage
                    case 2: settingsPage
                    case 4: debugPage
                    default: logsPage
                    }
                }.frame(maxWidth: .infinity, maxHeight: .infinity)
                Divider()
                HStack(spacing: 8) {
                    if model.busy { ProgressView().controlSize(.small).scaleEffect(0.75) }
                    else { Image(systemName: model.failed ? "exclamationmark.circle" : "circle.fill").font(.system(size: 7)).foregroundStyle(model.failed ? .orange : .secondary) }
                    Text(model.stage).font(.caption)
                    Spacer()
                    Text("原始 IPA 保留在本机").font(.caption).foregroundStyle(.secondary)
                }.padding(.horizontal, 24).padding(.vertical, 12)
            }.background(Color(nsColor: .windowBackgroundColor))
        }
        .frame(minWidth: 1000, minHeight: 700)
        .tint(brandTint)
        .alert(model.waitingForTrust ? "请在手机上信任开发者证书" : model.askingToUninstall ? "导出完成，要卸载辅助 App 吗？" : "Unfairplayed",
               isPresented: Binding(get: { model.waitingForTrust || model.askingToUninstall || !model.notice.isEmpty },
                                    set: { if !$0 { model.waitingForTrust = false; model.askingToUninstall = false; model.notice = "" } })) {
            if model.waitingForTrust {
                Button("已信任，重试启动") { model.retryExport() }
                Button("稍后", role: .cancel) { model.waitingForTrust = false }
            } else if model.askingToUninstall {
                Button("卸载辅助 App", role: .destructive) { model.uninstallHelper() }
                Button("暂时保留", role: .cancel) { model.keepHelper() }
            } else {
                Button("好") { model.notice = "" }
            }
        } message: {
            if model.waitingForTrust {
                Text("辅助 App 已安装，但系统拒绝启动，可能尚未信任开发者证书。\n\n请在 iPhone 打开：设置 → 通用 → VPN 与设备管理 → 开发者 App，选择对应账号并信任或验证。完成后保持手机解锁，点击重试。\n\n重试会直接启动并继续导出，无需重新下载或构建。若信任后仍失败，请检查日志中的签名或权限错误。")
            } else if model.askingToUninstall { Text(model.uninstallMessage) }
            else { Text(model.notice) }
        }
        .sheet(isPresented: $model.importSheet) { importSigningSheet }
        .sheet(isPresented: $model.bundleSheet) { newBundleSheet }
        .onReceive(Timer.publish(every: 2, on: .main, in: .common).autoconnect()) { _ in model.refreshConnections() }
        .onChange(of: model.page) { page in if page == 1 { model.refreshLibrary() } }
        .onDrop(of: [.fileURL], isTargeted: nil, perform: model.acceptDrop)
    }

    private var subtitle: String {
        ["检索 App Store，下载并处理你的应用。", "整理已下载和已脱壳的应用，随时复用。",
         "统一管理设备、签名与重新安装。", "查看当前任务的步骤、输出与校验结果。", "连接已安装的应用，使用 LLDB 或 Frida 调试。"][model.page]
    }

    private var sidebar: some View {
        VStack(alignment: .leading, spacing: 0) {
            HStack(spacing: 11) {
                Image("UnfairplayedLogo").resizable().scaledToFit().frame(width: 36, height: 36)
                VStack(alignment: .leading, spacing: 3) {
                    Text("Unfairplayed").font(.system(size: 19, weight: .semibold))
                    Text("IPA WORKSPACE").font(.system(size: 9, weight: .medium, design: .monospaced)).tracking(1.1).foregroundStyle(.secondary)
                }
            }.padding(.top, 34).padding(.bottom, 37).padding(.horizontal, 20)
            ForEach(sections.indices, id: \.self) { index in
                Button { model.page = index } label: {
                    HStack(spacing: 12) {
                        Image(systemName: sections[index].1).frame(width: 18)
                        Text(sections[index].0)
                        Spacer()
                        if index == 3 && model.busy { Circle().fill(brandTint).frame(width: 6, height: 6) }
                    }
                    .padding(.horizontal, 14).padding(.vertical, 11)
                    .contentShape(Rectangle())
                    .background(model.page == index ? brandTint.opacity(0.11) : .clear, in: RoundedRectangle(cornerRadius: 8))
                }.buttonStyle(.plain).padding(.horizontal, 10).padding(.bottom, 5)
            }
            Spacer()
            VStack(alignment: .leading, spacing: 12) {
                Label(model.loggedIn ? "Apple ID 已登录" : "Apple ID 未登录", systemImage: "person.crop.circle")
                Label(model.selectedPhone?.available == true ? "iPhone 可用" : "等待连接 iPhone", systemImage: "iphone")
                Button("刷新状态") { model.refresh() }.disabled(model.busy || model.refreshing)
            }.font(.caption).foregroundStyle(.secondary).padding(20)
        }.frame(width: 208).background(.regularMaterial)
    }

    private var searchPage: some View {
        VStack(spacing: 0) {
            HStack(spacing: 12) {
                HStack {
                    Image(systemName: "magnifyingglass").foregroundStyle(.secondary)
                    TextField("应用名称或 Bundle ID", text: $model.query).textFieldStyle(.plain).onSubmit { model.search() }
                }.padding(11).background(Color(nsColor: .textBackgroundColor), in: RoundedRectangle(cornerRadius: 8))
                Picker("商店", selection: $model.country) {
                    Text("中国大陆").tag("cn"); Text("美国").tag("us"); Text("新加坡").tag("sg"); Text("香港").tag("hk")
                }.labelsHidden().frame(width: 110).disabled(model.searching)
                Button("搜索") { model.search() }.buttonStyle(.borderedProminent).disabled(model.searching || model.query.trimmingCharacters(in: .whitespaces).isEmpty)
            }.padding(24)
            HSplitView {
                Group {
                    if model.searching {
                        VStack(spacing: 15) { ProgressView(); Text("正在检索 App Store…").foregroundStyle(.secondary) }.frame(maxWidth: .infinity, maxHeight: .infinity)
                    } else if model.results.isEmpty {
                        emptyState(icon: "square.grid.2x2", title: model.searched ? "未找到应用" : "从一个应用开始",
                                   detail: model.searchError.isEmpty ? (model.searched ? "试试其他名称、Bundle ID 或商店区域。" : "输入应用名称或 Bundle ID。\n搜索无需登录，下载使用你的 Apple ID。") : model.searchError)
                    } else {
                        ScrollView {
                            LazyVStack(spacing: 2) {
                                ForEach(model.results) { app in
                                    Button { model.selected = app } label: {
                                        HStack(spacing: 12) {
                                            AppArtwork(app: app)
                                            VStack(alignment: .leading, spacing: 4) {
                                                Text(app.name).font(.system(size: 13, weight: .medium)).lineLimit(1)
                                                Text(app.bundle).font(.system(size: 10, design: .monospaced)).foregroundStyle(.secondary).lineLimit(1)
                                                Text(app.artist).font(.caption).foregroundStyle(.secondary).lineLimit(1)
                                            }
                                            Spacer(minLength: 5)
                                        }.padding(12).contentShape(Rectangle())
                                            .background(model.selected?.id == app.id ? brandTint.opacity(0.09) : .clear, in: RoundedRectangle(cornerRadius: 9))
                                    }.buttonStyle(.plain)
                                }
                            }.padding(.horizontal, 14).padding(.bottom, 15)
                        }
                    }
                }.frame(minWidth: 320)
                appDetail.frame(width: 295).frame(maxHeight: .infinity)
            }
        }
    }

    private var appDetail: some View {
        ScrollView {
            VStack(alignment: .leading, spacing: 20) {
                if let app = model.selected {
                    AppArtwork(app: app, size: 76)
                    VStack(alignment: .leading, spacing: 8) {
                        Text(app.name).font(.system(size: 22, weight: .semibold))
                        Text(app.artist).foregroundStyle(.secondary)
                        Text(app.bundle).font(.system(size: 11, design: .monospaced)).textSelection(.enabled).foregroundStyle(.secondary)
                    }
                    HStack { Text("版本 \(app.version)"); Spacer(); Text(app.price) }.font(.caption).foregroundStyle(.secondary)
                    Divider()
                    Picker("下载平台", selection: $model.platform) { Text("iPhone").tag("iphone"); Text("iPad").tag("ipad") }
                    Toggle("为免费应用获取许可", isOn: $model.acquireLicense).font(.caption)
                    VStack(spacing: 10) {
                        Button { model.download(decryptAfter: true) } label: { Text("下载并砸壳").frame(maxWidth: .infinity) }
                            .buttonStyle(.borderedProminent).controlSize(.large).disabled(!model.loggedIn || !model.canDecrypt || !model.hasIpatool)
                        Button { model.download(decryptAfter: false) } label: { Text("仅下载加密 IPA").frame(maxWidth: .infinity) }
                            .controlSize(.large).disabled(!model.loggedIn || model.busy || model.refreshing || !model.hasIpatool)
                    }
                    if !model.loggedIn {
                        Text("下载前请先登录 Apple ID。密码与验证码在终端中输入。").font(.caption).foregroundStyle(.secondary)
                        Button("登录 Apple ID…") { model.login() }.disabled(model.busy || !model.hasIpatool)
                    } else if !model.canDecrypt {
                        Button("配置设备与证书 →") { model.page = 2 }.buttonStyle(.plain).foregroundStyle(brandTint)
                    }
                    Text("下载使用登录账号的商店区域，可能与搜索区域不同。付费应用须事先购买。").font(.caption).foregroundStyle(.secondary).lineSpacing(3)
                    if let url = URL(string: app.storeURL) { Link("在 App Store 查看", destination: url).font(.caption) }
                } else {
                    Image(systemName: "app.badge.checkmark").font(.system(size: 32)).foregroundStyle(.tertiary).padding(.top, 40)
                    Text("应用详情").font(.headline)
                    Text("搜索并选择应用后，在这里下载 IPA 或启动完整流程。").font(.callout).foregroundStyle(.secondary).lineSpacing(4)
                    Divider()
                    Button("选择本地 IPA…") { model.chooseIPA() }.disabled(model.busy)
                    Button("设备与签名设置") { model.page = 2 }
                }
            }.padding(25).frame(maxWidth: .infinity, alignment: .leading)
        }.background(Color(nsColor: .controlBackgroundColor).opacity(0.5))
    }

    private var localPage: some View {
        VStack(spacing: 0) {
            HStack(spacing: 12) {
                Picker("文件类型", selection: $model.libraryFilter) {
                    Text("已下载 · \(model.libraryCount("downloaded"))").tag("downloaded")
                    Text("已脱壳 · \(model.libraryCount("decrypted"))").tag("decrypted")
                }.pickerStyle(.segmented).labelsHidden().frame(width: 280)
                Spacer()
                if model.libraryLoading { ProgressView().controlSize(.small) }
                Button("刷新") { model.refreshLibrary() }.disabled(model.libraryLoading)
                Button("添加 IPA…") { model.chooseLibraryIPAs() }.disabled(model.busy)
            }.padding(.horizontal, 28).padding(.top, 24).padding(.bottom, 16)
            HStack(spacing: 9) {
                Image(systemName: "magnifyingglass").foregroundStyle(.secondary)
                TextField("搜索应用、Bundle ID 或文件名", text: $model.libraryQuery).textFieldStyle(.plain)
                if !model.libraryQuery.isEmpty {
                    Button { model.libraryQuery = "" } label: { Image(systemName: "xmark.circle.fill").foregroundStyle(.secondary) }.buttonStyle(.plain)
                }
            }.padding(10).background(Color(nsColor: .textBackgroundColor), in: RoundedRectangle(cornerRadius: 8))
                .padding(.horizontal, 28).padding(.bottom, 18)
            Divider()
            if !model.libraryError.isEmpty {
                Text(model.libraryError).font(.caption).foregroundStyle(.orange).textSelection(.enabled).padding(16)
            }
            if model.libraryLoading && model.libraryItems.isEmpty {
                VStack(spacing: 12) { ProgressView(); Text("正在整理本地 IPA…").foregroundStyle(.secondary) }
                    .frame(maxWidth: .infinity, maxHeight: .infinity)
            } else if model.visibleLibraryItems.isEmpty {
                emptyState(icon: model.libraryFilter == "decrypted" ? "checkmark.seal" : "shippingbox",
                           title: model.libraryQuery.isEmpty ? (model.libraryFilter == "decrypted" ? "还没有已脱壳的 IPA" : "还没有下载的 IPA") : "没有匹配的应用",
                           detail: model.libraryQuery.isEmpty ? "下载和导出结果会自动整理到这里。\n也可添加或拖入其他位置的 IPA。" : "试试应用名称、Bundle ID 或文件名。")
                    .frame(maxWidth: .infinity, maxHeight: .infinity)
            } else {
                ScrollView {
                    LazyVStack(spacing: 0) {
                        ForEach(model.visibleLibraryItems) { item in libraryRow(item) }
                    }.padding(.horizontal, 18).padding(.vertical, 10)
                }
            }
            Divider()
            HStack {
                Text("自动整理下载与导出结果，原文件保持不变。").font(.caption).foregroundStyle(.secondary)
                Spacer()
                if !model.canDecrypt && model.libraryFilter == "downloaded" {
                    Button("配置设备与签名 →") { model.page = 2 }.buttonStyle(.plain).font(.caption).foregroundStyle(brandTint)
                }
            }.padding(.horizontal, 28).padding(.vertical, 13)
        }
    }

    private func libraryRow(_ item: LocalIPA) -> some View {
        HStack(spacing: 15) {
            IPAArtwork(item: item).accessibilityLabel(item.name + " 图标")
            VStack(alignment: .leading, spacing: 5) {
                HStack(spacing: 8) {
                    Text(item.name).font(.system(size: 15, weight: .medium)).lineLimit(1)
                    if !item.version.isEmpty { Text(item.version).font(.caption).foregroundStyle(.secondary) }
                    Text(item.badge).font(.system(size: 10, weight: .medium)).foregroundStyle(item.reusable ? brandTint : .secondary)
                        .padding(.horizontal, 6).padding(.vertical, 3).background((item.reusable ? brandTint : Color.secondary).opacity(0.08), in: Capsule())
                }
                Text(item.bundle.isEmpty ? URL(fileURLWithPath: item.path).lastPathComponent : item.bundle)
                    .font(.caption.monospaced()).foregroundStyle(.secondary).lineLimit(1)
                HStack(spacing: 10) {
                    Text(ByteCountFormatter.string(fromByteCount: item.size, countStyle: .file))
                    Text(Date(timeIntervalSince1970: item.modified), format: .dateTime.month().day().hour().minute())
                    Text(URL(fileURLWithPath: item.path).lastPathComponent).lineLimit(1).truncationMode(.middle)
                }.font(.system(size: 10)).foregroundStyle(.tertiary)
            }
            Spacer(minLength: 8)
            if item.reusable {
                Button("重新安装") { model.reuseLibraryIPA(item) }.disabled(model.busy || model.refreshing)
            } else if item.error.isEmpty && !item.partial && item.state == "encrypted" {
                Button("砸壳并导出") { model.reuseLibraryIPA(item) }.disabled(!model.canDecrypt)
            }
            Menu {
                Button("在 Finder 中显示") { model.revealIPA(item) }
                Button("校验加密状态") { model.verifyLibraryIPA(item) }.disabled(model.busy || model.refreshing)
            } label: { Image(systemName: "ellipsis").frame(width: 16) }
                .menuStyle(.borderlessButton).menuIndicator(.hidden).fixedSize().accessibilityLabel("IPA 文件操作")
        }.padding(.horizontal, 13).padding(.vertical, 15).contentShape(Rectangle())
            .background(model.localIPA == item.path ? brandTint.opacity(0.06) : Color.clear, in: RoundedRectangle(cornerRadius: 9))
            .onTapGesture { model.localIPA = item.path }
            .help(item.error.isEmpty ? item.path : item.error)
    }

    private var settingsPage: some View {
        ScrollView {
            VStack(alignment: .leading, spacing: 24) {
                deviceSection
                Divider()
                helperSection
                Divider()
                reinstallSection
                lastInstallSection
                Divider()
                DisclosureGroup("App Store 账号与项目") { accountSection.padding(.top, 14) }
            }.textFieldStyle(.roundedBorder).padding(30).frame(maxWidth: 820, alignment: .leading).frame(maxWidth: .infinity)
                .disabled(model.busy || model.refreshing)
        }
    }

    private var deviceSection: some View {
        VStack(alignment: .leading, spacing: 12) {
            HStack { Text("目标设备").font(.headline); Spacer(); Button("刷新") { model.refresh() } }
            Picker("iPhone / iPad", selection: $model.deviceID) {
                Text("自动检测（只连接一台设备）").tag("")
                ForEach(model.phones) { phone in Text("\(phone.name) · \(model.connectionLabel(phone))").tag(phone.id) }
            }
            Text("设备需解锁、信任这台 Mac 并启用开发者模式。Frida 必须使用 USB 数据线，LLDB 可无线连接。")
                .font(.caption).foregroundStyle(.secondary)
        }
    }

    private var helperSection: some View {
        VStack(alignment: .leading, spacing: 12) {
            HStack {
                Text("辅助 App").font(.headline)
                Spacer()
                Button("导入证书与描述文件…") { model.chooseImportFolder() }
            }
            signerPicker(debug: false)
            LabeledContent("固定 Bundle ID") { Text(model.bundle).font(.caption.monospaced()).textSelection(.enabled) }
            if !model.quotaMessage(for: model.helperSigner).isEmpty {
                Text(model.quotaMessage(for: model.helperSigner)).font(.caption).foregroundStyle(.secondary)
            }
            HStack {
                Button("验证构建与签名") { model.build() }.disabled(!model.signingReason(model.helperSigner).isEmpty)
                Button("构建并安装辅助 App") { model.install() }.disabled(!model.canDecrypt)
            }
            Text("每次砸壳沿用这个固定标识。首次安装后如需信任证书，按手机提示操作即可重试启动。")
                .font(.caption).foregroundStyle(.secondary)
        }
    }

    private var reinstallSection: some View {
        VStack(alignment: .leading, spacing: 14) {
            HStack {
                Text("脱壳后重新安装").font(.headline)
                Spacer()
                Button("从本地列表选择") { model.libraryFilter = "decrypted"; model.libraryQuery = ""; model.page = 1 }
                Button("选择 IPA…") { model.chooseDebugIPA() }
            }
            Text(model.debugIPA.isEmpty ? "导出完成后会自动填入 IPA，也可选择已有文件。" : model.debugIPA)
                .font(.caption).foregroundStyle(.secondary).textSelection(.enabled).lineLimit(2)
            Toggle("沿用辅助 App 的签名", isOn: Binding(get: { model.reuseHelperSigning }, set: { model.setReuseHelperSigning($0) }))
            if !model.reuseHelperSigning { signerPicker(debug: true) }
            else if !model.signingReason(model.debugSigner, debug: model.debugEnabled).isEmpty {
                Text(model.signingReason(model.debugSigner, debug: model.debugEnabled)).font(.caption).foregroundStyle(.orange)
            }
            Picker("安装用 Bundle ID", selection: $model.debugMode) {
                Text("复用辅助 App ID").tag("helper")
                Text("指定 ID / 最近使用").tag("custom")
            }
            if model.debugMode == "helper" {
                Text("\(model.bundle)\n安装后会替换手机上的辅助 App；下次砸壳时会重新构建并安装辅助 App。")
                    .font(.caption).foregroundStyle(.secondary).textSelection(.enabled)
            } else {
                HStack {
                    BundleIDField(text: $model.customBundle, suggestions: model.bundleHistory.map(\.bundle)).frame(height: 25)
                    Button("新建 ID…") { model.showNewBundle() }
                }
                Text("成功使用或新建的 ID 会记住最近 10 个，超出时移除最旧记录。复用已有 ID 会替换手机上的对应应用。")
                    .font(.caption).foregroundStyle(.secondary)
            }
            Toggle("启用动态调试（LLDB / Frida）", isOn: Binding(
                get: { model.debugEnabled && model.canEnableDebugging },
                set: { model.debugEnabled = model.canEnableDebugging && $0 }
            )).disabled(!model.canEnableDebugging)
            if model.debugPermissionDenied {
                Text("当前描述文件未授权调试权限，仅支持普通重签名安装。").font(.caption).foregroundStyle(.secondary)
            }
            Toggle("保留应用扩展（小组件 / 分享 / Watch）", isOn: $model.keepExtensions)
            Text(model.keepExtensions ? "扩展需要各自的签名和 App ID，可能需登录 Xcode 申请。" : "仅安装主 App，复用所选 ID；不安装小组件、分享与 Watch 扩展。原始 IPA 保持完整。")
                .font(.caption).foregroundStyle(.secondary)
            injectionSettings
            Toggle("砸壳导出后自动重新安装", isOn: $model.autoDebug)
            Button(model.debugEnabled ? "重签名并安装调试版" : "重签名并安装") { model.debugInstall() }
                .buttonStyle(.borderedProminent).controlSize(.large).disabled(!model.canDebugInstall)
        }
    }

    private var injectionSettings: some View {
        VStack(alignment: .leading, spacing: 10) {
            Toggle("重签名前注入自定义 dylib", isOn: $model.injectionEnabled)
            if model.injectionEnabled {
                HStack {
                    Button("添加 dylib…") { model.chooseInjectionDylibs() }
                    Text("已选择 \(model.injectionDylibs.count) 个").font(.caption).foregroundStyle(.secondary)
                }
                ForEach(model.injectionDylibs, id: \.self) { path in
                    HStack {
                        Image(systemName: "doc.badge.gearshape").foregroundStyle(.secondary)
                        Text(URL(fileURLWithPath: path).lastPathComponent).lineLimit(1).truncationMode(.middle).help(path)
                        Spacer()
                        Button { model.injectionDylibs.removeAll { $0 == path } } label: { Image(systemName: "minus.circle") }
                            .buttonStyle(.plain).help("移除此动态库")
                    }.font(.caption)
                }
                Toggle("注入 Substrate / libhooker 兼容库", isOn: $model.injectionSubstrate)
                Picker("Hook 库兼容模式", selection: $model.injectionCompatibility) {
                    Text("新版兼容 · 仅 arm64").tag("modern")
                    Text("旧版兼容 · arm64 + arm64e").tag("legacy")
                }.disabled(!model.injectionSubstrate)
                Text(model.injectionSubstrate ? "新版模式沿用本机 iPatch 的裁剪方式，移除内置 Hook 库的 arm64e 切片；自定义 dylib 保持原架构。" : "适用于不依赖 Substrate 的动态库；其他依赖可一并添加。")
                    .font(.caption).foregroundStyle(.secondary)
                Text("脱壳 → 注入安装副本 → 重新签名 → 安装。仅注入主 App，原 IPA 和所选 dylib 不会改写。")
                    .font(.caption).foregroundStyle(.secondary)
            }
        }
    }

    private var debuggerSettings: some View {
        VStack(alignment: .leading, spacing: 12) {
            Picker("LLDB 启动方式", selection: $model.lldbMode) {
                Text("Attach · 附加进程").tag("attach")
                Text("Launch · 重新启动").tag("launch")
            }
            Text(model.lldbMode == "attach" ? "App 已运行时直接附加，不重新启动；未运行时启动并暂停后附加。" : "重新启动 App，在开始执行时暂停并附加 LLDB；当前运行状态会重置。")
                .font(.caption).foregroundStyle(.secondary)
            Toggle("准备匹配版本的 Frida Gadget", isOn: $model.debugFrida).disabled(!model.debugEnabled)
            Picker("Frida 启动方式", selection: $model.fridaMode) {
                Text("Attach · 附加进程").tag("attach")
                Text("Spawn · 由 Frida 启动").tag("spawn")
            }
            Text(model.fridaMode == "attach" ? "App 已运行时直接附加；未运行时才启动。保留当前运行状态，不覆盖启动前 Hook。" : "由 Frida 启动 App，可在继续运行主线程前安装 Hook。")
                .font(.caption).foregroundStyle(.secondary)
            HStack {
                Text("Frida 环境")
                Menu {
                    Button("自动 · 优先 Conda base") { model.selectFrida("") }
                    ForEach(model.fridaEnvironments) { env in
                        Button(env.name + (env.available ? "" : " · 未安装 Frida")) { model.selectFrida(env.id) }.disabled(!env.available)
                    }
                } label: {
                    Text(model.fridaPath.isEmpty ? "自动 · 优先 Conda base" : model.fridaEnvironments.first(where: { $0.id == model.fridaPath })?.name ?? "自定义 Frida")
                }
                Button("选择其他 frida…") { model.chooseFrida() }
            }
            Text((model.fridaVersion.isEmpty ? "启动前检查版本" : "版本 \(model.fridaVersion)") + " · " + model.fridaPath)
                .font(.caption).foregroundStyle(.secondary).textSelection(.enabled)
        }
    }

    @ViewBuilder private var lastInstallSection: some View {
        if let session = model.debugSession {
            Divider()
            HStack {
                Label("已安装 · \(session.bundle)", systemImage: "checkmark.circle").font(.callout)
                Spacer()
                Button("前往调试 →") { model.page = 4 }
            }
        }
    }

    private var debugPage: some View {
        ScrollView {
            VStack(alignment: .leading, spacing: 24) {
                if let session = model.debugSession {
                    VStack(alignment: .leading, spacing: 12) {
                        Text("调试目标").font(.headline)
                        Text(session.bundle).font(.title3.monospaced()).textSelection(.enabled)
                        let phone = model.phones.first { $0.id == session.device }
                        Label(phone?.name ?? session.device, systemImage: "iphone").font(.callout)
                        Text(session.ipa).font(.caption).foregroundStyle(.secondary).textSelection(.enabled)
                        if session.debuggable {
                            HStack(spacing: 12) {
                                Button("打开 LLDB") { model.openDebugger("lldb") }.controlSize(.large)
                                Button("打开 Frida") { model.openDebugger("frida") }
                                    .buttonStyle(.borderedProminent).controlSize(.large).disabled(!model.fridaWired)
                                Button("刷新状态") { model.refresh() }
                            }
                            Text(model.fridaWired ? "目标设备已通过 USB 连接。切换调试器前，请先退出当前会话。" : "Frida 需要 USB 数据线连接目标设备；LLDB 可无线使用。")
                                .font(.caption).foregroundStyle(.secondary)
                        } else {
                            Text("此应用安装时未启用动态调试。请返回设备与签名，使用支持调试的描述文件重新安装。")
                                .font(.callout).foregroundStyle(.secondary)
                        }
                    }
                } else {
                    VStack(alignment: .leading, spacing: 10) {
                        Label("还没有可调试的应用", systemImage: "ladybug").font(.headline)
                        Text("在设备与签名中重新签名安装并启用动态调试，完成后会自动来到这里。")
                            .font(.callout).foregroundStyle(.secondary)
                    }
                }
                Button("前往设备与签名 →") { model.page = 2 }
                Divider()
                Text("调试器设置").font(.headline)
                debuggerSettings
            }.padding(30).frame(maxWidth: 820, alignment: .leading).frame(maxWidth: .infinity)
                .disabled(model.busy || model.refreshing)
        }
    }

    private var accountSection: some View {
        VStack(alignment: .leading, spacing: 12) {
            HStack {
                Label(model.loggedIn ? "Apple ID 已登录" : "Apple ID 未登录", systemImage: "person.crop.circle")
                Spacer()
                Button("登录 Apple ID…") { model.login() }.disabled(!model.hasIpatool)
            }
            Text("下载账号与 Xcode 签名账号分别管理。登录在终端完成，回到这里刷新即可。")
                .font(.caption).foregroundStyle(.secondary)
            Text("项目：\(model.root.path)").font(.caption.monospaced()).foregroundStyle(.secondary).textSelection(.enabled)
            if !model.statusErrors.isEmpty { Text(model.statusErrors).font(.caption).foregroundStyle(.orange).textSelection(.enabled) }
        }
    }

    private var newBundleSheet: some View {
        VStack(alignment: .leading, spacing: 16) {
            Text("新建 Bundle ID").font(.title2.weight(.semibold))
            Text(model.signers.first(where: { $0.id == model.debugSigner })?.label ?? "请先选择签名身份").font(.caption).foregroundStyle(.secondary)
            HStack {
                TextField("Bundle ID", text: $model.newBundleValue).textFieldStyle(.roundedBorder)
                Button("生成") { model.newBundleValue = "dev.unfairplayed.debug." + UUID().uuidString.replacingOccurrences(of: "-", with: "").prefix(8).lowercased() }
            }.disabled(model.busy)
            TextField("名称（可选）", text: $model.newBundleName).textFieldStyle(.roundedBorder).disabled(model.busy)
            Text(model.debugSigner.hasPrefix("xcode:") ? "通过所选 Xcode 团队申请 App ID 和当前设备的开发签名。已有有效签名会直接复用。" : "导入证书无需向 Apple 注册新 ID，创建后会保存到最近使用。")
                .font(.caption).foregroundStyle(.secondary)
            if model.debugSigner.hasPrefix("xcode:") && model.selectedPhone?.available != true {
                Text("请先连接并选择目标设备，再申请开发签名。").font(.caption).foregroundStyle(.orange)
            }
            if !model.newBundleError.isEmpty {
                Text(model.newBundleError).font(.callout).foregroundStyle(.orange).textSelection(.enabled)
            }
            if model.newBundleNeedsAccount { Button("打开 Xcode，处理账号登录") { model.openXcode() } }
            HStack {
                if model.busy { ProgressView().controlSize(.small); Text("正在申请，请稍候…").font(.caption) }
                Spacer()
                if model.busy { Button("停止申请") { model.stop() } }
                else {
                    Button("取消") { model.bundleSheet = false }
                    Button(model.newBundleError.isEmpty ? "创建并使用" : "重新申请") { model.createBundle() }
                        .buttonStyle(.borderedProminent).disabled(!model.canCreateBundle)
                }
            }
        }.padding(26).frame(width: 560).interactiveDismissDisabled(model.busy)
    }

    @ViewBuilder
    private func signerPicker(debug: Bool) -> some View {
        let selection = Binding<String>(get: { debug ? model.debugSigner : model.helperSigner },
                                        set: { if debug { model.selectDebugSigner($0) } else { model.selectHelperSigner($0) } })
        HStack {
            Text("签名身份")
            Menu {
                Section("Xcode 开发团队") {
                    ForEach(model.signers.filter { $0.source == "xcode" }) { signer in
                        Button(signer.label) { selection.wrappedValue = signer.id }
                    }
                }
                Section("导入的证书与描述文件") {
                    ForEach(model.signers.filter { $0.source == "imported" }) { signer in
                        let reason = model.signingReason(signer.id, debug: false)
                        Button(signer.label + (reason.isEmpty ? "" : " · " + reason)) { selection.wrappedValue = signer.id }
                            .disabled(!reason.isEmpty)
                    }
                }
            } label: {
                Text(model.signers.first(where: { $0.id == selection.wrappedValue })?.label ?? "请选择签名身份")
                    .lineLimit(1)
            }
        }
        let reason = model.signingReason(selection.wrappedValue, debug: false)
        if !reason.isEmpty { Text(reason).font(.caption).foregroundStyle(.orange) }
    }

    private var importSigningSheet: some View {
        VStack(alignment: .leading, spacing: 18) {
            Text("导入签名材料").font(.title2.weight(.semibold))
            Text(model.importFolder).font(.caption).foregroundStyle(.secondary).textSelection(.enabled)
            SecureField("P12 证书密码（无密码可留空）", text: $model.importPassword).textFieldStyle(.roundedBorder)
                .onSubmit { model.importSigning() }
            Text("支持子目录中的多组证书。私钥存入独立钥匙串，P12 密码不会保存；不同密码的证书请分批导入。")
                .font(.caption).foregroundStyle(.secondary)
            if !model.importError.isEmpty { Text(model.importError).foregroundStyle(.orange).font(.caption).textSelection(.enabled) }
            HStack {
                if model.refreshing { ProgressView().controlSize(.small) }
                Spacer()
                Button("取消") { model.importPassword = ""; model.importSheet = false }.disabled(model.refreshing)
                Button("导入") { model.importSigning() }.buttonStyle(.borderedProminent).disabled(model.refreshing)
            }
        }.padding(26).frame(width: 500).interactiveDismissDisabled(model.refreshing)
    }

    private var logsPage: some View {
        VStack(alignment: .leading, spacing: 16) {
            HStack {
                if model.busy { ProgressView().controlSize(.small) }
                Text(model.stage).font(.headline)
                Spacer()
                Button("日志目录") { model.revealTaskLogs() }
                Button("保存完整日志…") { model.exportLog() }
                if model.pendingExport != nil && !model.busy {
                    Button("重试启动") { model.retryExport() }
                }
                if model.completedExport != nil && !model.busy {
                    Button("卸载辅助 App") { model.askingToUninstall = true }
                }
                if model.busy { Button("停止任务", role: .destructive) { model.stop() } }
            }
            if !model.activeLogPath.isEmpty {
                Text("完整日志实时保存（界面仅显示最近部分）：" + model.activeLogPath).font(.caption).foregroundStyle(.secondary).textSelection(.enabled)
            }
            if !model.logPersistenceError.isEmpty {
                Text(model.logPersistenceError).font(.caption).foregroundStyle(.orange).textSelection(.enabled)
            }
            ScrollViewReader { scroll in
                ScrollView([.horizontal, .vertical]) {
                    VStack(alignment: .leading, spacing: 0) {
                        Text(model.log).font(.system(size: 11, design: .monospaced)).textSelection(.enabled).fixedSize(horizontal: true, vertical: true)
                        Color.clear.frame(height: 1).id("end")
                    }.padding(16).frame(minWidth: 650, alignment: .leading)
                }
                .background(Color(nsColor: .textBackgroundColor), in: RoundedRectangle(cornerRadius: 9))
                .overlay(RoundedRectangle(cornerRadius: 9).stroke(.secondary.opacity(0.15)))
                .onChange(of: model.log) { _ in if model.busy { scroll.scrollTo("end", anchor: .bottomLeading) } }
            }
            Text("校验检查 Mach-O 的 cryptid；PARTIAL 表示仍有文件未成功处理。设备运行日志与构建日志同时保留在输出目录。")
                .font(.caption).foregroundStyle(.secondary)
        }.padding(25)
    }

    private func emptyState(icon: String, title: String, detail: String) -> some View {
        VStack(spacing: 14) {
            Image(systemName: icon).font(.system(size: 38, weight: .light)).foregroundStyle(.tertiary)
            Text(title).font(.title3.weight(.medium))
            Text(detail).font(.callout).foregroundStyle(.secondary).multilineTextAlignment(.center).lineSpacing(5).frame(maxWidth: 330)
        }.frame(maxWidth: .infinity, maxHeight: .infinity).padding(25)
    }
}

final class AppDelegate: NSObject, NSApplicationDelegate {
    func applicationShouldTerminateAfterLastWindowClosed(_ sender: NSApplication) -> Bool { true }
    func applicationDidFinishLaunching(_ notification: Notification) {
        NSApp.setActivationPolicy(.regular)
        NSApp.activate(ignoringOtherApps: true)
    }
    func applicationShouldTerminate(_ sender: NSApplication) -> NSApplication.TerminateReply {
        // Closing a long-running export should require an explicit choice.
        if DesktopApp.workspace?.busy == true {
            let alert = NSAlert()
            alert.messageText = "任务仍在运行"
            alert.informativeText = "退出会停止当前下载、构建或导出。"
            alert.addButton(withTitle: "继续运行")
            alert.addButton(withTitle: "停止并退出")
            if alert.runModal() == .alertFirstButtonReturn { return .terminateCancel }
            DesktopApp.workspace?.stop()
        }
        return .terminateNow
    }
}

@main
struct DesktopApp: App {
    static var workspace: Workspace?
    @NSApplicationDelegateAdaptor(AppDelegate.self) var delegate
    @StateObject private var model = Workspace()
    var body: some Scene {
        WindowGroup("Unfairplayed") {
            ContentView().environmentObject(model).onAppear { Self.workspace = model }
        }
        .defaultSize(width: 1120, height: 790)
        .commands {
            CommandGroup(replacing: .newItem) {
                Button("选择 IPA…") { model.chooseIPA() }.keyboardShortcut("o")
                Button("打开输出目录") { model.revealOutput() }.keyboardShortcut("o", modifiers: [.command, .shift])
                Divider()
                Button("刷新环境状态") { model.refresh() }.keyboardShortcut("r")
            }
        }
    }
}
