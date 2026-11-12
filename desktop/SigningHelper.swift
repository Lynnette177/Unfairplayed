import Foundation
import Security
import CryptoKit

// Passwords arrive on stdin. Imported private keys stay in a dedicated local
// keychain; its random unlock password is stored in the user's login keychain.
enum SigningError: LocalizedError {
    case message(String)
    var errorDescription: String? { if case .message(let text) = self { return text }; return nil }
}

func checked(_ status: OSStatus, _ operation: String) throws {
    guard status == errSecSuccess else {
        let detail = SecCopyErrorMessageString(status, nil) as String? ?? "OSStatus \(status)"
        throw SigningError.message("\(operation)：\(detail)")
    }
}

func credentialQuery(_ id: String) -> [String: Any] {
    [kSecClass as String: kSecClassGenericPassword,
     kSecAttrService as String: "dev.unfairplayed.signing-keychain",
     kSecAttrAccount as String: id]
}

func secret(_ id: String) throws -> Data {
    var query = credentialQuery(id)
    query[kSecReturnData as String] = true
    var result: CFTypeRef?
    try checked(SecItemCopyMatching(query as CFDictionary, &result), "读取签名钥匙串凭据")
    guard let data = result as? Data else { throw SigningError.message("签名钥匙串凭据无效") }
    return data
}

func storeSecret(_ id: String, _ data: Data) throws {
    var query = credentialQuery(id)
    query[kSecValueData as String] = data
    query[kSecAttrAccessible as String] = kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly
    try checked(SecItemAdd(query as CFDictionary, nil), "保存签名钥匙串凭据")
}

func unlock(_ id: String, _ path: String) throws -> SecKeychain {
    var keychain: SecKeychain?
    try checked(SecKeychainOpen(path, &keychain), "打开签名钥匙串")
    guard let keychain else { throw SigningError.message("无法打开签名钥匙串") }
    let password = try secret(id)
    try password.withUnsafeBytes { bytes in
        try checked(SecKeychainUnlock(keychain, UInt32(password.count), bytes.baseAddress, true), "解锁签名钥匙串")
    }
    return keychain
}

func metadata(_ identity: SecIdentity) throws -> [String: String] {
    var certificate: SecCertificate?
    try checked(SecIdentityCopyCertificate(identity, &certificate), "读取签名证书")
    guard let certificate else { throw SigningError.message("证书为空") }
    var key: SecKey?
    try checked(SecIdentityCopyPrivateKey(identity, &key), "读取证书私钥")
    let data = SecCertificateCopyData(certificate) as Data
    return ["sha1": Insecure.SHA1.hash(data: data).map { String(format: "%02X", $0) }.joined(),
            "certificate": data.base64EncodedString(),
            "name": SecCertificateCopySubjectSummary(certificate) as String? ?? "Imported identity"]
}

func importIdentity(_ data: Data, _ password: String, keychain: SecKeychain? = nil) throws -> SecIdentity {
    var options: [String: Any] = [kSecImportExportPassphrase as String: password]
    if let keychain {
        var trusted: SecTrustedApplication?
        try checked(SecTrustedApplicationCreateFromPath("/usr/bin/codesign", &trusted), "设置签名工具访问权限")
        var access: SecAccess?
        try checked(SecAccessCreate("Unfairplayed Signing" as CFString, [trusted!] as CFArray, &access), "创建私钥访问控制")
        options[kSecImportExportKeychain as String] = keychain
        options[kSecImportExportAccess as String] = access
    } else {
        if #available(macOS 15.0, *) { options[kSecImportToMemoryOnly as String] = true }
        else { throw SigningError.message("证书导入需要 macOS 15 或更新版本") }
    }
    var imported: CFArray?
    try checked(SecPKCS12Import(data as CFData, options as CFDictionary, &imported), "导入 P12（请确认密码及文件格式）")
    guard let items = imported as? [[String: Any]], items.count == 1,
          let value = items[0][kSecImportItemIdentity as String] else {
        throw SigningError.message("P12 必须包含一组证书及对应私钥")
    }
    return value as! SecIdentity
}

func run() throws -> [String: String] {
    let requestData = FileHandle.standardInput.readDataToEndOfFile()
    guard let request = try JSONSerialization.jsonObject(with: requestData) as? [String: String],
          let action = request["action"] else { throw SigningError.message("无效的签名请求") }
    if action == "inspect" {
        return try metadata(importIdentity(Data(contentsOf: URL(fileURLWithPath: request["p12"] ?? "")), request["password"] ?? ""))
    }
    guard let id = request["id"], let path = request["keychain"] else { throw SigningError.message("缺少签名钥匙串参数") }
    if action == "delete" {
        var keychain: SecKeychain?
        if SecKeychainOpen(path, &keychain) == errSecSuccess, let keychain {
            try checked(SecKeychainDelete(keychain), "清理未完成的签名钥匙串")
        }
        let status = SecItemDelete(credentialQuery(id) as CFDictionary)
        if status != errSecItemNotFound { try checked(status, "清理签名钥匙串凭据") }
        return ["deleted": id]
    }
    if action == "unlock" {
        _ = try unlock(id, path)
        return ["keychain": path]
    }
    guard action == "import", !FileManager.default.fileExists(atPath: path) else {
        throw SigningError.message("签名钥匙串已存在或操作无效")
    }
    // Validate in memory before creating persistent state.
    let p12 = try Data(contentsOf: URL(fileURLWithPath: request["p12"] ?? ""))
    _ = try importIdentity(p12, request["password"] ?? "")
    let password = Data((UUID().uuidString + UUID().uuidString).utf8)
    var keychain: SecKeychain?
    try password.withUnsafeBytes { bytes in
        try checked(SecKeychainCreate(path, UInt32(password.count), bytes.baseAddress, false, nil, &keychain), "创建签名钥匙串")
    }
    guard let keychain else { throw SigningError.message("签名钥匙串创建失败") }
    do {
        let identity = try importIdentity(p12, request["password"] ?? "", keychain: keychain)
        // security's partition-list command accepts only an argument password.
        // This is a random per-keychain secret, never the supplied P12 password.
        let process = Process()
        process.executableURL = URL(fileURLWithPath: "/usr/bin/security")
        process.arguments = ["set-key-partition-list", "-S", "apple-tool:,apple:,codesign:", "-s", "-k", String(decoding: password, as: UTF8.self), path]
        let pipe = Pipe(); process.standardOutput = pipe; process.standardError = pipe
        try process.run(); _ = pipe.fileHandleForReading.readDataToEndOfFile(); process.waitUntilExit()
        guard process.terminationStatus == 0 else { throw SigningError.message("设置 codesign 私钥访问权限失败") }
        try storeSecret(id, password)
        return try metadata(identity)
    } catch {
        SecKeychainDelete(keychain)
        throw error
    }
}

do {
    let result = try run()
    let data = try JSONSerialization.data(withJSONObject: result, options: [.sortedKeys])
    FileHandle.standardOutput.write(data)
    FileHandle.standardOutput.write(Data("\n".utf8))
} catch {
    FileHandle.standardError.write(Data((error.localizedDescription + "\n").utf8))
    exit(1)
}
