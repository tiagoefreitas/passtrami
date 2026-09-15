import Darwin
import Foundation

private final class BlockingFIFOReader: @unchecked Sendable {
    let started = DispatchSemaphore(value: 0)
    let finished = DispatchSemaphore(value: 0)
    private let lock = NSLock()
    private var result: Int?

    var byteCount: Int? { lock.withLock { result } }

    func start(path: String) {
        DispatchQueue.global(qos: .userInitiated).async { [self] in
            started.signal()
            let descriptor = open(path, O_RDONLY | O_NOFOLLOW | O_CLOEXEC)
            var count = -2
            if descriptor >= 0 {
                var byte: UInt8 = 0
                count = Darwin.read(descriptor, &byte, 1)
                Darwin.close(descriptor)
            }
            lock.withLock { result = count }
            finished.signal()
        }
    }
}

@MainActor
private final class MCPFixture {
    let root: URL
    let pipes: PasswordPipes
    var forwarded: [(String, String)] = []
    var responses: [(String, String)] = []
    var cancelled: [String] = []
    var instant = ContinuousClock.now
    lazy var broker = MCPBroker(pipes: pipes, forward: { [unowned self] in forwarded.append(($0, $1)) },
                               reply: { [unowned self] in responses.append(($0, $1)) },
                               cancel: { [unowned self] in cancelled.append($0) },
                               now: { [unowned self] in instant })

    init(lifetime: Duration = .seconds(60), limit: Int = 16) throws {
        root = URL(fileURLWithPath: "/private/tmp").appendingPathComponent("passtrami-mcp-tests-\(UUID().uuidString)")
        try FileManager.default.createDirectory(at: root, withIntermediateDirectories: false,
                                                attributes: [.posixPermissions: 0o700])
        pipes = try PasswordPipes(directory: root.appendingPathComponent("pipes"), lifetime: lifetime, limit: limit)
    }

    func close() {
        broker.invalidate()
        try? FileManager.default.removeItem(at: root)
    }

    @discardableResult
    func request(_ id: String, _ value: [String: Any]) throws -> Bool {
        broker.receive(id, text: String(decoding: try JSONSerialization.data(withJSONObject: value), as: UTF8.self))
    }

    func nativeReply(_ id: String, _ value: [String: Any]) throws {
        broker.receiveReply(id, text: String(decoding: try JSONSerialization.data(withJSONObject: value), as: UTF8.self))
    }

    func response(_ id: String) throws -> [String: Any] {
        guard let text = responses.last(where: { $0.0 == id })?.1,
              let value = try JSONSerialization.jsonObject(with: Data(text.utf8)) as? [String: Any] else {
            throw EngineFailure("test", "The MCP fixture did not receive a JSON response.")
        }
        return value
    }
}

@MainActor
private func mcpWait(_ message: String, until condition: () -> Bool) async throws {
    let deadline = ContinuousClock.now + .seconds(2)
    while !condition() {
        try engineExpect(ContinuousClock.now < deadline, message)
        try await Task.sleep(for: .milliseconds(5))
    }
}

@MainActor
private func readPasswordPipe(_ path: String, expected: Data) async throws {
    let descriptor = open(path, O_RDONLY | O_NONBLOCK | O_NOFOLLOW | O_CLOEXEC)
    try engineExpect(descriptor >= 0, "The FIFO reader could not open the lease.")
    defer { Darwin.close(descriptor) }
    var received = Data()
    var buffer = [UInt8](repeating: 0, count: Int(PIPE_BUF) + 1)
    let deadline = ContinuousClock.now + .seconds(2)
    while received.count < expected.count {
        let count = Darwin.read(descriptor, &buffer, buffer.count)
        if count > 0 { received.append(contentsOf: buffer.prefix(count)) }
        else if count < 0 && errno != EAGAIN && errno != EWOULDBLOCK && errno != EINTR {
            throw EngineFailure("test", "The FIFO read failed.")
        }
        try engineExpect(ContinuousClock.now < deadline, "The FIFO did not deliver the credential.")
        if received.count < expected.count { try await Task.sleep(for: .milliseconds(5)) }
    }
    try engineExpect(received == expected, "The FIFO changed the credential bytes.")
    try engineExpect(Darwin.read(descriptor, &buffer, buffer.count) == 0, "The FIFO wrote extra bytes or remained open.")
    var info = stat()
    try engineExpect(lstat(path, &info) != 0 && errno == ENOENT, "The consumed FIFO still has a pathname.")
}

@MainActor
private func testBlockingReaderRevocation(password: String, session: String) throws {
    let f = try MCPFixture(); defer { f.close() }
    let metadata = try f.pipes.create(password: password, session: session)
    let reader = BlockingFIFOReader()
    reader.start(path: metadata["path"] as! String)
    try engineExpect(reader.started.wait(timeout: .now() + 1) == .success, "The blocking FIFO reader did not start.")
    // This test is synchronous so MainActor cannot poll and deliver the credential first.
    usleep(50_000)
    try engineExpect(reader.finished.wait(timeout: .now()) == .timedOut, "The FIFO reader did not block before revocation.")
    f.pipes.revokeAll()
    try engineExpect(reader.finished.wait(timeout: .now() + 1) == .success, "Revocation left a consumer blocked in FIFO open.")
    try engineExpect(reader.byteCount == 0, "Revocation delivered credential bytes instead of EOF.")
    try engineExpect(f.pipes.count == 0 && !FileManager.default.fileExists(atPath: metadata["path"] as! String), "Revocation left the blocking-reader lease active.")
}

@MainActor
func runMCPTests() async throws {
    let session = UUID().uuidString, otherSession = UUID().uuidString
    let sentinel = "fixture-only-\u{1F512}\n\u{0}-end"
    func prepare(_ session: String) -> [String: Any] {
        ["op": "mcp_prepare", "session": session, "domain": "https://EXAMPLE.test/login", "username": "person"]
    }

    // Approval retention is scoped to normalized account + MCP session, never the CLI socket.
    do {
        let f = try MCPFixture(); defer { f.close() }
        f.broker.setEnabled(true); f.broker.setState("unlocked")
        try f.request("first", prepare(session))
        try engineExpect(!f.broker.hasRetainedApproval(for: "mcp:first"), "Unapproved work reused approval.")
        f.broker.retainApproval(for: "mcp:first")
        try f.nativeReply("first", ["ok": true, "password": sentinel])
        f.broker.disconnected("first") // Each tool call has its own short-lived engine socket.
        var same = prepare(session); same["domain"] = "example.test"
        try f.request("same", same)
        try engineExpect(f.broker.hasRetainedApproval(for: "mcp:same"), "A new call on the same MCP connection lost approval.")
        try engineExpect(!f.broker.hasRetainedApproval(for: "same"), "CLI access inherited MCP approval.")
        for (id, field, value) in [("other-session", "session", otherSession),
                                   ("other-account", "username", "someone-else"),
                                   ("other-domain", "domain", "other.example.test")] {
            var changed = same; changed[field] = value
            try f.request(id, changed)
            try engineExpect(!f.broker.hasRetainedApproval(for: "mcp:" + id), "Approval crossed an account or connection boundary.")
        }
        f.instant = f.instant.advanced(by: .seconds(7_199))
        try engineExpect(f.broker.hasRetainedApproval(for: "mcp:same"), "Default approval did not last two hours.")
        f.instant = f.instant.advanced(by: .seconds(1))
        try engineExpect(!f.broker.hasRetainedApproval(for: "mcp:same"), "Reuse extended approval or accepted the expiry boundary.")
    }

    for cause in ["close", "lock", "disable", "policy", "duration"] {
        let f = try MCPFixture(); defer { f.close() }
        f.broker.setEnabled(true); f.broker.setState("unlocked")
        try f.request("first", prepare(session))
        f.broker.retainApproval(for: "mcp:first")
        switch cause {
        case "close": try f.request("close", ["op": "mcp_close", "session": session])
        case "lock": f.broker.setState("locked"); f.broker.setState("unlocked")
        case "disable": f.broker.setEnabled(false); f.broker.setEnabled(true)
        case "duration": f.broker.setApprovalRetention(seconds: 900)
        default: f.broker.invalidate()
        }
        try f.request("next", prepare(session))
        try engineExpect(!f.broker.hasRetainedApproval(for: "mcp:next"), "Revocation retained an approval: " + cause)
    }

    do {
        let f = try MCPFixture(); defer { f.close() }
        f.broker.setEnabled(true); f.broker.setState("unlocked")
        f.broker.setApprovalRetention(seconds: 0)
        try f.request("disabled-retention", prepare(session))
        f.broker.retainApproval(for: "mcp:disabled-retention")
        try engineExpect(!f.broker.hasRetainedApproval(for: "mcp:disabled-retention"), "Never retained an approval.")
        f.broker.setApprovalRetention(seconds: 900)
        try f.request("short", prepare(session)); f.broker.retainApproval(for: "mcp:short")
        f.instant = f.instant.advanced(by: .seconds(900))
        try engineExpect(!f.broker.hasRetainedApproval(for: "mcp:short"), "Custom duration was ignored.")
    }

    try engineExpect(SessionDiagnostics.message(sentinel) == nil, "Diagnostics accepted an arbitrary event.")
    try engineExpect(SessionDiagnostics.message("request_failed", detail: sentinel) == "request_failed", "Diagnostics exposed error contents.")
    try engineExpect(SessionDiagnostics.message("apple_error", value: 9) == "apple_error status=9", "Apple status was lost.")
    try engineExpect(SessionDiagnostics.message("apple_error", value: 999_999) == nil, "Diagnostics accepted an unbounded numeric value.")

    // Disabled access does not reach the session engine. Existing CLI requests still pass through.
    do {
        let f = try MCPFixture(); defer { f.close() }
        try engineExpect(try f.request("disabled", prepare(session)), "MCP was not intercepted.")
        try engineExpect(f.forwarded.isEmpty && f.response("disabled")["code"] as? String == "mcp_disabled", "Disabled MCP reached the password service.")
        try engineExpect(try !f.request("cli", ["op": "get", "domain": "example.test", "username": "person"]), "The MCP broker captured the CLI protocol.")
        try f.request("status", ["op": "mcp_status"])
        try engineExpect(try f.response("status")["enabled"] as? Bool == false, "MCP status did not report the default disabled state.")
    }

    // Successful list and prepare responses cannot expose extra native fields or plaintext.
    do {
        let f = try MCPFixture(); defer { f.close() }
        f.broker.setEnabled(true)
        try f.request("list", ["op": "mcp_list", "domain": "example.test"])
        try engineExpect(f.forwarded.first?.0 == "mcp:list", "MCP did not use a reserved request identity.")
        let listRequest = try JSONSerialization.jsonObject(with: Data(f.forwarded[0].1.utf8)) as! [String: Any]
        try engineExpect(listRequest["op"] as? String == "list", "The account list requested a password.")
        try f.nativeReply("list", ["ok": true, "usernames": ["person"], "password": sentinel, "extra": sentinel])
        let list = try f.response("list")
        try engineExpect(Set(list.keys) == ["ok", "usernames"] && list["usernames"] as? [String] == ["person"], "The account result did not filter native fields.")
        try f.request("prepare", prepare(session))
        f.broker.setState("starting")
        f.broker.setState("pairing")
        try engineExpect(f.cancelled.isEmpty, "Normal unlock progress cancelled the pending MCP request.")
        f.broker.setState("unlocked")
        try f.nativeReply("prepare", ["ok": true, "password": sentinel, "extra": sentinel])
        let metadata = try f.response("prepare")
        try engineExpect(metadata["ok"] as? Bool == true && metadata["single_use"] as? Bool == true && metadata["format"] as? String == "utf8", "The pipe metadata is incomplete.")
        try engineExpect(metadata["password"] == nil && !f.responses.contains(where: { $0.1.contains("fixture-only") }), "MCP exposed a credential in a response.")
        guard let path = metadata["path"] as? String else { throw EngineFailure("test", "The pipe metadata has no path.") }
        var fifoInfo = stat(), directoryInfo = stat()
        try engineExpect(lstat(path, &fifoInfo) == 0 && fifoInfo.st_mode & S_IFMT == S_IFIFO && fifoInfo.st_mode & 0o777 == 0o600 && fifoInfo.st_uid == getuid(), "The FIFO is not private and owned by this user.")
        try engineExpect(lstat(URL(fileURLWithPath: path).deletingLastPathComponent().path, &directoryInfo) == 0 && directoryInfo.st_mode & 0o777 == 0o700, "The FIFO directory is not private.")
        try await readPasswordPipe(path, expected: Data(sentinel.utf8))
        try engineExpect(f.pipes.count == 0, "The consumed lease remained active.")
    }

    // Arbitrary native error messages, codes and malformed responses cannot become MCP text.
    do {
        let f = try MCPFixture(); defer { f.close() }
        f.broker.setEnabled(true); f.broker.setState("unlocked")
        for (index, reply) in [["ok": false, "code": "not_found", "message": sentinel],
                              ["ok": false, "code": sentinel, "message": sentinel],
                              ["ok": true, "usernames": sentinel, "password": sentinel]].enumerated() {
            let id = "error-\(index)"
            try f.request(id, ["op": "mcp_list", "domain": "example.test"])
            try f.nativeReply(id, reply)
            try engineExpect(try f.response(id)["ok"] as? Bool == false, "A malformed native error became success.")
        }
        try f.request("invalid-json", prepare(session))
        f.broker.receiveReply("invalid-json", text: sentinel)
        try engineExpect(try f.response("invalid-json")["ok"] as? Bool == false, "Invalid native JSON became success.")
        try engineExpect(!f.responses.contains(where: { $0.1.contains("fixture-only") }), "MCP exposed credential data through error text.")
    }

    // Invalid fields and excess pending work must fail before authentication begins.
    do {
        let f = try MCPFixture(); defer { f.close() }
        f.broker.setEnabled(true)
        for domain in ["", "file:///example.test", "https://user:password@example.test", "not a domain"] {
            try f.request(UUID().uuidString, ["op": "mcp_list", "domain": domain])
        }
        for username in ["", "line\nfeed", "return\rname", "null\0name"] {
            var request = prepare(session); request["username"] = username
            try f.request(UUID().uuidString, request)
        }
        try f.request("bad-owner", prepare("not-a-UUID"))
        try engineExpect(f.forwarded.isEmpty, "Invalid MCP fields reached authentication.")
        for index in 0..<16 { try f.request("pending-\(index)", prepare(session)) }
        try f.request("overflow", prepare(session))
        try engineExpect(f.forwarded.count == 16 && f.response("overflow")["code"] as? String == "busy", "Pending MCP requests are not bounded.")
    }

    // Disconnect, disable and explicit lock invalidate pending work; late replies are discarded.
    do {
        let f = try MCPFixture(); defer { f.close() }
        f.broker.setEnabled(true); f.broker.setState("unlocked")
        try f.request("cancelled", prepare(session)); f.broker.disconnected("cancelled")
        try f.nativeReply("cancelled", ["ok": true, "password": sentinel])
        try engineExpect(f.cancelled == ["mcp:cancelled"] && f.responses.isEmpty && f.pipes.count == 0, "Disconnected MCP work created a lease or response.")
        try f.request("disabled", prepare(session)); f.broker.setEnabled(false)
        f.broker.setEnabled(true)
        let responses = f.responses.count
        try f.nativeReply("disabled", ["ok": true, "password": sentinel])
        try engineExpect(f.responses.count == responses && f.pipes.count == 0 && f.cancelled.contains("mcp:disabled"), "Re-enabling MCP restored a stale request.")
        try f.request("locked", prepare(session)); f.broker.invalidate()
        try f.nativeReply("locked", ["ok": true, "password": sentinel])
        try engineExpect(f.pipes.count == 0 && f.cancelled.contains("mcp:locked"), "Explicit lock retained pending MCP work.")
    }

    // Lost metadata cannot leave an unused secret lease behind.
    do {
        let f = try MCPFixture(); defer { f.close() }
        f.broker.setEnabled(true); f.broker.setState("unlocked")
        try f.request("lost-metadata", prepare(session))
        try f.nativeReply("lost-metadata", ["ok": true, "password": sentinel])
        try engineExpect(f.pipes.count == 1, "The metadata failure fixture has no lease.")
        f.broker.responseFinished("lost-metadata", delivered: false)
        try engineExpect(f.pipes.count == 0, "A failed metadata delivery retained its credential lease.")
        try f.request("delivered-metadata", prepare(session))
        try f.nativeReply("delivered-metadata", ["ok": true, "password": sentinel])
        f.broker.responseFinished("delivered-metadata", delivered: true)
        // Duplicate completion must not revoke a lease whose metadata was already delivered.
        f.broker.responseFinished("delivered-metadata", delivered: false)
        try engineExpect(f.pipes.count == 1, "A completed metadata delivery revoked its usable lease.")
        let metadata = try f.response("delivered-metadata")
        try await readPasswordPipe(metadata["path"] as! String, expected: Data(sentinel.utf8))
    }

    // Session ownership limits revocation; state changes revoke all issued leases.
    do {
        let f = try MCPFixture(); defer { f.close() }
        f.broker.setEnabled(true); f.broker.setState("unlocked")
        let metadata = try f.pipes.create(password: sentinel, session: session)
        let id = metadata["lease_id"] as! String
        try f.request("wrong-owner", ["op": "mcp_revoke", "session": otherSession, "lease_id": id])
        try engineExpect(f.pipes.count == 1, "Another MCP session revoked a lease.")
        try f.request("owner", ["op": "mcp_revoke", "session": session, "lease_id": id])
        try engineExpect(f.pipes.count == 0, "The lease owner could not revoke its pipe.")
        for state in ["starting", "pairing", "locked", "error"] {
            f.broker.setState("unlocked")
            _ = try f.pipes.create(password: sentinel, session: session)
            f.broker.setState(state)
            try engineExpect(f.pipes.count == 0, "A state change retained issued password pipes.")
        }
        try f.request("closing", prepare(session))
        _ = try f.pipes.create(password: sentinel, session: session)
        _ = try f.pipes.create(password: sentinel, session: otherSession)
        try f.request("close", ["op": "mcp_close", "session": session])
        try engineExpect(f.pipes.count == 1 && f.cancelled.contains("mcp:closing"), "Session close did not isolate lease cleanup and cancellation.")
    }

    // Unread leases expire, large passwords are refused and issued leases are bounded.
    do {
        let f = try MCPFixture(lifetime: .milliseconds(60), limit: 2); defer { f.close() }
        let first = try f.pipes.create(password: sentinel, session: session)
        _ = try f.pipes.create(password: sentinel, session: session)
        do { _ = try f.pipes.create(password: sentinel, session: session); throw EngineFailure("test", "The FIFO limit was ignored.") }
        catch let error as EngineFailure { try engineExpect(error.code == "pipe_limit", "The FIFO limit returned the wrong failure.") }
        try await mcpWait("Unread leases did not expire.") { f.pipes.count == 0 }
        try engineExpect(!FileManager.default.fileExists(atPath: first["path"] as! String), "An expired FIFO remained on disk.")
        for password in ["", String(repeating: "x", count: Int(PIPE_BUF) + 1)] {
            do { _ = try f.pipes.create(password: password, session: session); throw EngineFailure("test", "An invalid-size password was accepted.") }
            catch let error as EngineFailure { try engineExpect(error.code == "password_size", "Password size returned the wrong failure.") }
        }
        try engineExpect(f.pipes.count == 0, "Rejected passwords retained leases.")
    }

    // Restart cleanup removes only owned UUID FIFOs, leaving ordinary files and links intact.
    do {
        let f = try MCPFixture(); defer { f.close() }
        let directory = f.root.appendingPathComponent("restart")
        try FileManager.default.createDirectory(at: directory, withIntermediateDirectories: false, attributes: [.posixPermissions: 0o700])
        let stale = directory.appendingPathComponent(UUID().uuidString).path
        let ordinary = directory.appendingPathComponent(UUID().uuidString).path
        let link = directory.appendingPathComponent(UUID().uuidString).path
        let unrelated = directory.appendingPathComponent("unrelated-fifo").path
        try engineExpect(mkfifo(stale, 0o600) == 0 && mkfifo(unrelated, 0o600) == 0, "The stale FIFO fixture could not be created.")
        try Data("ordinary fixture".utf8).write(to: URL(fileURLWithPath: ordinary))
        try engineExpect(symlink(ordinary, link) == 0, "The stale link fixture could not be created.")
        let restarted = try PasswordPipes(directory: directory)
        defer { restarted.revokeAll() }
        var info = stat()
        try engineExpect(lstat(stale, &info) != 0 && errno == ENOENT, "Restart retained a stale owned FIFO.")
        try engineExpect(lstat(ordinary, &info) == 0 && info.st_mode & S_IFMT == S_IFREG, "Restart removed an ordinary file.")
        try engineExpect(lstat(link, &info) == 0 && info.st_mode & S_IFMT == S_IFLNK, "Restart followed or removed a link.")
        try engineExpect(lstat(unrelated, &info) == 0 && info.st_mode & S_IFMT == S_IFIFO, "Restart removed an unrelated FIFO.")
        for path in [ordinary, link] {
            do { _ = try PasswordPipes(directory: URL(fileURLWithPath: path)); throw EngineFailure("test", "An invalid pipe directory was accepted.") }
            catch let error as EngineFailure { try engineExpect(error.code == "pipe_directory", "An invalid pipe directory returned the wrong failure.") }
        }
        var ownerInfo = stat()
        if lstat("/private/var/root", &ownerInfo) == 0, ownerInfo.st_uid != getuid() {
            do {
                _ = try PasswordPipes(directory: URL(fileURLWithPath: "/private/var/root"))
                throw EngineFailure("test", "A directory owned by another user was accepted.")
            } catch let error as EngineFailure {
                try engineExpect(error.code == "pipe_directory", "A foreign directory returned the wrong failure.")
            }
        }
    }

    // Replaced lease paths cannot receive plaintext, and cleanup must not delete the replacement.
    for replacement in ["file", "symlink", "fifo", "permissions"] {
        let f = try MCPFixture(); defer { f.close() }
        let metadata = try f.pipes.create(password: sentinel, session: session)
        let path = metadata["path"] as! String
        if replacement == "permissions" { try engineExpect(chmod(path, 0o644) == 0, "The permission fixture failed.") }
        else {
            try engineExpect(unlink(path) == 0, "The replacement fixture could not unlink the FIFO.")
            if replacement == "file" { try Data("ordinary fixture".utf8).write(to: URL(fileURLWithPath: path)) }
            else if replacement == "fifo" { try engineExpect(mkfifo(path, 0o600) == 0, "The replacement FIFO fixture failed.") }
            else { try engineExpect(symlink("/dev/null", path) == 0, "The replacement link fixture failed.") }
        }
        try await mcpWait("An unsafe FIFO replacement retained its lease.") { f.pipes.count == 0 }
        var info = stat()
        try engineExpect(lstat(path, &info) == 0, "FIFO cleanup removed a replacement path.")
        if replacement == "file" { try engineExpect(try Data(contentsOf: URL(fileURLWithPath: path)) == Data("ordinary fixture".utf8), "The engine wrote a credential to an ordinary file.") }
    }

    // A reader that exits before delivery cannot stall the engine or extend expiry.
    do {
        let f = try MCPFixture(lifetime: .milliseconds(60)); defer { f.close() }
        let metadata = try f.pipes.create(password: sentinel, session: session)
        let descriptor = open(metadata["path"] as! String, O_RDONLY | O_NONBLOCK | O_CLOEXEC)
        try engineExpect(descriptor >= 0, "The disconnecting reader fixture could not open the FIFO.")
        Darwin.close(descriptor)
        try await mcpWait("An exited reader kept its lease alive.") { f.pipes.count == 0 }
        try engineExpect(!FileManager.default.fileExists(atPath: metadata["path"] as! String), "An exited reader left a stale FIFO.")
    }

    // Revocation must release a consumer already blocked in open(O_RDONLY) with EOF.
    try testBlockingReaderRevocation(password: sentinel, session: session)
}
