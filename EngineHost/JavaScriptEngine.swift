import Darwin
import Foundation

@MainActor
// Owns native I/O. SessionScript decides when to unlock, send requests, or stop.
final class JavaScriptEngine {
    private let resources: URL
    private let dataDirectory: URL
    private var script: SessionScript?
    private var cli: CLIListener?
    private var mcp: MCPBroker?
    private var bridge: BridgeListener?
    private var port: UInt16 = 0
    private var browser: BrowserSession?
    private var readyBrowserRuntime: BrowserRuntime.Status?
    private var startup: Task<Void, Never>?
    private var timers: [String: Task<Void, Never>] = [:]
    private var signals: [DispatchSourceSignal] = []
    private var input = Data()
    private var stopping = false
    private var instanceLock: EngineInstanceLock?
    private var authorizations = Set<String>()
    private var phoneApprovalRequired: Bool
    private var approvalPolicyRevision = 0
    private lazy var passwordAccess = TouchIDPreferenceWindow(directory: dataDirectory) { [weak self] accessID in
        Task { @MainActor in self?.deliver(["type": "passwordAccessExpired", "accessID": accessID]) }
    }

    init(resources: URL, dataDirectory: URL, phoneApprovalRequired: Bool = false) {
        self.resources = resources
        self.dataDirectory = dataDirectory
        self.phoneApprovalRequired = phoneApprovalRequired
    }

    func start() async throws {
        try requireFullDiskAccess()
        try FileManager.default.createDirectory(at: dataDirectory, withIntermediateDirectories: true,
                                                attributes: [.posixPermissions: 0o700])
        try FileManager.default.setAttributes([.posixPermissions: 0o700], ofItemAtPath: dataDirectory.path)
        instanceLock = try EngineInstanceLock(directory: dataDirectory)
        try await passwordAccess.recover(requireEnabled: phoneApprovalRequired)
        let pipes = try PasswordPipes(directory: dataDirectory.appendingPathComponent("password-pipes"))
        mcp = MCPBroker(pipes: pipes, forward: { [weak self] id, text in
            self?.deliver(["type": "request", "connection": id, "text": text])
        }, reply: { [weak self] id, text in
            self?.cli?.reply(id: id, json: text)
        }, cancel: { [weak self] id in
            self?.deliver(["type": "clientClosed", "connection": id])
        })
        script = try SessionScript(directory: resources.appendingPathComponent("Engine"), onPost: { [weak self] in
            self?.handle($0)
        }, onFailure: { [weak self] in
            self?.emit(["type": "state", "state": "error", "message": "The password service failed. Select Unlock to try again."])
            Task { await self?.shutdown(exitCode: 1) }
        })
        let listener = BridgeListener(onOpen: { [weak self] id in
            self?.deliver(["type": "bridgeOpen", "connection": id])
        }, onText: { [weak self] id, text in
            self?.deliver(["type": "bridgeText", "connection": id, "text": text])
        }, onClose: { [weak self] id in
            self?.deliver(["type": "bridgeClosed", "connection": id])
        })
        bridge = listener
        port = try await listener.start()
        cli = try CLIListener(path: dataDirectory.appendingPathComponent("passtrami.sock").path, onRequest: { [weak self] id, text in
            if self?.mcp?.receive(id, text: text) == true { return }
            self?.deliver(["type": "request", "connection": id, "text": text])
        }, onDisconnect: { [weak self] id in
            self?.mcp?.disconnected(id)
            self?.deliver(["type": "clientClosed", "connection": id])
        }, onFinish: { [weak self] id, delivered in
            self?.mcp?.responseFinished(id, delivered: delivered)
        })
        FileHandle.standardInput.readabilityHandler = { [weak self] handle in
            let data = handle.availableData
            if data.isEmpty { handle.readabilityHandler = nil }
            DispatchQueue.main.async { self?.readInput(data) }
        }
        signal(SIGPIPE, SIG_IGN)
        for number in [SIGINT, SIGTERM] {
            signal(number, SIG_IGN)
            let source = DispatchSource.makeSignalSource(signal: number, queue: .main)
            source.setEventHandler { [weak self] in
                MainActor.assumeIsolated { self?.command(["op": "shutdown"]) }
            }
            signals.append(source)
            source.resume()
        }
        deliver(["type": "ready"])
    }

    private func deliver(_ event: [String: Any]) {
        guard !stopping else { return }
        script?.receive(event)
    }

    private func handle(_ text: String) {
        guard !stopping, let data = text.data(using: .utf8),
              let message = try? JSONSerialization.jsonObject(with: data) as? [String: Any],
              let operation = message["op"] as? String else { return }
        let id = message["id"] as? String ?? ""
        let connection = message["connection"] as? String ?? ""
        switch operation {
        case "authorizePassword":
            guard let domain = message["domain"] as? String, let username = message["username"] as? String else { return }
            authorizations.insert(id)
            Task { [weak self] in
                guard let self else { return }
                do {
                    // A failed restore must also block later requests that use local approval.
                    try await passwordAccess.recover(requireEnabled: phoneApprovalRequired)
                    guard !stopping, authorizations.contains(id) else { return }
                    emit(["type": "deviceApprovalRequired", "id": id, "domain": domain, "username": username])
                } catch {
                    guard authorizations.remove(id) != nil else { return }
                    complete(id, error: EngineFailure("password_access", "Could not restore the password approval setting."))
                }
            }
        case "cancelAuthorization":
            authorizations.remove(id)
            emit(["type": "deviceApprovalCancelled", "id": id])
        case "beginPasswordAccess", "endPasswordAccess":
            guard let accessID = message["accessID"] as? String else { return }
            Task { [weak self] in
                guard let self else { return }
                do {
                    if operation == "beginPasswordAccess" { try await passwordAccess.begin(accessID) }
                    else { try await passwordAccess.end(accessID) }
                    complete(id)
                } catch {
                    // A failed guard need not discard Apple's authenticated session
                    // once protection is verified restored. Never return a password
                    // from the failed operation; subsequent requests reauthorize.
                    var restored = false
                    do {
                        try await passwordAccess.recover(requireEnabled: true)
                        restored = true
                    } catch { }
                    complete(id, error: EngineFailure("password_access", "Could not restore or change the password approval setting."),
                             result: ["accessRestored": restored])
                }
            }
        case "emit":
            if let event = message["event"] as? [String: Any] { emit(event) }
        case "timer":
            guard let milliseconds = message["milliseconds"] as? Int, milliseconds >= 0 else { return }
            timers[id] = Task { [weak self] in
                do { try await Task.sleep(for: .milliseconds(milliseconds)) } catch { return }
                self?.timers.removeValue(forKey: id)
                self?.deliver(["type": "timer", "id": id])
            }
        case "cancelTimer": timers.removeValue(forKey: id)?.cancel()
        case "send":
            if let text = message["text"] as? String { bridge?.send(id: connection, text: text) }
        case "disconnect": bridge?.disconnect(id: connection)
        case "bridgeAuthenticated": bridge?.authenticated(id: connection)
        case "reply":
            if let text = message["text"] as? String {
                if connection.hasPrefix("mcp:") {
                    mcp?.receiveReply(String(connection.dropFirst(4)), text: text)
                } else { cli?.reply(id: connection, json: text) }
            }
        case "closeClient":
            if connection.hasPrefix("mcp:") {
                let id = String(connection.dropFirst(4))
                mcp?.disconnected(id)
                cli?.disconnect(id: id)
            } else { cli?.disconnect(id: connection) }
        case "startBrowser":
            guard let token = message["token"] as? String else { return }
            startup = Task { [weak self] in
                guard let self else { return }
                do {
                    try requireFullDiskAccess()
                    do { try await passwordAccess.recover(requireEnabled: phoneApprovalRequired) }
                    catch {
                        throw EngineFailure("password_access", "Could not restore the password approval setting. Select Unlock to retry.")
                    }
                    try Task.checkCancellation()
                    let executable = try await BrowserRuntime.resolve(dataDirectory: dataDirectory) { [weak self] status in
                        self?.updateBrowserRuntime(status)
                        if [.checking, .downloading, .installing].contains(status.phase), let message = status.message {
                            self?.deliver(["type": "progress", "token": token, "message": message])
                        }
                    }
                    try requireFullDiskAccess()
                    let session = try await BrowserSession.start(executable: executable, resources: resources,
                        dataDirectory: dataDirectory, port: port, token: token) { [weak self] in
                            self?.deliver(["type": "browserExited", "token": token])
                        }
                    if Task.isCancelled { await session.stop(); throw CancellationError() }
                    browser = session
                    complete(id)
                } catch {
                    let failure = error as? EngineFailure ?? EngineFailure("browser_start", "Could not start the password browser.")
                    complete(id, error: failure)
                }
            }
        case "stopBrowser":
            mcp?.revokePipes()
            Task { [weak self] in
                guard let self else { return }
                await stopBrowser()
                complete(id)
            }
        case "shutdown": Task { await shutdown(exitCode: 0) }
        default: break
        }
    }

    private func requireFullDiskAccess() throws {
        switch FullDiskAccessCheck.checkRequiredLocation() {
        case .available:
            return
        case .required:
            throw EngineFailure("full_disk_access", "Full Disk Access is required. Open Settings to continue.")
        case .missingPreferences:
            throw EngineFailure("full_disk_access", "Apple Passwords settings are missing. Open Safari once, then retry setup.")
        case .unavailable:
            throw EngineFailure("full_disk_access", "Apple Passwords settings are unavailable. Open Settings to continue.")
        }
    }

    private func complete(_ id: String, error: EngineFailure? = nil, result: [String: Any]? = nil) {
        var event: [String: Any] = ["type": "nativeResult", "id": id]
        if let error { event["error"] = ["code": error.code, "message": error.message] }
        if let result { event["result"] = result }
        deliver(event)
    }

    private func readInput(_ data: Data) {
        guard !stopping else { return }
        if data.isEmpty {
            command(["op": "shutdown"])
            return
        }
        input.append(data)
        guard input.count <= 1_048_576 else {
            Task { await shutdown(exitCode: 1) }
            return
        }
        while let newline = input.firstIndex(of: 0x0A) {
            let line = Data(input[..<newline])
            input.removeSubrange(...newline)
            guard let value = try? JSONSerialization.jsonObject(with: line) as? [String: Any],
                  value["op"] is String else { continue }
            command(value)
        }
    }

    private func command(_ value: [String: Any]) {
        if value["op"] as? String == "phoneApprovalPolicy" {
            guard let required = value["required"] as? Bool else { return }
            // Storage loss can change local approval to unavailable while both
            // states report false. Every policy event revokes prior access.
            phoneApprovalRequired = required
            approvalPolicyRevision += 1
            let revision = approvalPolicyRevision
            mcp?.invalidate()
            deliver(["type": "approvalPolicyChanged"])
            if required {
                Task { [weak self] in
                    guard let self else { return }
                    do { try await passwordAccess.recover(requireEnabled: true) }
                    catch {
                        guard !stopping, revision == approvalPolicyRevision else { return }
                        deliver(["type": "approvalRecoveryFailed",
                                 "message": "Could not enable the password approval setting. Select Unlock to retry."])
                    }
                }
            }
            return
        }
        if value["op"] as? String == "deviceApprovalResult" {
            guard let id = value["id"] as? String, authorizations.remove(id) != nil else { return }
            if let message = value["error"] as? String {
                complete(id, error: EngineFailure("device_approval", message))
            } else {
                let remote = value["remote"] as? Bool == true
                if phoneApprovalRequired && !remote {
                    complete(id, error: EngineFailure("device_approval", "iPhone approval is required."))
                } else { complete(id, result: ["remote": remote]) }
            }
            return
        }
        if value["op"] as? String == "mcp" {
            if let enabled = value["enabled"] as? Bool { mcp?.setEnabled(enabled) }
            return
        }
        if ["lock", "shutdown"].contains(value["op"] as? String ?? "") {
            mcp?.invalidate()
            for id in authorizations {
                emit(["type": "deviceApprovalCancelled", "id": id])
                complete(id, error: EngineFailure("cancelled", "Request cancelled."))
            }
            authorizations.removeAll()
        }
        deliver(["type": "command", "command": value])
    }

    private func emit(_ event: [String: Any]) {
        if event["type"] as? String == "state", let state = event["state"] as? String { mcp?.setState(state) }
        guard var data = try? JSONSerialization.data(withJSONObject: event) else { return }
        data.append(0x0A)
        try? FileHandle.standardOutput.write(contentsOf: data)
    }

    private func updateBrowserRuntime(_ status: BrowserRuntime.Status) {
        switch status.phase {
        case .ready: readyBrowserRuntime = status
        case .downloading, .failed: readyBrowserRuntime = nil
        default: break
        }
        let current = status.phase == .idle ? readyBrowserRuntime ?? status : status
        emit(["type": "browserRuntime", "browserRuntime": current.value])
    }

    private func stopBrowser() async {
        let pending = startup
        pending?.cancel()
        await pending?.value
        startup = nil
        let current = browser
        browser = nil
        await current?.stop()
    }

    private func shutdown(exitCode: Int32) async {
        guard !stopping else { return }
        mcp?.invalidate()
        stopping = true
        try? await passwordAccess.recover(requireEnabled: phoneApprovalRequired)
        FileHandle.standardInput.readabilityHandler = nil
        for task in timers.values { task.cancel() }
        timers.removeAll()
        await stopBrowser()
        cli?.close()
        bridge?.close()
        for source in signals { source.cancel() }
        exit(exitCode)
    }
}
