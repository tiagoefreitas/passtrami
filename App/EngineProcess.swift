import Foundation
import Darwin

enum EngineState: String, Decodable, Sendable {
    case starting, locked, pairing, unlocked, error
}

struct EngineEvent: Decodable, Sendable {
    let type: String
    let state: EngineState?
    let message: String?
    var browserRuntime: BrowserRuntimeStatus? = nil
    var id: String? = nil
    var domain: String? = nil
    var username: String? = nil
    var retainedApproval: Bool? = nil
}

@MainActor
final class EngineProcess {
    var onEvent: ((EngineEvent) -> Void)?
    private var process: Process?
    private var input: Pipe?
    private var outputReader: EngineOutputReader?
    private var pendingOutput = Data()
    private var lastEngineError: String?
    private var stopping = false
    // Ignore output and exit callbacks from an earlier child after a restart.
    private var processGeneration = UUID()

    var isRunning: Bool { process?.isRunning == true }

    func start(phoneApprovalRequired: Bool) throws {
        guard !isRunning else { return }
        guard let resources = Bundle.main.resourceURL else {
            throw CocoaError(.fileNoSuchFile)
        }
        let child = Process()
        let generation = UUID()
        processGeneration = generation
        let stdin = Pipe()
        let stdout = Pipe()
        child.executableURL = resources.appendingPathComponent("passtrami-engine")
        child.arguments = [
            "--resources", resources.path,
            "--data-dir", FileManager.default.homeDirectoryForCurrentUser
                .appendingPathComponent("Library/Application Support/io.zats.Passtrami").path
        ]
        if phoneApprovalRequired { child.arguments?.append("--require-phone-approval") }
        child.standardInput = stdin
        child.standardOutput = stdout
        child.standardError = FileHandle.nullDevice
        stopping = false
        pendingOutput.removeAll(keepingCapacity: false)
        lastEngineError = nil
        let reader = try EngineOutputReader(handle: stdout.fileHandleForReading) { [weak self] data in
            DispatchQueue.main.async { [weak self] in self?.receive(data, generation: generation) }
        }
        child.terminationHandler = { [weak self] _ in
            // Drain queued output before exit reaches the main queue. A descendant may
            // still hold stdout open, so the drain must not wait for EOF.
            reader.finish { [weak self] in
                DispatchQueue.main.async { [weak self] in self?.didExit(generation: generation) }
            }
        }
        process = child
        input = stdin
        outputReader = reader
        do {
            // Queue app-owned access policy before the child can accept requests.
            try writeCommand(["op": "mcp", "enabled": MCPSettings().isEnabled,
                              "approvalRetentionSeconds": MCPSettings().approvalRetentionSeconds], to: stdin.fileHandleForWriting)
            try child.run()
        } catch {
            reader.finish {}
            child.terminationHandler = nil
            process = nil
            input = nil
            outputReader = nil
            throw error
        }
    }

    func send(_ operation: String, pin: String? = nil) {
        var command: [String: Any] = ["op": operation]
        if let pin { command["pin"] = pin }
        sendCommand(command)
    }

    func setMCPEnabled(_ enabled: Bool) {
        sendCommand(["op": "mcp", "enabled": enabled,
                     "approvalRetentionSeconds": MCPSettings().approvalRetentionSeconds])
    }

    func setPhoneApprovalRequired(_ required: Bool) {
        sendCommand(["op": "phoneApprovalPolicy", "required": required])
    }

    func finishDeviceApproval(id: String, remote: Bool = false, error: String? = nil) {
        var command: [String: Any] = ["op": "deviceApprovalResult", "id": id, "remote": remote]
        if let error { command["error"] = error }
        sendCommand(command)
    }

    private func sendCommand(_ command: [String: Any]) {
        guard isRunning, let input else { return }
        do {
            try writeCommand(command, to: input.fileHandleForWriting)
        } catch {
            reportError("Could not contact the password service.")
        }
    }

    private func writeCommand(_ command: [String: Any], to handle: FileHandle) throws {
        var data = try JSONSerialization.data(withJSONObject: command)
        data.append(0x0A)
        try handle.write(contentsOf: data)
    }

    func shutdown() async {
        stopping = true
        guard let child = process else { return }
        send("shutdown")
        // Allow a cancelled runtime install to detach its disk image before exit.
        let deadline = Date().addingTimeInterval(30)
        while child.isRunning && Date() < deadline {
            try? await Task.sleep(for: .milliseconds(50))
        }
        if child.isRunning {
            child.terminate()
            let terminationDeadline = Date().addingTimeInterval(4)
            while child.isRunning && Date() < terminationDeadline {
                try? await Task.sleep(for: .milliseconds(50))
            }
        }
        if child.isRunning { kill(child.processIdentifier, SIGKILL) }
        try? input?.fileHandleForWriting.close()
    }

    private func receive(_ data: Data, generation: UUID) {
        guard generation == processGeneration, !stopping, !data.isEmpty else { return }
        pendingOutput.append(data)
        guard pendingOutput.count <= 1_048_576 else {
            pendingOutput.removeAll(keepingCapacity: false)
            reportError("The password service sent an invalid response.")
            return
        }
        while let newline = pendingOutput.firstIndex(of: 0x0A) {
            let line = Data(pendingOutput[..<newline])
            pendingOutput.removeSubrange(...newline)
            guard !line.isEmpty else { continue }
            guard let event = try? JSONDecoder().decode(EngineEvent.self, from: line) else {
                reportError("The password service sent an invalid response.")
                continue
            }
            if event.type == "state", let state = event.state {
                if state != .error {
                    lastEngineError = nil
                } else if let message = event.message, !message.isEmpty {
                    lastEngineError = message
                }
            }
            onEvent?(event)
        }
    }

    private func didExit(generation: UUID) {
        guard generation == processGeneration else { return }
        outputReader = nil
        try? input?.fileHandleForWriting.close()
        if !stopping {
            reportError(lastEngineError ?? "The password service stopped. Select Unlock to try again.")
        }
    }

    private func reportError(_ message: String) {
        onEvent?(EngineEvent(type: "state", state: .error, message: message))
    }
}

// Mutable reader state is confined to its serial queue. Callbacks enqueue data and
// exit on the main queue in the same order, including when the child exits at once.
private final class EngineOutputReader: @unchecked Sendable {
    private let queue = DispatchQueue(label: "io.zats.Passtrami.engine-output")
    private let source: DispatchSourceRead
    private let handle: FileHandle
    private let onData: @Sendable (Data) -> Void
    private var finished = false

    init(handle: FileHandle, onData: @escaping @Sendable (Data) -> Void) throws {
        let descriptor = handle.fileDescriptor
        let flags = fcntl(descriptor, F_GETFL)
        guard flags != -1, fcntl(descriptor, F_SETFL, flags | O_NONBLOCK) != -1 else {
            throw POSIXError(POSIXErrorCode(rawValue: errno) ?? .EIO)
        }
        self.handle = handle
        self.onData = onData
        source = DispatchSource.makeReadSource(fileDescriptor: descriptor, queue: queue)
        source.setEventHandler { [weak self] in self?.drain() }
        source.setCancelHandler { try? handle.close() }
        source.resume()
    }

    func finish(_ completion: @escaping @Sendable () -> Void) {
        queue.async {
            if !self.finished {
                self.drain()
                self.finished = true
                self.source.cancel()
            }
            completion()
        }
    }

    private func drain() {
        guard !finished else { return }
        // Bound each pass even if an inherited writer continues producing output.
        var remaining = 1_048_576
        var bytes = [UInt8](repeating: 0, count: 65_536)
        while remaining > 0 {
            let count = Darwin.read(handle.fileDescriptor, &bytes, min(bytes.count, remaining))
            if count > 0 {
                onData(Data(bytes.prefix(count)))
                remaining -= count
            } else if count == -1 && errno == EINTR {
                continue
            } else {
                if count == 0 || (errno != EAGAIN && errno != EWOULDBLOCK) {
                    finished = true
                    source.cancel()
                }
                return
            }
        }
    }
}
