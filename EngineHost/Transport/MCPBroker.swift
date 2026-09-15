import Foundation

@MainActor
// Gates MCP in the engine, and replaces raw credential replies with pipe metadata.
final class MCPBroker {
    private enum Request {
        case list
        case prepare(session: String)
    }

    private let pipes: PasswordPipes
    private let forward: (String, String) -> Void
    private let reply: (String, String) -> Void
    private let cancel: (String) -> Void
    private var pending: [String: Request] = [:]
    private var deliveries: [String: (lease: String, session: String)] = [:]
    private(set) var enabled = false
    private(set) var state = "starting"

    init(pipes: PasswordPipes, forward: @escaping (String, String) -> Void,
         reply: @escaping (String, String) -> Void, cancel: @escaping (String) -> Void) {
        self.pipes = pipes
        self.forward = forward
        self.reply = reply
        self.cancel = cancel
    }

    func setEnabled(_ value: Bool) {
        enabled = value
        if !value { invalidate(code: "mcp_disabled", message: "Enable MCP in Passtrami Settings.") }
    }

    func setState(_ value: String) {
        state = value
        if value != "unlocked" { pipes.revokeAll() }
    }

    func revokePipes() { pipes.revokeAll() }

    func invalidate(code: String = "cancelled", message: String = "The password request was cancelled.") {
        pipes.revokeAll()
        let clients = Array(pending.keys)
        pending.removeAll()
        for id in clients {
            cancel("mcp:" + id)
            send(id, failure(code, message))
        }
    }

    func disconnected(_ id: String) {
        if pending.removeValue(forKey: id) != nil { cancel("mcp:" + id) }
    }

    func responseFinished(_ id: String, delivered: Bool) {
        guard let delivery = deliveries.removeValue(forKey: id) else { return }
        if !delivered { pipes.revoke(delivery.lease, session: delivery.session) }
    }

    // Return false only for the existing CLI protocol.
    func receive(_ id: String, text: String) -> Bool {
        guard let object = try? JSONSerialization.jsonObject(with: Data(text.utf8)) as? [String: Any],
              let op = object["op"] as? String, op.hasPrefix("mcp_") else { return false }
        if op == "mcp_status" {
            send(id, ["ok": true, "enabled": enabled, "state": state])
            return true
        }
        if op == "mcp_close" {
            if let session = validSession(object) {
                pipes.revoke(session: session)
                let clients = pending.keys.filter {
                    if case let .prepare(owner) = pending[$0] { return owner == session }
                    return false
                }
                for client in clients { disconnected(client); send(client, failure("cancelled", "The MCP client disconnected.")) }
                send(id, ["ok": true])
            } else { send(id, failure("invalid_request", "A valid MCP session is required.")) }
            return true
        }
        guard enabled else {
            send(id, failure("mcp_disabled", "Enable MCP in Passtrami Settings."))
            return true
        }
        if op == "mcp_revoke" {
            guard let session = validSession(object), let lease = object["lease_id"] as? String, UUID(uuidString: lease) != nil else {
                send(id, failure("invalid_request", "A valid pipe ID and MCP session are required."))
                return true
            }
            pipes.revoke(lease, session: session)
            send(id, ["ok": true])
            return true
        }
        guard op == "mcp_list" || op == "mcp_prepare",
              let domain = object["domain"] as? String, SessionScript.hostname(domain) != nil else {
            send(id, failure("invalid_request", "Use a website domain or an HTTP(S) URL."))
            return true
        }
        guard pending.count < 16 else {
            send(id, failure("busy", "Too many pending MCP requests. Try again after a request finishes."))
            return true
        }
        var request: [String: Any] = ["op": "list", "domain": domain]
        if op == "mcp_prepare" {
            guard let session = validSession(object), let username = object["username"] as? String,
                  !username.isEmpty, !username.contains(where: { $0.isNewline || $0 == "\0" }) else {
                send(id, failure("invalid_request", "An account name and valid MCP session are required."))
                return true
            }
            pending[id] = .prepare(session: session)
            request["op"] = "get"
            request["username"] = username
        } else { pending[id] = .list }
        let data = try! JSONSerialization.data(withJSONObject: request)
        forward("mcp:" + id, String(decoding: data, as: UTF8.self))
        return true
    }

    func receiveReply(_ id: String, text: String) {
        guard let request = pending.removeValue(forKey: id) else { return }
        guard enabled else { send(id, failure("mcp_disabled", "Enable MCP in Passtrami Settings.")); return }
        guard let result = try? JSONSerialization.jsonObject(with: Data(text.utf8)) as? [String: Any] else {
            send(id, failure("internal", "The password service sent an invalid response.")); return
        }
        guard result["ok"] as? Bool == true else {
            // Error text from Apple's response must not become an MCP result.
            let code = result["code"] as? String ?? "internal"
            let errors = [
                "not_found": "No password matched the domain and account.",
                "ambiguous": "More than one password matched. Select a more specific account.",
                "locked": "Unlock the password service and try again.",
                "cancelled": "The password request was cancelled.",
                "timeout": "The password request timed out.",
                "invalid_request": "The domain or account is invalid."
            ]
            send(id, failure(errors[code] == nil ? "internal" : code, errors[code] ?? "The password request failed."))
            return
        }
        switch request {
        case .list:
            guard let usernames = result["usernames"] as? [String] else {
                send(id, failure("internal", "The password service sent an invalid account list.")); return
            }
            send(id, ["ok": true, "usernames": usernames])
        case let .prepare(session):
            guard state == "unlocked", let password = result["password"] as? String else {
                send(id, failure("locked", "Unlock the password service and try again.")); return
            }
            do {
                var metadata = try pipes.create(password: password, session: session)
                metadata["ok"] = true
                deliveries[id] = (metadata["lease_id"] as! String, session)
                send(id, metadata)
            } catch {
                let failure = error as? EngineFailure ?? EngineFailure("pipe_create", "Could not create the password pipe.")
                send(id, self.failure(failure.code, failure.message))
            }
        }
    }

    private func validSession(_ object: [String: Any]) -> String? {
        guard let session = object["session"] as? String, UUID(uuidString: session) != nil else { return nil }
        return session
    }

    private func failure(_ code: String, _ message: String) -> [String: Any] {
        ["ok": false, "code": code, "message": message]
    }

    private func send(_ id: String, _ value: [String: Any]) {
        let data = try! JSONSerialization.data(withJSONObject: value)
        reply(id, String(decoding: data, as: UTF8.self))
    }
}
