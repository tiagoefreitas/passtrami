import Foundation
import JavaScriptCore

@MainActor
private final class ScriptFixture {
    var script: SessionScript!
    var posts: [[String: Any]] = []
    var failed = false

    init(automaticallyAuthorizesPasswords: Bool = true) throws {
        script = try SessionScript(directory: URL(fileURLWithPath: "Engine"), onPost: { [weak self] text in
            if let object = try? JSONSerialization.jsonObject(with: Data(text.utf8)) as? [String: Any] {
                self?.posts.append(object)
                if automaticallyAuthorizesPasswords, object["op"] as? String == "authorizePassword" {
                    Task { [weak self] in self?.complete(object, result: ["remote": false]) }
                }
            }
        }, onFailure: { [weak self] in self?.failed = true })
    }

    func event(_ value: [String: Any]) { script.receive(value) }
    func command(_ op: String, pin: String? = nil) {
        var value = ["op": op]
        if let pin { value["pin"] = pin }
        event(["type": "command", "command": value])
    }
    func message(_ bridge: String, _ value: [String: Any]) throws {
        event(["type": "bridgeText", "connection": bridge,
               "text": String(decoding: try JSONSerialization.data(withJSONObject: value), as: UTF8.self)])
    }
    func state(_ bridge: String, _ state: String) throws {
        try message(bridge, ["type": "nativeState", "state": state])
    }
    func connect(_ bridge: String, token: String, state: String = "NotInSession") throws {
        event(["type": "bridgeOpen", "connection": bridge])
        try message(bridge, ["token": token])
        try self.state(bridge, state)
    }
    func request(_ id: String, op: String = "get", domain: String = "example.test", username: String = "person") throws {
        let text = String(decoding: try JSONSerialization.data(withJSONObject:
            ["op": op, "domain": domain, "username": username]), as: UTF8.self)
        event(["type": "request", "connection": id, "text": text])
    }
    func complete(_ operation: [String: Any], error: String? = nil,
                  code: String = "browser_start", result: [String: Any]? = nil) {
        var event: [String: Any] = ["type": "nativeResult", "id": operation["id"]!]
        if let error { event["error"] = ["code": code, "message": error] }
        if let result { event["result"] = result }
        self.event(event)
    }
    func take(_ op: String, connection: String? = nil) async throws -> [String: Any] {
        let end = ContinuousClock.now + .seconds(2)
        repeat {
            if let index = posts.firstIndex(where: { $0["op"] as? String == op && (connection == nil || $0["connection"] as? String == connection) }) {
                return posts.remove(at: index)
            }
            try engineExpect(!failed, "JavaScript threw an exception")
            try await Task.sleep(for: .milliseconds(2))
        } while ContinuousClock.now < end
        throw EngineFailure("test", "Missing JavaScript operation: \(op)")
    }
    func start() async throws -> String {
        event(["type": "ready"])
        let operation = try await take("startBrowser")
        complete(operation)
        return operation["token"] as! String
    }
    func sent(_ connection: String) async throws -> [String: Any] {
        let operation = try await take("send", connection: connection)
        return try JSONSerialization.jsonObject(with: Data((operation["text"] as! String).utf8)) as! [String: Any]
    }
    func response(_ connection: String) async throws -> [String: Any] {
        let operation = try await take("reply", connection: connection)
        return try JSONSerialization.jsonObject(with: Data((operation["text"] as! String).utf8)) as! [String: Any]
    }
    func status() async throws -> [String: Any] {
        try request("status", op: "status")
        return try await response("status")
    }
    func nativeReply(_ bridge: String, request: [String: Any], status: Int = 0) throws {
        try message(bridge, ["id": request["id"]!, "data": ["STATUS": status, "Entries": [
            ["USR": "person", "PWD": "fixture-only", "sites": ["example.test"]],
            ["USR": "person", "PWD": "Not Included", "sites": ["accounts.example.test"]]
        ]]])
    }
}

@MainActor
func runJavaScriptTests() async throws {
    let fixture = try ScriptFixture()
    var unitCount = 0
    var unitFailure: String?
    let test: @convention(block) (String, JSValue) -> Void = { name, function in
        fixture.script.context.exception = nil
        function.call(withArguments: [])
        if fixture.failed { unitFailure = name } else { unitCount += 1 }
    }
    fixture.script.context.setObject(test, forKeyedSubscript: "test" as NSString)
    fixture.script.context.setObject(try String(contentsOfFile: "Engine/bridge.js", encoding: .utf8),
                                     forKeyedSubscript: "__bridgeSource" as NSString)
    for name in ["credentials", "bridge"] {
        fixture.script.context.evaluateScript(try String(contentsOfFile: "Tests/Engine/\(name).js", encoding: .utf8))
        if let unitFailure { throw EngineFailure("test", unitFailure) }
        try engineExpect(!fixture.failed, "JavaScript unit fixture failed")
    }
    try engineExpect(unitCount == 14, "Some JavaScript unit tests did not run")
    try await runPolicyCancellationTests()
    try await runSessionReuseTests()

    // Native URL normalization is part of the credential trust boundary.
    for invalid in ["", "https://a:b@example.test", "https://a@example.test", "file:///example.test", "not a domain", "https://", "https://example.test%2fevil.test"] {
        try engineExpect(SessionScript.hostname(invalid) == nil, "Accepted an invalid website")
    }
    for (input, expected) in [("https://GOOGLE.com/path", "google.com"), ("google.com.", "google.com"),
                              ("https://example.test:443/login", "example.test"), ("https://bücher.example", "xn--bcher-kva.example")] {
        try engineExpect(SessionScript.hostname(input) == expected, "Website normalization changed")
    }

    // Settings can prepare or retry Chromium without starting a PIN challenge or a second setup.
    do {
        let f = try ScriptFixture()
        f.event(["type": "ready"])
        let first = try await f.take("startBrowser")
        f.command("prepareBrowser")
        f.command("prepareBrowser")
        try engineExpect(!f.posts.contains { $0["op"] as? String == "startBrowser" }, "Prepare duplicated the automatic browser setup")
        f.complete(first, error: "Fixture download failure")
        try engineExpect(try await f.status()["state"] as? String == "error", "Download failure did not finish setup")

        f.command("prepareBrowser")
        let retry = try await f.take("startBrowser")
        f.command("prepareBrowser")
        try engineExpect(!f.posts.contains { $0["op"] as? String == "startBrowser" }, "Prepare duplicated a retry")
        f.complete(retry)
        try f.connect("prepared", token: retry["token"] as! String)
        try engineExpect(try await f.status()["state"] as? String == "locked", "Prepare requested an unlock")
        f.command("prepareBrowser")
        try engineExpect(!f.posts.contains { $0["op"] as? String == "startBrowser" || $0["op"] as? String == "send" },
                         "Prepare restarted Chromium or sent a PIN challenge")
        try engineExpect(!f.posts.contains { ($0["event"] as? [String: Any])?["type"] as? String == "pinRequired" },
                         "Prepare opened the PIN window")
    }

    // Locked list waits for the PIN result and sends no password request.
    do {
        let f = try ScriptFixture(), token = try await f.start()
        try f.connect("bridge", token: token)
        try f.request("list", op: "list", domain: "https://EXAMPLE.test/path")
        try engineExpect(try await f.sent("bridge")["op"] as? String == "unlock", "List did not unlock")
        try f.state("bridge", "NotInSession")
        try engineExpect(try await f.status()["state"] as? String == "pairing", "Duplicate state cancelled pairing")
        try f.state("bridge", "MSG1Set")
        f.command("pin", pin: "12345")
        try engineExpect(!f.posts.contains { $0["op"] as? String == "send" }, "Accepted a short PIN")
        f.command("pin", pin: "123456")
        try engineExpect(try await f.sent("bridge")["op"] as? String == "pin", "PIN was not forwarded")
        try engineExpect(try await f.status()["state"] as? String == "pairing", "PIN submission unlocked before Apple replied")
        try f.state("bridge", "SessionKeySet")
        let request = try await f.sent("bridge")
        try engineExpect(request["cmd"] as? Int == 4, "List used a password command")
        try f.nativeReply("bridge", request: request)
        let response = try await f.response("list")
        try engineExpect(response["usernames"] as? [String] == ["person"] && response["password"] == nil, "List leaked a password or kept duplicates")
    }

    // Cancellation at queue, unlock, and native-request stages must be isolated.
    for op in ["get", "list"] {
        let f = try ScriptFixture(), token = try await f.start()
        try f.connect("bridge", token: token, state: "SessionKeySet")
        try f.request("first", op: op)
        let first = try await f.sent("bridge")
        try f.request("cancelled", op: op)
        f.event(["type": "clientClosed", "connection": "cancelled"])
        try f.request("next", op: op)
        try f.nativeReply("bridge", request: first)
        _ = try await f.response("first")
        let next = try await f.sent("bridge")
        try f.nativeReply("bridge", request: next)
        _ = try await f.response("next")
        try engineExpect(!f.posts.contains { $0["op"] as? String == "reply" && $0["connection"] as? String == "cancelled" }, "Cancelled client got a reply")

        try f.request("inflight", op: op)
        let stale = try await f.sent("bridge")
        try f.request("after", op: op)
        f.event(["type": "clientClosed", "connection": "inflight"])
        let stop = try await f.take("stopBrowser")
        try engineExpect(!f.posts.contains { $0["op"] as? String == "startBrowser" }, "New browser started before old browser stopped")
        f.complete(stop)
        let start = try await f.take("startBrowser")
        try engineExpect(start["token"] as? String != token, "New session reused token")
        f.complete(start)
        try f.nativeReply("bridge", request: stale)
        try f.connect("new", token: start["token"] as! String, state: "SessionKeySet")
        let after = try await f.sent("new")
        try f.nativeReply("new", request: after)
        _ = try await f.response("after")
    }

    do {
        let f = try ScriptFixture(), token = try await f.start()
        try f.connect("bridge", token: token)
        try f.request("waiting")
        _ = try await f.sent("bridge")
        f.event(["type": "clientClosed", "connection": "waiting"])
        f.complete(try await f.take("stopBrowser"))
        try engineExpect(try await f.status()["state"] as? String == "locked", "Cancelled unlock left pairing active")
        try f.connect("old", token: token, state: "SessionKeySet")
        _ = try await f.take("disconnect", connection: "old")
        try engineExpect(try await f.status()["state"] as? String == "locked", "Accepted old token after lock")
    }

    // Timeouts and native locks end the old session before retrying.
    for cause in ["timeout", "locked", "relogin", "bridgeClosed", "browserExited"] {
        let f = try ScriptFixture(), token = try await f.start()
        try f.connect("bridge", token: token, state: "SessionKeySet")
        try f.request("request")
        let request = try await f.sent("bridge")
        if cause == "timeout" {
            let timer = f.posts.last { $0["op"] as? String == "timer" && $0["milliseconds"] as? Int == 120000 }!
            f.event(["type": "timer", "id": timer["id"]!])
        } else if cause == "locked" { try f.nativeReply("bridge", request: request, status: 9) }
        else if cause == "relogin" {
            try f.state("bridge", "CheckEngine")
            try f.state("bridge", "NotInSession")
        }
        else if cause == "bridgeClosed" { f.event(["type": cause, "connection": "bridge"]) }
        else { f.event(["type": cause, "token": token]) }
        f.complete(try await f.take("stopBrowser"))
        if cause == "timeout" {
            try engineExpect(try await f.response("request")["code"] as? String == "timeout", "Timeout was not returned")
        } else {
            let start = try await f.take("startBrowser")
            f.complete(start)
            try f.connect("new", token: start["token"] as! String, state: "SessionKeySet")
            let retry = try await f.sent("new")
            try f.nativeReply("new", request: retry)
            try engineExpect(try await f.response("request")["password"] as? String == "fixture-only", "Retry failed")
        }
    }

    // Helper and approval recovery failures must release the browser before an app or CLI retry.
    for cause in ["helper", "approvalRecovery"] {
        for op in ["unlock", "get", "list"] {
            let f = try ScriptFixture(), token = try await f.start()
            try f.connect("old", token: token, state: "SessionKeySet")
            if cause == "helper" { try f.state("old", "NativeSupportNotInstalled") }
            else {
                f.event(["type": "approvalRecoveryFailed", "message": "Fixture approval recovery failed."])
            }
            try engineExpect(try await f.status()["state"] as? String == "error", "Session failure did not reach the error state")
            let stop = try await f.take("stopBrowser")
            if op == "unlock" { f.command("unlock") }
            else { try f.request("retry", op: op) }
            try engineExpect(!f.posts.contains { $0["op"] as? String == "startBrowser" }, "Recovery started before the old browser stopped")
            f.complete(stop)
            let start = try await f.take("startBrowser")
            try engineExpect(start["token"] as? String != token, "Recovery reused the failed session")
            f.complete(start)
            try f.state("old", "SessionKeySet")
            try engineExpect(try await f.status()["state"] as? String != "unlocked", "The failed helper restored an old session")
            try f.connect("new", token: start["token"] as! String)
            try engineExpect(try await f.sent("new")["op"] as? String == "unlock", "Recovery did not request pairing")
            try f.state("new", "MSG1Set")
            try engineExpect(f.posts.contains {
                $0["op"] as? String == "emit" && ($0["event"] as? [String: Any])?["type"] as? String == "pinRequired"
            }, "Recovery did not request the PIN window")
            f.command("pin", pin: "123456")
            let pin = try await f.sent("new")
            try engineExpect(pin["op"] as? String == "pin" && pin["pin"] as? String == "123456", "Recovery did not submit the PIN")
            try f.state("new", "SessionKeySet")
            if op == "unlock" { try f.request("retry") }
            try f.nativeReply("new", request: await f.sent("new"))
            let response = try await f.response("retry")
            try engineExpect(response["ok"] as? Bool == true, "CLI request did not resume after recovery")
            if op != "list" {
                try engineExpect(response["password"] as? String == "fixture-only", "Recovery did not return the fixture password")
            }
            try engineExpect(try await f.status()["state"] as? String == "unlocked", "Recovery did not update the UI state")
        }
    }

    // The final invalid-session reply must clear both CLI status and the menu state.
    for op in ["get", "list"] {
        let f = try ScriptFixture(), token = try await f.start()
        try f.connect("old", token: token, state: "SessionKeySet")
        try f.request("request", op: op)
        try f.nativeReply("old", request: await f.sent("old"), status: 9)
        f.complete(try await f.take("stopBrowser"))
        let start = try await f.take("startBrowser")
        f.complete(start)
        try f.connect("new", token: start["token"] as! String, state: "SessionKeySet")
        try f.nativeReply("new", request: await f.sent("new"), status: 9)
        f.complete(try await f.take("stopBrowser"))
        try engineExpect(try await f.response("request")["code"] as? String == "locked", "The final lock error was not returned")
        try engineExpect(try await f.status()["state"] as? String == "locked", "The final lock error left CLI status unlocked")
        let lastState = f.posts.compactMap { $0["event"] as? [String: Any] }.last { $0["type"] as? String == "state" }
        try engineExpect(lastState?["state"] as? String == "locked", "The final lock error left the menu state unlocked")
        try engineExpect(!f.posts.contains { $0["op"] as? String == "startBrowser" }, "Retried beyond the request limit")
    }

    // A failed startup must invalidate an already-connected extension.
    do {
        let f = try ScriptFixture()
        f.event(["type": "ready"])
        let first = try await f.take("startBrowser")
        try f.connect("old", token: first["token"] as! String)
        f.complete(first, error: "Fixture startup error")
        try engineExpect(try await f.status()["message"] as? String == "Fixture startup error", "Lost startup error details")
        f.command("unlock")
        _ = try await f.take("startBrowser")
        try f.state("old", "SessionKeySet")
        try engineExpect(try await f.status()["state"] as? String != "unlocked", "Stale bridge unlocked new generation")
        f.event(["type": "bridgeOpen", "connection": "invalid"])
        f.event(["type": "bridgeText", "connection": "invalid", "text": "null"])
        _ = try await f.take("disconnect", connection: "invalid")
        try engineExpect(!f.failed, "Malformed bridge message escaped into JSC")
    }

    // Stop a launch in progress and ignore its late success.
    do {
        let f = try ScriptFixture()
        f.event(["type": "ready"])
        let start = try await f.take("startBrowser")
        f.command("lock")
        let stop = try await f.take("stopBrowser")
        f.complete(start)
        f.complete(stop)
        try f.connect("late", token: start["token"] as! String, state: "SessionKeySet")
        _ = try await f.take("disconnect", connection: "late")
        try engineExpect(try await f.status()["state"] as? String == "locked", "Cancelled launch changed state")
        f.command("shutdown")
        f.complete(try await f.take("stopBrowser"))
        _ = try await f.take("shutdown")
    }
    try await runPasswordAuthorizationTests()
    print("JavaScriptCore: 14 credential/bridge tests, session lifecycle, and password approval checks passed")
}

@MainActor
private func runPasswordAuthorizationTests() async throws {
    // Both the app approval and native access window must finish before the get is sent.
    do {
        let f = try ScriptFixture(automaticallyAuthorizesPasswords: false)
        let token = try await f.start()
        try f.connect("bridge", token: token, state: "SessionKeySet")
        try f.request("approved", domain: "https://EXAMPLE.test/login")
        let approval = try await f.take("authorizePassword")
        let approvalTimer = f.posts.last { $0["op"] as? String == "timer" && $0["milliseconds"] as? Int == 120000 }!
        try engineExpect(approval["domain"] as? String == "example.test" && approval["username"] as? String == "person",
                         "Approval did not receive the normalized account")
        try engineExpect(!f.posts.contains { ["send", "beginPasswordAccess"].contains($0["op"] as? String ?? "") },
                         "A password query started before approval")

        f.complete(approval, result: ["remote": true])
        let begin = try await f.take("beginPasswordAccess")
        try engineExpect(f.posts.contains {
            $0["op"] as? String == "cancelTimer" && $0["id"] as? String == approvalTimer["id"] as? String
        }, "Approval completion did not cancel its timer")
        f.event(["type": "timer", "id": approvalTimer["id"]!])
        let accessID = begin["accessID"] as! String
        try engineExpect(!f.posts.contains { $0["op"] as? String == "send" }, "A query started before access was ready")
        f.complete(begin)
        let request = try await f.sent("bridge")
        try engineExpect(request["cmd"] as? Int == 5, "An approved get used the wrong native command")
        try f.nativeReply("bridge", request: request)
        let end = try await f.take("endPasswordAccess")
        try engineExpect(end["accessID"] as? String == accessID, "Success restored a different access window")
        try engineExpect(!f.posts.contains { $0["op"] as? String == "reply" && $0["connection"] as? String == "approved" },
                         "The password was returned before access restoration")
        f.complete(end)
        try engineExpect(try await f.response("approved")["password"] as? String == "fixture-only", "Approved get failed")
    }

    // Denied approval must leave both the preference window and browser query untouched.
    do {
        let f = try ScriptFixture(automaticallyAuthorizesPasswords: false)
        let token = try await f.start()
        try f.connect("bridge", token: token, state: "SessionKeySet")
        try f.request("denied")
        let approval = try await f.take("authorizePassword")
        f.complete(approval, error: "Fixture denial", code: "device_approval")
        try engineExpect(try await f.response("denied")["code"] as? String == "device_approval", "Approval denial was lost")
        try engineExpect(!f.posts.contains {
            ["send", "beginPasswordAccess", "endPasswordAccess", "stopBrowser"].contains($0["op"] as? String ?? "")
        }, "Denied approval touched the password session")
    }

    // Closing a client cancels its app approval; a late success must not send that get.
    do {
        let f = try ScriptFixture(automaticallyAuthorizesPasswords: false)
        let token = try await f.start()
        try f.connect("bridge", token: token, state: "SessionKeySet")
        try f.request("cancelled-approval")
        let approval = try await f.take("authorizePassword")
        let approvalTimer = f.posts.last { $0["op"] as? String == "timer" && $0["milliseconds"] as? Int == 120000 }!
        f.event(["type": "clientClosed", "connection": "cancelled-approval"])
        let cancellation = try await f.take("cancelAuthorization")
        try engineExpect(cancellation["id"] as? String == approval["id"] as? String, "Cancelled the wrong app approval")
        try engineExpect(f.posts.contains {
            $0["op"] as? String == "cancelTimer" && $0["id"] as? String == approvalTimer["id"] as? String
        }, "Approval cancellation did not cancel its timer")
        f.complete(approval, result: ["remote": true])
        try f.request("list-after-cancel", op: "list")
        let request = try await f.sent("bridge")
        try engineExpect(request["cmd"] as? Int == 4, "A cancelled approval sent a late password get")
        try f.nativeReply("bridge", request: request)
        _ = try await f.response("list-after-cancel")
        try engineExpect(!f.posts.contains {
            $0["op"] as? String == "beginPasswordAccess" ||
            ($0["op"] as? String == "reply" && $0["connection"] as? String == "cancelled-approval")
        }, "Cancelled approval changed access or replied to the closed client")
    }

    // An app that does not answer cannot hold the request queue indefinitely.
    do {
        let f = try ScriptFixture(automaticallyAuthorizesPasswords: false)
        let token = try await f.start()
        try f.connect("bridge", token: token, state: "SessionKeySet")
        try f.request("approval-timeout")
        let approval = try await f.take("authorizePassword")
        let timer = f.posts.last { $0["op"] as? String == "timer" && $0["milliseconds"] as? Int == 120000 }!
        f.event(["type": "timer", "id": timer["id"]!])
        let cancellation = try await f.take("cancelAuthorization")
        try engineExpect(cancellation["id"] as? String == approval["id"] as? String, "Timeout cancelled the wrong approval")
        try engineExpect(try await f.response("approval-timeout")["code"] as? String == "timeout", "Approval timeout was not returned")
        try engineExpect(!f.posts.contains {
            ["send", "beginPasswordAccess", "endPasswordAccess", "stopBrowser"].contains($0["op"] as? String ?? "")
        }, "Approval timeout touched the password session")

        f.complete(approval, result: ["remote": true])
        f.event(["type": "timer", "id": timer["id"]!])
        try f.request("after-approval-timeout", op: "list")
        let request = try await f.sent("bridge")
        try engineExpect(request["cmd"] as? Int == 4, "An expired approval sent a late password get")
        try f.nativeReply("bridge", request: request)
        _ = try await f.response("after-approval-timeout")
        try engineExpect(!f.posts.contains {
            ["beginPasswordAccess", "cancelAuthorization"].contains($0["op"] as? String ?? "") ||
            ($0["op"] as? String == "reply" && $0["connection"] as? String == "approval-timeout")
        }, "An expired approval was completed twice")
    }

    // Browser loss cancels the app approval before a queued request can start a new session.
    for cause in ["bridgeClosed", "browserExited"] {
        let f = try ScriptFixture(automaticallyAuthorizesPasswords: false)
        let token = try await f.start()
        try f.connect("bridge", token: token, state: "SessionKeySet")
        try f.request("interrupted-approval")
        let approval = try await f.take("authorizePassword")
        let timer = f.posts.last { $0["op"] as? String == "timer" && $0["milliseconds"] as? Int == 120000 }!
        try f.request("after-browser-stop")
        if cause == "bridgeClosed" {
            f.event(["type": cause, "connection": "bridge"])
        } else {
            f.event(["type": cause, "token": token])
        }
        let cancellation = try await f.take("cancelAuthorization")
        try engineExpect(cancellation["id"] as? String == approval["id"] as? String, "Browser loss cancelled the wrong approval")
        try engineExpect(f.posts.contains {
            $0["op"] as? String == "cancelTimer" && $0["id"] as? String == timer["id"] as? String
        }, "Browser loss left the approval timer active")
        let stop = try await f.take("stopBrowser")
        try engineExpect(try await f.response("interrupted-approval")["code"] as? String == "locked", "Browser loss left approval pending")
        f.complete(approval, result: ["remote": true])
        _ = try await f.status()
        try engineExpect(!f.posts.contains {
            ["send", "beginPasswordAccess", "authorizePassword", "startBrowser"].contains($0["op"] as? String ?? "")
        }, "A queued request used the browser while it was stopping")

        f.complete(stop)
        let start = try await f.take("startBrowser")
        f.complete(start)
        try f.connect("new", token: start["token"] as! String, state: "SessionKeySet")
        let nextApproval = try await f.take("authorizePassword")
        try engineExpect(nextApproval["id"] as? String != approval["id"] as? String, "The next request reused its cancelled approval")
        f.complete(nextApproval, result: ["remote": false])
        let request = try await f.sent("new")
        try f.nativeReply("new", request: request)
        _ = try await f.response("after-browser-stop")
        try engineExpect(!f.posts.contains { $0["op"] as? String == "beginPasswordAccess" },
                         "A late remote approval changed the next request")
    }

    // Apple can end its session while the browser remains open and phone approval is pending.
    for state in ["CheckEngine", "NotInSession"] {
        let f = try ScriptFixture(automaticallyAuthorizesPasswords: false)
        let token = try await f.start()
        try f.connect("bridge", token: token, state: "SessionKeySet")
        try f.request("native-session-ended")
        let approval = try await f.take("authorizePassword")
        let timer = f.posts.last { $0["op"] as? String == "timer" && $0["milliseconds"] as? Int == 120000 }!
        try f.state("bridge", state)
        let cancellation = try await f.take("cancelAuthorization")
        try engineExpect(cancellation["id"] as? String == approval["id"] as? String, "Native session loss cancelled the wrong approval")
        try engineExpect(f.posts.contains {
            $0["op"] as? String == "cancelTimer" && $0["id"] as? String == timer["id"] as? String
        }, "Native session loss left the approval timer active")
        let response = try await f.response("native-session-ended")
        try engineExpect(response["code"] as? String == "locked" && response["password"] == nil,
                         "Native session loss left phone approval pending")

        try f.state("bridge", "SessionKeySet")
        f.complete(approval, result: ["remote": true])
        _ = try await f.status()
        try engineExpect(!f.posts.contains {
            ["send", "beginPasswordAccess", "authorizePassword", "startBrowser"].contains($0["op"] as? String ?? "") ||
            ($0["op"] as? String == "reply" && $0["connection"] as? String == "native-session-ended")
        }, "A stale approval started a request after native session loss")
    }

    // A native failure still restores access; failed restoration must not return the password.
    for failure in ["native", "restore"] {
        let f = try ScriptFixture(automaticallyAuthorizesPasswords: false)
        let token = try await f.start()
        try f.connect("bridge", token: token, state: "SessionKeySet")
        try f.request("failure")
        f.complete(try await f.take("authorizePassword"), result: ["remote": true])
        let begin = try await f.take("beginPasswordAccess")
        f.complete(begin)
        let request = try await f.sent("bridge")
        if failure == "native" {
            try f.message("bridge", ["id": request["id"]!, "status": 1])
        } else {
            try f.nativeReply("bridge", request: request)
        }
        let end = try await f.take("endPasswordAccess")
        try engineExpect(end["accessID"] as? String == begin["accessID"] as? String,
                         "Failure restored a different access window")
        try engineExpect(!f.posts.contains { $0["op"] as? String == "stopBrowser" },
                         "The failure abandoned restoration before stopping")
        if failure == "restore" {
            f.complete(end, error: "Fixture restoration failure", code: "password_access")
        } else {
            f.complete(end)
        }
        f.complete(try await f.take("stopBrowser"))
        let response = try await f.response("failure")
        let expected = failure == "native" ? "native_error" : "password_access"
        try engineExpect(response["code"] as? String == expected && response["password"] == nil,
                         "A failed password request returned success or lost its error")
    }

    // Session loss or cancellation during restoration must discard a password already received from Apple.
    for interruption in ["lock", "cancelled", "CheckEngine", "NotInSession", "policy"] {
        let f = try ScriptFixture(automaticallyAuthorizesPasswords: false)
        let token = try await f.start()
        try f.connect("bridge", token: token, state: "SessionKeySet")
        try f.request("interrupted-restoration")
        f.complete(try await f.take("authorizePassword"), result: ["remote": true])
        f.complete(try await f.take("beginPasswordAccess"))
        let request = try await f.sent("bridge")
        try f.nativeReply("bridge", request: request)
        let end = try await f.take("endPasswordAccess")
        if interruption == "lock" {
            f.command("lock")
            f.complete(try await f.take("stopBrowser"))
        } else if interruption == "cancelled" {
            f.event(["type": "clientClosed", "connection": "interrupted-restoration"])
        } else if interruption == "policy" {
            f.event(["type": "approvalPolicyChanged"])
        } else {
            try f.state("bridge", interruption)
            try f.state("bridge", "SessionKeySet")
        }
        try engineExpect(!f.posts.contains {
            $0["op"] as? String == "reply" && $0["connection"] as? String == "interrupted-restoration"
        }, "Interrupted restoration returned a password before it finished")
        f.complete(end)
        if interruption != "cancelled" {
            let response = try await f.response("interrupted-restoration")
            let expectedCode = interruption == "policy" ? "cancelled" : "locked"
            try engineExpect(response["code"] as? String == expectedCode && response["password"] == nil,
                             "Session loss during restoration still returned the password")
        } else {
            _ = try await f.status()
            try engineExpect(!f.posts.contains {
                $0["op"] as? String == "reply" && $0["connection"] as? String == "interrupted-restoration"
            }, "Cancelled restoration replied to the closed client")
        }
        try engineExpect(!f.posts.contains { $0["op"] as? String == "startBrowser" || $0["op"] as? String == "authorizePassword" },
                         "Interrupted restoration retried the password request")
    }

    // A changed approval requirement cancels both waiting approval and an
    // already-sent local query; late approvals and replies cannot release a value.
    for phase in ["approval", "query"] {
        let f = try ScriptFixture(automaticallyAuthorizesPasswords: false)
        let token = try await f.start()
        try f.connect("bridge", token: token, state: "SessionKeySet")
        try f.request("policy-change")
        let authorization = try await f.take("authorizePassword")
        var query: [String: Any]?
        if phase == "query" {
            f.complete(authorization, result: ["remote": false])
            query = try await f.sent("bridge")
        }
        f.event(["type": "approvalPolicyChanged"])
        if phase == "approval" {
            f.complete(authorization, result: ["remote": false])
        } else {
            f.complete(try await f.take("stopBrowser"))
            try f.nativeReply("bridge", request: query!)
        }
        let response = try await f.response("policy-change")
        try engineExpect(response["ok"] as? Bool == false && response["password"] == nil,
                         "A policy change released a password under the old approval rule")
        try engineExpect(!f.posts.contains { ["send", "beginPasswordAccess", "startBrowser"].contains($0["op"] as? String ?? "") },
                         "A policy change reused the old approval or retried without a new request")
    }

    // Expiry or cancellation while native access starts must still restore without sending a get.
    for interruption in ["expired", "cancelled"] {
        let f = try ScriptFixture(automaticallyAuthorizesPasswords: false)
        let token = try await f.start()
        try f.connect("bridge", token: token, state: "SessionKeySet")
        try f.request("interrupted-begin")
        f.complete(try await f.take("authorizePassword"), result: ["remote": true])
        let begin = try await f.take("beginPasswordAccess")
        if interruption == "expired" {
            f.event(["type": "passwordAccessExpired", "accessID": begin["accessID"]!])
        } else {
            f.event(["type": "clientClosed", "connection": "interrupted-begin"])
        }
        f.complete(begin)
        let end = try await f.take("endPasswordAccess")
        try engineExpect(end["accessID"] as? String == begin["accessID"] as? String,
                         "Interrupted startup restored a different access window")
        try engineExpect(!f.posts.contains { $0["op"] as? String == "send" },
                         "Interrupted access startup sent a password query")
        f.complete(end)
        try engineExpect(try await f.status()["state"] as? String == "unlocked",
                         "An unsent query discarded the healthy session after restoration")
        try engineExpect(!f.posts.contains { $0["op"] as? String == "stopBrowser" },
                         "An unsent query stopped the browser")
        if interruption == "expired" {
            try engineExpect(try await f.response("interrupted-begin")["code"] as? String == "timeout",
                             "Expiry during startup did not reject the request")
        } else {
            _ = try await f.status()
            try engineExpect(!f.posts.contains {
                $0["op"] as? String == "reply" && $0["connection"] as? String == "interrupted-begin"
            }, "Cancelled access startup replied to the closed client")
        }
    }

    // Expiry is tied to one access ID. A late expiry cannot reject a later account request.
    do {
        let f = try ScriptFixture(automaticallyAuthorizesPasswords: false)
        let token = try await f.start()
        try f.connect("old", token: token, state: "SessionKeySet")
        try f.request("expired")
        f.complete(try await f.take("authorizePassword"), result: ["remote": true])
        let firstBegin = try await f.take("beginPasswordAccess")
        let firstID = firstBegin["accessID"] as! String
        f.complete(firstBegin)
        _ = try await f.sent("old")
        try f.request("after-expiry")
        f.event(["type": "passwordAccessExpired", "accessID": "unrelated-access"])
        _ = try await f.status()
        try engineExpect(!f.posts.contains { ["endPasswordAccess", "stopBrowser"].contains($0["op"] as? String ?? "") },
                         "An unrelated expiry cancelled the active request")

        f.event(["type": "passwordAccessExpired", "accessID": firstID])
        let firstEnd = try await f.take("endPasswordAccess")
        try engineExpect(firstEnd["accessID"] as? String == firstID, "Expiry restored the wrong access window")
        f.complete(firstEnd)
        f.complete(try await f.take("stopBrowser"))
        try engineExpect(try await f.response("expired")["code"] as? String == "timeout", "Expiry did not reject its own query")

        let start = try await f.take("startBrowser")
        f.complete(start)
        try f.connect("new", token: start["token"] as! String, state: "SessionKeySet")
        f.complete(try await f.take("authorizePassword"), result: ["remote": true])
        let secondBegin = try await f.take("beginPasswordAccess")
        let secondID = secondBegin["accessID"] as! String
        try engineExpect(secondID != firstID, "The next request reused the expired access ID")
        f.complete(secondBegin)
        let second = try await f.sent("new")
        f.event(["type": "passwordAccessExpired", "accessID": firstID])
        _ = try await f.status()
        try engineExpect(!f.posts.contains { ["endPasswordAccess", "stopBrowser"].contains($0["op"] as? String ?? "") },
                         "An old expiry cancelled the next request")
        try f.nativeReply("new", request: second)
        let secondEnd = try await f.take("endPasswordAccess")
        try engineExpect(secondEnd["accessID"] as? String == secondID, "The next request restored the wrong access window")
        f.complete(secondEnd)
        try engineExpect(try await f.response("after-expiry")["password"] as? String == "fixture-only",
                         "The next request did not survive a stale expiry")
    }
}

@MainActor
func runPolicyCancellationTests() async throws {
    // A policy change invalidates all received work, including requests that have
    // not reached the front of the queue. It does not close connected clients.
    for stage in ["approval", "query", "unlock", "pin", "begin", "begin-error", "restoring"] {
        let f = try ScriptFixture(automaticallyAuthorizesPasswords: false)
        let token = try await f.start()
        let waitingUnlock = stage == "unlock" || stage == "pin"
        try f.connect("bridge", token: token, state: waitingUnlock ? "NotInSession" : "SessionKeySet")
        try f.request("active")
        var authorization: [String: Any]?
        var begin: [String: Any]?
        var query: [String: Any]?
        var end: [String: Any]?
        if waitingUnlock {
            _ = try await f.sent("bridge")
            if stage == "pin" {
                try f.state("bridge", "MSG1Set")
                f.command("pin", pin: "123456")
                _ = try await f.sent("bridge")
            }
        } else {
            authorization = try await f.take("authorizePassword")
            if stage != "approval" {
                let remote = stage != "query"
                f.complete(authorization!, result: ["remote": remote])
                if remote { begin = try await f.take("beginPasswordAccess") }
                if stage == "query" || stage == "restoring" {
                    if let begin { f.complete(begin) }
                    query = try await f.sent("bridge")
                    if stage == "restoring" {
                        try f.nativeReply("bridge", request: query!)
                        end = try await f.take("endPasswordAccess")
                    }
                }
            }
        }
        try f.request("queued-get")
        try f.request("queued-list", op: "list")
        f.event(["type": "approvalPolicyChanged"])
        if stage == "approval" {
            _ = try await f.take("cancelAuthorization")
            f.complete(authorization!, result: ["remote": true])
        } else if stage == "begin" || stage == "begin-error" {
            try engineExpect(!f.posts.contains { $0["op"] as? String == "endPasswordAccess" },
                             "Policy cancellation ended a guard before its begin completed")
            if stage == "begin-error" {
                f.complete(begin!, error: "Fixture stale policy", code: "locked")
            } else {
                f.complete(begin!)
                end = try await f.take("endPasswordAccess")
                try engineExpect(end?["accessID"] as? String == begin?["accessID"] as? String,
                                 "Policy cancellation restored a different guard")
            }
        }
        if let end {
            try engineExpect(!f.posts.contains { $0["op"] as? String == "reply" && $0["connection"] as? String == "active" },
                             "Policy cancellation finished before guard restoration")
            f.complete(end)
        }
        if waitingUnlock || stage == "query" || stage == "begin-error" {
            f.complete(try await f.take("stopBrowser"))
        }
        if stage == "query" { try f.nativeReply("bridge", request: query!) }
        for connection in ["active", "queued-get", "queued-list"] {
            let response = try await f.response(connection)
            try engineExpect(response["code"] as? String == "cancelled" && response["password"] == nil && response["usernames"] == nil,
                             "Policy change did not cancel every received request at stage \(stage)")
        }
        try engineExpect(!f.posts.contains {
            ["send", "authorizePassword", "beginPasswordAccess", "startBrowser", "closeClient"].contains($0["op"] as? String ?? "")
        }, "An old request retried or a connected client was closed after the policy changed")

        // A request received after the event uses the new policy and can complete.
        let unlocked = try await f.status()["state"] as? String == "unlocked"
        try f.request("new-policy")
        let bridge: String
        if unlocked { bridge = "bridge" }
        else {
            let start = try await f.take("startBrowser")
            f.complete(start)
            bridge = "new-bridge"
            try f.connect(bridge, token: start["token"] as! String, state: "SessionKeySet")
        }
        f.complete(try await f.take("authorizePassword"), result: ["remote": false])
        let newQuery = try await f.sent(bridge)
        try f.nativeReply(bridge, request: newQuery)
        try engineExpect(try await f.response("new-policy")["password"] as? String == "fixture-only",
                         "A new request could not use the new policy")
    }
}

@MainActor
private func runSessionReuseTests() async throws {
    // Recovery is explicit: only a verified restore may preserve the paired session.
    for stage in ["begin", "end"] {
        for restored in [true, false] {
            let f = try ScriptFixture(automaticallyAuthorizesPasswords: false)
            let token = try await f.start()
            try f.connect("bridge", token: token, state: "SessionKeySet")
            try f.request("failed-access")
            f.complete(try await f.take("authorizePassword"), result: ["remote": true])
            let begin = try await f.take("beginPasswordAccess")
            let failedOperation: [String: Any]
            if stage == "begin" { failedOperation = begin }
            else {
                f.complete(begin)
                try f.nativeReply("bridge", request: try await f.sent("bridge"))
                failedOperation = try await f.take("endPasswordAccess")
            }
            f.complete(failedOperation, error: "Fixture access failure", code: "password_access",
                       result: ["accessRestored": restored])
            if !restored { f.complete(try await f.take("stopBrowser")) }
            let response = try await f.response("failed-access")
            try engineExpect(response["code"] as? String == "password_access" && response["password"] == nil,
                             "Failed access released a password")
            guard restored else {
                try engineExpect(try await f.status()["state"] as? String == "locked",
                                 "Unverified restoration left the session open")
                continue
            }
            try engineExpect(try await f.status()["state"] as? String == "unlocked",
                             "Verified restoration discarded the paired session")
            try f.request("next-access")
            let approval = try await f.take("authorizePassword")
            try engineExpect(!f.posts.contains {
                ["send", "beginPasswordAccess", "startBrowser", "stopBrowser", "disconnect"].contains($0["op"] as? String ?? "")
            }, "Session reuse skipped approval or restarted the browser")
            f.complete(approval, result: ["remote": true])
            f.complete(try await f.take("beginPasswordAccess"))
            try f.nativeReply("bridge", request: try await f.sent("bridge"))
            f.complete(try await f.take("endPasswordAccess"))
            try engineExpect(try await f.response("next-access")["password"] as? String == "fixture-only",
                             "A newly approved request could not reuse the session")
        }
    }

    // Even verified restoration cannot make an unanswered native query reusable.
    let f = try ScriptFixture(automaticallyAuthorizesPasswords: false)
    let token = try await f.start()
    try f.connect("old", token: token, state: "SessionKeySet")
    try f.request("cancelled-query")
    f.complete(try await f.take("authorizePassword"), result: ["remote": true])
    f.complete(try await f.take("beginPasswordAccess"))
    let oldQuery = try await f.sent("old")
    f.event(["type": "clientClosed", "connection": "cancelled-query"])
    f.complete(try await f.take("endPasswordAccess"), error: "Fixture recovered guard", code: "password_access",
               result: ["accessRestored": true])
    f.complete(try await f.take("stopBrowser"))
    try f.nativeReply("old", request: oldQuery)
    try engineExpect(try await f.status()["state"] as? String == "locked",
                     "A late reply reopened a cancelled native session")
    try engineExpect(!f.posts.contains { $0["op"] as? String == "reply" && $0["connection"] as? String == "cancelled-query" },
                     "A cancelled native query released a password")
}
