import OSLog

enum SessionDiagnostics {
    private static let logger = Logger(subsystem: "io.zats.Passtrami", category: "SessionLifecycle")

    static func record(_ name: String, detail: String = "", value: Int? = nil) {
        guard let text = message(name, detail: detail, value: value) else { return }
        logger.notice("\(text, privacy: .public)")
    }

    // Never interpolate arbitrary native errors, request fields or credential data.
    static func message(_ name: String, detail: String = "", value: Int? = nil) -> String? {
        let events: Set<String> = ["native_state", "session_lock", "native_timeout", "request_failed",
                                   "bridge_closed", "browser_exited", "access_expired", "apple_error",
                                   "approval_requested", "approval_reuse_requested", "approval_granted", "approval_retained", "approval_reused"]
        guard events.contains(name) else { return nil }
        if name == "apple_error" {
            guard let value, (0...1_000).contains(value) else { return nil }
            return "apple_error status=\(value)"
        }
        let details: Set<String> = ["NotInSession", "ChallengeSent", "MSG1Set", "SessionKeySet", "CheckEngine",
                                    "NativeSupportNotInstalled", "IncompatibleOS", "Connecting", "locked",
                                    "cancelled", "timeout", "password_access", "native_error", "native_helper"]
        return details.contains(detail) ? "\(name) \(detail)" : name
    }
}
