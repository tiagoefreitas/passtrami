import Foundation

struct MCPSettings {
    private let defaults: UserDefaults

    init(defaults: UserDefaults = .standard) {
        self.defaults = defaults
    }

    var approvalRetentionSeconds: Int {
        get {
            guard defaults.object(forKey: "mcpApprovalRetentionSeconds") != nil else { return 7_200 }
            return min(86_400, max(0, defaults.integer(forKey: "mcpApprovalRetentionSeconds")))
        }
        nonmutating set { defaults.set(min(86_400, max(0, newValue)), forKey: "mcpApprovalRetentionSeconds") }
    }

    var isEnabled: Bool {
        get { defaults.bool(forKey: "mcpEnabled") }
        nonmutating set { defaults.set(newValue, forKey: "mcpEnabled") }
    }
}
