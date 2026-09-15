import Foundation

struct MCPSettings {
    private let defaults: UserDefaults

    init(defaults: UserDefaults = .standard) {
        self.defaults = defaults
    }

    var isEnabled: Bool {
        get { defaults.bool(forKey: "mcpEnabled") }
        nonmutating set { defaults.set(newValue, forKey: "mcpEnabled") }
    }
}
