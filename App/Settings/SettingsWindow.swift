import AppKit
import Observation
import ServiceManagement
import SwiftUI

@MainActor
final class SettingsWindow: NSWindowController, NSWindowDelegate {
    private static let frameAutosaveName = "Passtrami.SettingsWindow"
    private let model: SettingsModel
    private let companion: CompanionService
    private let didClose: () -> Void

    init(launchAtLogin: LaunchAtLoginController, updates: ApplicationUpdates, browserRuntime: BrowserRuntimeModel,
         fullDiskAccess: FullDiskAccessModel,
         companion: CompanionService,
         onMCPChange: @escaping (Bool) -> Void,
         didClose: @escaping () -> Void) {
        model = SettingsModel(launchAtLogin: launchAtLogin, onMCPChange: onMCPChange)
        self.companion = companion
        self.didClose = didClose
        let window = NSWindow(
            contentRect: NSRect(x: 0, y: 0, width: 760, height: 520),
            styleMask: [.titled, .closable, .miniaturizable, .fullSizeContentView],
            backing: .buffered,
            defer: false
        )
        window.title = "\(Bundle.main.displayName) Settings"
        window.titleVisibility = .visible
        window.titlebarAppearsTransparent = true
        window.titlebarSeparatorStyle = .none
        window.backgroundColor = .clear
        window.isOpaque = false
        window.isReleasedWhenClosed = false
        window.minSize = NSSize(width: 680, height: 0)
        window.standardWindowButton(.zoomButton)?.isEnabled = false
        window.collectionBehavior = [.moveToActiveSpace, .fullScreenNone]
        if !window.setFrameUsingName(Self.frameAutosaveName) { window.center() }
        window.setFrameAutosaveName(Self.frameAutosaveName)
        super.init(window: window)
        window.delegate = self
        window.contentViewController = NSHostingController(rootView: SettingsView(
            model: model, updates: updates, browserRuntime: browserRuntime, fullDiskAccess: fullDiskAccess, companion: companion,
            onContentHeightChange: { [weak self] height in self?.fitContent(height: height) }
        ))
    }

    @available(*, unavailable)
    required init?(coder: NSCoder) { fatalError("init(coder:) is unavailable") }

    func present() {
        model.refresh()
        Task { await companion.refresh() }
        showWindow(nil)
        window?.makeKeyAndOrderFront(nil)
        window?.orderFrontRegardless()
        NSApp.activate()
    }

    private func fitContent(height: CGFloat) {
        guard let window, let contentView = window.contentView else { return }
        var frame = window.frame
        let frameHeight = ceil(height + frame.height - contentView.frame.height)
        guard abs(frame.height - frameHeight) > 1 else { return }
        frame.origin.y += frame.height - frameHeight
        frame.size.height = frameHeight
        window.setFrame(frame, display: true,
                        animate: window.isVisible && !NSWorkspace.shared.accessibilityDisplayShouldReduceMotion)
    }

    func windowShouldZoom(_ window: NSWindow, toFrame newFrame: NSRect) -> Bool { false }

    func windowDidBecomeKey(_ notification: Notification) { model.refresh() }
    func windowWillClose(_ notification: Notification) { didClose() }
}

@MainActor
@Observable
final class SettingsModel {
    private let launchAtLogin: LaunchAtLoginController
    private let installer: CLIInstaller
    private let mcpSettings: MCPSettings
    private let onMCPChange: (Bool) -> Void
    private(set) var loginStatus: SMAppService.Status = .notRegistered
    private(set) var loginError: String?
    private(set) var cliInstalled = false
    private(set) var cliError: String?
    private(set) var mcpError: String?

    var approvalRetentionSeconds: Int {
        didSet {
            guard approvalRetentionSeconds != oldValue else { return }
            mcpSettings.approvalRetentionSeconds = approvalRetentionSeconds
            onMCPChange(mcpEnabled)
        }
    }

    var mcpEnabled: Bool {
        didSet {
            guard mcpEnabled != oldValue else { return }
            mcpSettings.isEnabled = mcpEnabled
            onMCPChange(mcpEnabled)
        }
    }

    var launchAtLoginEnabled: Bool {
        get { loginStatus == .enabled }
        set {
            launchAtLogin.setEnabled(newValue)
            refresh()
        }
    }

    init(launchAtLogin: LaunchAtLoginController, installer: CLIInstaller = CLIInstaller(),
         mcpSettings: MCPSettings = MCPSettings(), onMCPChange: @escaping (Bool) -> Void) {
        self.launchAtLogin = launchAtLogin
        self.installer = installer
        self.mcpSettings = mcpSettings
        self.onMCPChange = onMCPChange
        mcpEnabled = mcpSettings.isEnabled
        approvalRetentionSeconds = mcpSettings.approvalRetentionSeconds
    }

    func refresh() {
        launchAtLogin.refresh()
        loginStatus = launchAtLogin.status
        loginError = launchAtLogin.operationError
        cliInstalled = installer.isInstalled
    }

    func openLoginItems() { launchAtLogin.openLoginItems() }

    func copyMCPConfiguration() {
        mcpError = nil
        guard let executable = Bundle.main.resourceURL?.appendingPathComponent("passtrami-mcp") else {
            mcpError = "The MCP server is unavailable."
            return
        }
        let configuration: [String: Any] = [
            "mcpServers": ["passtrami": ["command": executable.path, "args": [String]()]]
        ]
        do {
            let data = try JSONSerialization.data(withJSONObject: configuration, options: [.prettyPrinted, .sortedKeys])
            NSPasteboard.general.clearContents()
            if !NSPasteboard.general.setString(String(decoding: data, as: UTF8.self), forType: .string) {
                mcpError = "Could not copy the configuration."
            }
        } catch {
            mcpError = "Could not copy the configuration."
        }
    }

    func revealCLI() {
        guard installer.isInstalled else { return }
        NSWorkspace.shared.activateFileViewerSelecting([installer.commandURL])
    }

    func installCLI() {
        cliError = nil
        do {
            try installer.install()
            refresh()
        } catch {
            cliError = error.localizedDescription
        }
    }

    func uninstallCLI() {
        cliError = nil
        do {
            try installer.uninstall()
            refresh()
        } catch {
            cliError = error.localizedDescription
        }
    }
}
