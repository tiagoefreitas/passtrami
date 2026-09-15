import AppKit
import CloudKit
import OSLog

@MainActor
final class AppDelegate: NSObject, NSApplicationDelegate {
    private let companionLogger = Logger(subsystem: "io.zats.Passtrami", category: "CompanionSync")
    private let engine = EngineProcess()
    private let pinWindow = PINWindow()
    private let launchAtLogin = LaunchAtLoginController()
    private let browserRuntime = BrowserRuntimeModel()
    private let fullDiskAccess = FullDiskAccessModel()
    private let companion = CompanionService(role: .mac)
    private var approvalTasks: [String: Task<Void, Never>] = [:]
    private lazy var updates = ApplicationUpdates()
    private var isSettingsVisible = false
    private lazy var settings = SettingsWindow(launchAtLogin: launchAtLogin, updates: updates, browserRuntime: browserRuntime, fullDiskAccess: fullDiskAccess, companion: companion, onMCPChange: { [weak self] enabled in
        self?.engine.setMCPEnabled(enabled)
    }) { [weak self] in
        self?.isSettingsVisible = false
        self?.updateActivationPolicy()
    }
    private var statusItem: NSStatusItem!
    private let unlockItem = NSMenuItem(title: "Unlock…", action: nil, keyEquivalent: "")
    private let lockItem = NSMenuItem(title: "Lock", action: nil, keyEquivalent: "")
    private var firstLockedEventHandled = false
    private var shutdownTask: Task<Void, Never>?
    private var accessShutdownTask: Task<Void, Never>?
    private var didFinishLaunching = false

    func applicationDidFinishLaunching(_ notification: Notification) {
        launchAtLogin.applyInitialDefaultIfNeeded()
        createMenu()
        fullDiskAccess.onCheckAgain = { [weak self] in self?.startEngine() }
        updates.onVisibilityChange = { [weak self] in self?.updateActivationPolicy() }
        engine.onEvent = { [weak self] event in self?.handle(event) }
        companion.onApprovalPolicyChange = { [weak self] required in
            self?.cancelDeviceApprovals()
            self?.engine.setPhoneApprovalRequired(required)
        }
        companion.start()
        NSApp.registerForRemoteNotifications()
        browserRuntime.onDownload = { [weak self] in
            guard let self else { return }
            guard startEngine() else { return }
            engine.send("prepareBrowser")
        }
        pinWindow.onSubmit = { [weak self] pin in self?.engine.send("pin", pin: pin) }
        pinWindow.onCancel = { [weak self] in self?.lock() }
        if !UserDefaults.standard.bool(forKey: "didShowInitialSettings") {
            UserDefaults.standard.set(SettingsPane.general.rawValue, forKey: "settingsPane")
            showSettings()
            UserDefaults.standard.set(true, forKey: "didShowInitialSettings")
        }
        didFinishLaunching = true
        startEngine()
    }

    func applicationDidBecomeActive(_ notification: Notification) {
        guard didFinishLaunching, shutdownTask == nil else { return }
        let wasAvailable = fullDiskAccess.status == .available
        if fullDiskAccess.refresh() {
            if !wasAvailable { startEngine() }
        } else if wasAvailable {
            stopEngineForAccess()
            showAccessSettings()
        }
    }

    func applicationShouldHandleReopen(_ sender: NSApplication, hasVisibleWindows flag: Bool) -> Bool {
        showSettings()
        return true
    }

    func application(_ application: NSApplication, didRegisterForRemoteNotificationsWithDeviceToken deviceToken: Data) {
        companionLogger.info("Registered for iCloud change notifications")
    }

    func application(_ application: NSApplication, didFailToRegisterForRemoteNotificationsWithError error: any Error) {
        let error = error as NSError
        companionLogger.error("iCloud notification registration failed: \(error.domain, privacy: .public) \(error.code)")
    }

    func application(_ application: NSApplication, didReceiveRemoteNotification userInfo: [String: Any]) {
        guard let notification = CKNotification(fromRemoteNotificationDictionary: userInfo),
              notification.containerIdentifier == CompanionCloudStore.containerIdentifier else { return }
        companionLogger.info("Received iCloud change notification")
        Task { await companion.remoteChanged() }
    }

    private func createMenu() {
        statusItem = NSStatusBar.system.statusItem(withLength: NSStatusItem.squareLength)
        statusItem.button?.image = NSImage(systemSymbolName: "lock.fill", accessibilityDescription: "\(Bundle.main.displayName) is starting")
        let menu = NSMenu()
        menu.autoenablesItems = false
        unlockItem.target = self
        unlockItem.action = #selector(unlock)
        unlockItem.isEnabled = false
        lockItem.target = self
        lockItem.action = #selector(lock)
        lockItem.isEnabled = false
        let settingsItem = NSMenuItem(title: "Settings…", action: #selector(showSettings), keyEquivalent: ",")
        settingsItem.target = self
        let quit = NSMenuItem(title: "Quit \(Bundle.main.displayName)", action: #selector(NSApplication.terminate(_:)), keyEquivalent: "q")
        quit.target = NSApp
        for item in [unlockItem, lockItem, .separator(), settingsItem, updates.makeMenuItem(), .separator(), quit] {
            menu.addItem(item)
        }
        statusItem.menu = menu
        let mainMenu = NSMenu()
        let appItem = NSMenuItem()
        let appMenu = NSMenu(title: Bundle.main.displayName)
        let mainSettings = NSMenuItem(title: "Settings…", action: #selector(showSettings), keyEquivalent: ",")
        mainSettings.target = self
        appMenu.addItem(mainSettings)
        appMenu.addItem(updates.makeMenuItem())
        appMenu.addItem(.separator())
        appMenu.addItem(withTitle: "Quit \(Bundle.main.displayName)", action: #selector(NSApplication.terminate(_:)), keyEquivalent: "q")
        appItem.submenu = appMenu
        mainMenu.addItem(appItem)
        let fileItem = NSMenuItem()
        let fileMenu = NSMenu(title: "File")
        fileMenu.addItem(withTitle: "Close", action: #selector(NSWindow.performClose(_:)), keyEquivalent: "w")
        fileItem.submenu = fileMenu
        mainMenu.addItem(fileItem)
        NSApp.mainMenu = mainMenu
    }

    @discardableResult
    private func startEngine() -> Bool {
        guard fullDiskAccess.refresh() else {
            stopEngineForAccess()
            showAccessSettings()
            return false
        }
        guard shutdownTask == nil, accessShutdownTask == nil else { return false }
        if engine.isRunning { return true }
        do {
            try engine.start(phoneApprovalRequired: companion.requiresPhoneApproval)
            return true
        } catch {
            handle(EngineEvent(type: "state", state: .error, message: "Could not start the password service."))
            return false
        }
    }

    private func stopEngineForAccess() {
        cancelDeviceApprovals()
        pinWindow.dismiss()
        browserRuntime.pauseSetup()
        guard engine.isRunning, accessShutdownTask == nil, shutdownTask == nil else { return }
        accessShutdownTask = Task { [weak self] in
            guard let self else { return }
            await engine.shutdown()
            accessShutdownTask = nil
            if shutdownTask == nil, fullDiskAccess.refresh() { startEngine() }
        }
    }

    private func showAccessSettings() {
        updateMenu(.error, message: fullDiskAccess.status == .required
                   ? "Full Disk Access is required. Open Settings to continue."
                   : "Apple Passwords settings are unavailable. Open Settings to continue.")
        UserDefaults.standard.set(SettingsPane.general.rawValue, forKey: "settingsPane")
        showSettings()
    }

    private func handle(_ event: EngineEvent) {
        switch event.type {
        case "deviceApprovalRequired":
            if let id = event.id, let domain = event.domain, let username = event.username {
                requestDeviceApproval(id: id, domain: domain, username: username, retained: event.retainedApproval == true)
            }
        case "deviceApprovalCancelled":
            if let id = event.id { approvalTasks.removeValue(forKey: id)?.cancel() }
        case "browserRuntime":
            if let status = event.browserRuntime { browserRuntime.receive(status) }
        case "pinRequired": pinWindow.present()
        case "pinError": pinWindow.showError(event.message)
        case "state":
            guard let state = event.state else { return }
            if state == .error {
                cancelDeviceApprovals()
                if !fullDiskAccess.refresh() {
                    stopEngineForAccess()
                    showAccessSettings()
                    return
                }
                browserRuntime.serviceFailed(event.message ?? "The password service stopped. Try again.")
            }
            updateMenu(state, message: event.message)
            if state == .unlocked {
                UserDefaults.standard.set(true, forKey: "didCompletePairing")
                pinWindow.dismiss()
            } else if state == .locked || state == .error {
                pinWindow.dismiss()
            }
            if state == .locked && !firstLockedEventHandled {
                firstLockedEventHandled = true
                if !UserDefaults.standard.bool(forKey: "didCompletePairing") { engine.send("unlock") }
            }
        default: break
        }
    }

    private func updateMenu(_ state: EngineState, message: String?) {
        let label: String
        switch state {
        case .starting: label = message ?? "Starting…"
        case .locked: label = "Locked"
        case .pairing: label = "Enter code to unlock"
        case .unlocked: label = "Unlocked"
        case .error: label = message ?? "Could not connect"
        }
        statusItem.button?.toolTip = "\(Bundle.main.displayName): " + label
        statusItem.button?.image = NSImage(systemSymbolName: state == .unlocked ? "lock.open.fill" : "lock.fill",
                                          accessibilityDescription: "\(Bundle.main.displayName): " + label)
        unlockItem.isEnabled = state == .locked || state == .error
        lockItem.title = state == .starting ? "Cancel Setup" : "Lock"
        lockItem.isEnabled = state == .starting || state == .unlocked || state == .pairing
    }

    @objc private func unlock() {
        guard startEngine() else { return }
        engine.send("unlock")
    }

    @objc private func lock() {
        firstLockedEventHandled = true
        cancelDeviceApprovals()
        engine.send("lock")
    }

    private func requestDeviceApproval(id: String, domain: String, username: String, retained: Bool) {
        approvalTasks[id]?.cancel()
        approvalTasks[id] = Task { [weak self] in
            guard let self else { return }
            defer { approvalTasks.removeValue(forKey: id) }
            do {
                let remote = try await companion.authorizePasswordAccess(domain: domain, username: username, reuseApproval: retained)
                try Task.checkCancellation()
                engine.finishDeviceApproval(id: id, remote: remote)
            } catch is CancellationError {
                engine.finishDeviceApproval(id: id, error: "Request cancelled.")
            } catch {
                engine.finishDeviceApproval(id: id, error: error.localizedDescription)
            }
        }
    }

    private func cancelDeviceApprovals() {
        for (id, task) in approvalTasks {
            task.cancel()
            engine.finishDeviceApproval(id: id, error: "Request cancelled.")
        }
        approvalTasks.removeAll()
    }
    @objc private func showSettings() {
        isSettingsVisible = true
        updateActivationPolicy()
        settings.present()
    }

    private func updateActivationPolicy() {
        if isSettingsVisible || updates.isShowingUserInterface {
            NSApp.setActivationPolicy(.regular)
        } else {
            NSApp.setActivationPolicy(.accessory)
            NSApp.deactivate()
        }
    }

    func applicationShouldTerminate(_ sender: NSApplication) -> NSApplication.TerminateReply {
        guard shutdownTask == nil else { return .terminateLater }
        pinWindow.dismiss()
        cancelDeviceApprovals()
        companion.stop()
        let pendingAccessShutdown = accessShutdownTask
        shutdownTask = Task { [engine] in
            await pendingAccessShutdown?.value
            await engine.shutdown()
            NSApp.reply(toApplicationShouldTerminate: true)
        }
        return .terminateLater
    }
}
