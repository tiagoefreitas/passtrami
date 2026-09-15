import SwiftUI

struct SettingsView: View {
    let model: SettingsModel
    let updates: ApplicationUpdates
    let browserRuntime: BrowserRuntimeModel
    let fullDiskAccess: FullDiskAccessModel
    let companion: CompanionService
    let onContentHeightChange: (CGFloat) -> Void
    @AppStorage("settingsPane") private var selectedPane: SettingsPane = .general
    @State private var columnVisibility: NavigationSplitViewVisibility = .all
    @State private var paneHeights: [SettingsPane: CGFloat] = [:]
    @State private var sidebarHeight: CGFloat = 0

    var body: some View {
        NavigationSplitView(columnVisibility: $columnVisibility) {
            SettingsSidebar(selection: $selectedPane, onHeightChange: { sidebarHeight = $0 })
                .navigationSplitViewColumnWidth(min: 210, ideal: 210, max: 210)
                .background {
                    SettingsSidebarMaterial()
                        .ignoresSafeArea()
                }
        } detail: {
            ZStack {
                ForEach(SettingsPane.allCases) { pane in
                    SettingsDetailView(pane: pane, model: model, updates: updates, browserRuntime: browserRuntime, fullDiskAccess: fullDiskAccess,
                                       companion: companion) { height in
                        paneHeights[pane] = height
                    }
                    .opacity(selectedPane == pane ? 1 : 0)
                    .allowsHitTesting(selectedPane == pane)
                    .accessibilityHidden(selectedPane != pane)
                    .disabled(selectedPane != pane)
                }
            }
            .frame(maxWidth: .infinity, maxHeight: .infinity)
            .navigationTitle(Text(selectedPane.title))
        }
        .navigationSplitViewStyle(.balanced)
        .frame(
            minWidth: 680, idealWidth: 760, maxWidth: .infinity,
            maxHeight: .infinity
        )
        .onChange(of: paneHeights) { _, _ in reportContentHeight() }
        .onChange(of: sidebarHeight) { _, _ in reportContentHeight() }
        .background {
            Color.clear
                .glassEffect(.regular, in: RoundedRectangle(cornerRadius: 16))
                .ignoresSafeArea()
        }
    }

    private func reportContentHeight() {
        guard paneHeights.count == SettingsPane.allCases.count, sidebarHeight > 0 else { return }
        onContentHeightChange(max(sidebarHeight, paneHeights.values.max() ?? 0))
    }
}

private struct SettingsDetailView: View {
    let pane: SettingsPane
    let model: SettingsModel
    let updates: ApplicationUpdates
    let browserRuntime: BrowserRuntimeModel
    let fullDiskAccess: FullDiskAccessModel
    let companion: CompanionService
    let onHeightChange: (CGFloat) -> Void

    var body: some View {
        Form {
            switch pane {
            case .general:
                StartupSettingsSection(model: model)
                SetupSettingsSection(model: fullDiskAccess, browserRuntime: browserRuntime)
            case .tools:
                CommandLineSettingsSection(model: model)
                MCPSettingsSection(model: model)
            case .devices:
                DevicesSettingsSection(companion: companion)
            case .about:
                AboutSettingsSection()
                UpdatesSettingsSection(updates: updates)
            }
        }
        .formStyle(.grouped)
        .animation(.easeInOut(duration: 0.25), value: model.mcpEnabled)
        .animation(.easeInOut(duration: 0.25), value: fullDiskAccess.status)
        .animation(.easeInOut(duration: 0.25), value: companion.pairedDevice?.id)
        .animation(.easeInOut(duration: 0.25), value: companion.pairingCode)
        .labeledContentStyle(CenteredLabeledContentStyle())
        .scrollContentBackground(.hidden)
        .buttonStyle(.glass)
        .controlSize(.regular)
        .onScrollGeometryChange(for: CGFloat.self) { geometry in
            ceil(geometry.contentSize.height + geometry.contentInsets.top + geometry.contentInsets.bottom)
        } action: { _, height in
            onHeightChange(height)
        }
    }
}

private struct StartupSettingsSection: View {
    @Bindable var model: SettingsModel

    var body: some View {
        Section {
            Toggle("Launch at Login", isOn: $model.launchAtLoginEnabled)
                .toggleStyle(.switch)
            if model.loginStatus == .requiresApproval {
                LabeledContent("Login Items") {
                    Button("Open…", action: model.openLoginItems)
                }
            }
        } header: {
            Text("Startup")
        } footer: {
            if let error = model.loginError {
                Text(error)
            } else if model.loginStatus == .requiresApproval {
                Text("Approval is required in Login Items.")
            } else if model.loginStatus == .notFound {
                Text("\(Bundle.main.displayName) could not be found by macOS.")
            } else if model.loginStatus != .enabled && model.loginStatus != .notRegistered {
                Text("Launch at Login is unavailable.")
            }
        }
    }
}

private struct CommandLineSettingsSection: View {
    let model: SettingsModel

    var body: some View {
        Section {
            HStack(alignment: .center, spacing: 16) {
                HStack(spacing: 4) {
                    Text("passtrami")
                    if model.cliInstalled {
                        Button("Reveal in Finder", systemImage: "arrow.up.right.square.fill", action: model.revealCLI)
                            .labelStyle(.iconOnly)
                            .buttonStyle(.plain)
                            .controlSize(.mini)
                            .font(.caption)
                            .foregroundStyle(.secondary)
                            .help("Reveal in Finder")
                    }
                }
                .fixedSize(horizontal: false, vertical: true)
                Spacer(minLength: 16)
                if model.cliInstalled {
                    Button("Uninstall", role: .destructive, action: model.uninstallCLI)
                        .buttonStyle(.glassProminent)
                        .tint(.red)
                } else {
                    Button("Install…", action: model.installCLI)
                }
            }
        } header: {
            Text("Command Line")
        } footer: {
            VStack(alignment: .leading, spacing: 4) {
                Text("Run `passtrami --help` from a terminal window to learn more.")
                if let error = model.cliError {
                    Text(error)
                }
            }
        }
    }
}

private struct MCPSettingsSection: View {
    @Bindable var model: SettingsModel

    var body: some View {
        Section {
            Toggle("Enable MCP", isOn: $model.mcpEnabled)
                .toggleStyle(.switch)
            if model.mcpEnabled {
                Picker("Remember iPhone Approval", selection: $model.approvalRetentionSeconds) {
                    Text("Never").tag(0)
                    Text("15 minutes").tag(900)
                    Text("30 minutes").tag(1_800)
                    Text("1 hour").tag(3_600)
                    Text("2 hours").tag(7_200)
                    Text("4 hours").tag(14_400)
                    Text("8 hours").tag(28_800)
                    Text("24 hours").tag(86_400)
                }
                LabeledContent("Server Configuration") {
                    Button("Copy Configuration", action: model.copyMCPConfiguration)
                        .fixedSize()
                }
                .transition(.opacity)
            }
        } header: {
            Text("MCP")
        } footer: {
            VStack(alignment: .leading, spacing: 4) {
                Text("Lets AI agents use passwords without including password values in session transcripts.")
                if model.mcpEnabled {
                    Text("Remembered approval applies only to the same domain and account on the same MCP connection. Locking Passtrami, closing the connection, or changing approval settings clears it.")
                }
                if model.mcpEnabled, let error = model.mcpError {
                    Text(error)
                }
            }
        }
    }
}

private struct AboutSettingsSection: View {
    var body: some View {
        Section {
            LabeledContent("Version", value: Bundle.main.displayVersion)
            LabeledContent("GitHub") {
                Link("zats/passtrami", destination: URL(string: "https://github.com/zats/passtrami")!)
                    .buttonStyle(.plain)
                    .foregroundStyle(.tint)
            }
        }
    }
}

private struct UpdatesSettingsSection: View {
    @Bindable var updates: ApplicationUpdates

    var body: some View {
        Section("Updates") {
            Toggle("Check Automatically", isOn: $updates.automaticallyChecksForUpdates)
                .toggleStyle(.switch)
            LabeledContent("App Updates") {
                Button("Check for Updates…", action: updates.checkForUpdates)
                    .disabled(!updates.canCheckForUpdates)
            }
        }
    }
}

private struct CenteredLabeledContentStyle: LabeledContentStyle {
    func makeBody(configuration: Configuration) -> some View {
        HStack(alignment: .center, spacing: 16) {
            configuration.label
            Spacer(minLength: 16)
            configuration.content
        }
    }
}
