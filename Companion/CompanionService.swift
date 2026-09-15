import CloudKit
import CryptoKit
import Foundation
import LocalAuthentication
import Observation
import Security
#if os(iOS)
import UIKit
#endif

@MainActor @Observable
final class CompanionService {
    static let notificationCategory = CompanionCloudStore.notificationCategory
    let role: CompanionRole
    private(set) var accountAvailable = false
    private(set) var accountMessage: String?
    private(set) var pairedDevice: CompanionDevice?
    private(set) var localDevice: CompanionDevice?
    private(set) var pairingCode: String?
    private(set) var pairingURL: URL?
    private(set) var pairingExpiresAt: Date?
    private(set) var pairingID: String?
    private(set) var hasLocalPairing = false
    private enum ApprovalPolicy { case unconfigured, local, phone, unavailable }
    private var approvalPolicy = ApprovalPolicy.unconfigured
    var requiresPhoneApproval: Bool { approvalPolicy == .phone }
    var approvalPolicyNeedsSetup: Bool { approvalPolicy == .unconfigured || approvalPolicy == .unavailable }
    private(set) var refreshSucceeded = false
    private(set) var pendingRequests: [CompanionRequest] = []
    private(set) var history: [CompanionRequest] = []
    private(set) var errorMessage: String?
    private(set) var isBusy = false

    @ObservationIgnored private let cloud = CompanionCloudStore()
    @ObservationIgnored private let defaults: UserDefaults
    @ObservationIgnored private let policyStore: CompanionApprovalPolicyStore
    @ObservationIgnored private let authenticatePolicyChange: @MainActor () async throws -> Void
    @ObservationIgnored var onApprovalPolicyChange: ((Bool) -> Void)?
    @ObservationIgnored private let deviceID: String
    @ObservationIgnored private let signingKey: CompanionSigningKey
    @ObservationIgnored private var trust: CompanionTrust?
    @ObservationIgnored private var currentAccountID: String?
    @ObservationIgnored private var pollTask: Task<Void, Never>?
    @ObservationIgnored private var pollSleep: Task<Void, Never>?
    @ObservationIgnored private var accountObserver: (any NSObjectProtocol)?
    @ObservationIgnored private var refreshTask: Task<Void, any Error>?
    @ObservationIgnored private var remoteRefreshPending = false
    @ObservationIgnored private var subscribedPairID: String?

    init(role: CompanionRole, defaults: UserDefaults = .standard,
         policyStore: CompanionApprovalPolicyStore = .keychain,
         authenticatePolicyChange: @escaping @MainActor () async throws -> Void = {
             let context = LAContext()
             defer { context.invalidate() }
             guard try await context.evaluatePolicy(.deviceOwnerAuthentication,
                 localizedReason: String(localized: "Use local approval for passwords.")) else {
                 throw CompanionError.cancelled
             }
         }) {
        self.role = role
        self.defaults = defaults
        self.policyStore = policyStore
        self.authenticatePolicyChange = authenticatePolicyChange
        let idKey = "companion.deviceID.\(role.rawValue)"
        let id = defaults.string(forKey: idKey) ?? UUID().uuidString
        defaults.set(id, forKey: idKey)
        deviceID = id
        signingKey = CompanionSigningKey(tag: Data("io.zats.Passtrami.companion.\(id)".utf8), requiresPresence: role == .phone)
        if role == .mac { try? reloadApprovalPolicy() }
        if let data = defaults.data(forKey: "companion.trust"),
           let saved = try? CompanionProtocol.decode(CompanionTrust.self, from: data) {
            trust = saved
            hasLocalPairing = true
            pairingID = saved.pairID
            pairedDevice = role == .mac ? saved.phone : saved.mac
        }
        if role == .mac, let code = defaults.string(forKey: "companion.offerCode"),
           let expiry = defaults.object(forKey: "companion.offerExpiry") as? Date, expiry > Date() {
            showCode(code, expiresAt: expiry)
        }
    }

    func start() {
        guard pollTask == nil else { return }
        accountObserver = NotificationCenter.default.addObserver(forName: .CKAccountChanged, object: nil, queue: .main) { [weak self] _ in
            Task { @MainActor [weak self] in
                if let task = self?.refreshTask { _ = await task.result }
                self?.accountAvailable = false
                self?.refreshSucceeded = false
                self?.currentAccountID = nil
                self?.subscribedPairID = nil
                await self?.refresh()
            }
        }
        pollTask = Task { [weak self] in
            while !Task.isCancelled {
                await self?.refresh()
                guard !Task.isCancelled, self != nil else { return }
                let interval: TimeInterval = self?.pairingCode != nil ? 1 : (self?.pendingRequests.isEmpty == false ? 5 : 30)
                let sleep = Task<Void, Never> { try? await Task.sleep(for: .seconds(interval)) }
                self?.pollSleep = sleep
                await sleep.value
                guard !Task.isCancelled else { return }
                self?.pollSleep = nil
            }
        }
    }

    func stop() {
        pollTask?.cancel()
        pollTask = nil
        pollSleep?.cancel()
        pollSleep = nil
        if let accountObserver { NotificationCenter.default.removeObserver(accountObserver) }
        accountObserver = nil
    }

    func refresh() async {
        guard refreshTask != nil || !isBusy else { return }
        try? await refreshSharedState()
    }

    func remoteChanged() async {
        remoteRefreshPending = true
        // A notification can arrive after an in-flight fetch has read the old record.
        if let refreshTask { _ = await refreshTask.result }
        guard !isBusy, remoteRefreshPending else { return }
        remoteRefreshPending = false
        await refresh()
    }

    private func refreshSharedState() async throws {
        if let refreshTask { try await refreshTask.value; return }
        let task = Task { @MainActor [self] in
            // Only this task clears its handle. stop/start and callers do not replace it.
            defer { refreshTask = nil }
            do {
                try await refreshState()
                errorMessage = nil
            } catch {
                #if DEBUG && os(iOS)
                CompanionDiagnostics.recordError("refresh", error: error)
                #endif
                refreshSucceeded = false
                errorMessage = userMessage(error)
                throw error
            }
        }
        refreshTask = task
        try await task.value
    }

    func beginPairing() async {
        await perform {
            guard role == .mac else { throw CompanionError.message("Start pairing in the Mac app.") }
            try await checkAccount()
            guard trust == nil else { throw CompanionError.message("Unpair the current iPhone before you pair another device.") }
            let record = try await cloud.record(CompanionCloudStore.pairRecordID)
                ?? CKRecord(recordType: "PasstramiPair", recordID: CompanionCloudStore.pairRecordID)
            let state = record["state"] as? String
            if state == "paired" { throw CompanionError.message("An iPhone is already paired. Unpair it before you continue.") }
            if state == "offered", let data = record["offer"] as? Data {
                let old = try CompanionProtocol.decode(CompanionAuthenticatedOffer.self, from: data).offer
                if old.mac.id != deviceID && old.expiresAt > Date() {
                    throw CompanionError.message("Another Mac has an active pairing code. Wait for it to expire.")
                }
            }
            let device = try makeLocalDevice()
            let alphabet = Array("ABCDEFGHJKLMNPQRSTUVWXYZ23456789")
            // Rejection sampling avoids a biased code if the alphabet length changes.
            var characters: [Character] = []
            while characters.count < 12 {
                var byte: UInt8 = 0
                guard SecRandomCopyBytes(kSecRandomDefault, 1, &byte) == errSecSuccess else {
                    throw CompanionError.message("Could not create a pairing code.")
                }
                if Int(byte) < 256 - (256 % alphabet.count) { characters.append(alphabet[Int(byte) % alphabet.count]) }
            }
            let code = String(characters)
            let offer = CompanionPairingOffer(pairID: UUID().uuidString, mac: device,
                expiresAt: Date().addingTimeInterval(CompanionProtocol.pairingLifetime))
            record["pairID"] = offer.pairID
            record["state"] = "offered"
            record["offer"] = try CompanionProtocol.encode(CompanionProtocol.authenticateOffer(offer, code: code))
            record["phone"] = nil
            record["proof"] = nil
            record["expiresAt"] = offer.expiresAt
            _ = try await cloud.save(record)
            defaults.set(code, forKey: "companion.offerCode")
            defaults.set(offer.expiresAt, forKey: "companion.offerExpiry")
            defaults.set(currentAccountID, forKey: "companion.offerAccountID")
            defaults.set(offer.pairID, forKey: "companion.offerPairID")
            showCode(code, expiresAt: offer.expiresAt)
        }
        pollSleep?.cancel()
    }

    func pair(code input: String) async {
        await perform {
            guard role == .phone else { throw CompanionError.message("Enter this code in the iPhone app.") }
            try await refreshState()
            guard trust == nil else { throw CompanionError.message("Unpair the current Mac before you pair another device.") }
            let code = try CompanionProtocol.pairingCode(from: input)
            guard let record = try await cloud.record(CompanionCloudStore.pairRecordID),
                  record["state"] as? String == "offered", let data = record["offer"] as? Data else {
                throw CompanionError.message("No pairing code is available. Create a new code on your Mac.")
            }
            let authenticated = try CompanionProtocol.decode(CompanionAuthenticatedOffer.self, from: data)
            let offer = try CompanionProtocol.verifyOffer(authenticated, code: code, now: Date())
            guard record["pairID"] as? String == offer.pairID else { throw CompanionError.invalidSignature }
            let phone = try makeLocalDevice()
            let receipt = CompanionPairingReceipt(pairID: offer.pairID, mac: offer.mac, phone: phone)
            record["phone"] = try CompanionProtocol.encode(phone)
            record["proof"] = try CompanionProtocol.pairingProof(code: code, receipt: receipt)
            record["state"] = "paired"
            _ = try await cloud.save(record)
            try saveTrust(CompanionTrust(accountID: currentAccountID!, pairID: offer.pairID, mac: offer.mac, phone: phone))
            try await refreshState()
        }
    }

    func unpair() async {
        // Capture ownership before perform() waits for an in-flight refresh.
        let capturedTrust = trust
        let offerCode = defaults.string(forKey: "companion.offerCode")
        let offerExpiry = defaults.object(forKey: "companion.offerExpiry") as? Date
        let offerAccountID = defaults.string(forKey: "companion.offerAccountID")
        let offerPairID = defaults.string(forKey: "companion.offerPairID")
        await perform {
            try await checkAccount()
            let ownerAccountID = capturedTrust?.accountID ?? offerAccountID
            guard ownerAccountID == nil || ownerAccountID == currentAccountID else {
                throw CompanionError.accountUnavailable
            }
            if let record = try await cloud.record(CompanionCloudStore.pairRecordID) {
                var ownsRecord = false
                // No legacy offer decoder: unpair with the previous apps before
                // installing this format. Unknown records do not establish ownership.
                if let data = record["offer"] as? Data,
                   let authenticated = try? CompanionProtocol.decode(CompanionAuthenticatedOffer.self, from: data),
                   record["pairID"] as? String == authenticated.offer.pairID {
                    let offer = authenticated.offer
                    if let capturedTrust, record["state"] as? String == "paired",
                       let phoneData = record["phone"] as? Data,
                       let phone = try? CompanionProtocol.decode(CompanionDevice.self, from: phoneData) {
                        ownsRecord = offer.pairID == capturedTrust.pairID
                            && offer.mac == capturedTrust.mac && phone == capturedTrust.phone
                    } else if capturedTrust == nil, role == .mac, offerAccountID != nil, let offerCode,
                              offer.pairID == offerPairID, offer.expiresAt == offerExpiry, offer.mac.id == deviceID {
                        if offer.mac.publicKey == (try signingKey.publicKey()) {
                            // Expiry ends enrollment, but does not prevent cancellation of our own offer.
                            _ = try CompanionProtocol.verifyOfferAuthentication(authenticated, code: offerCode)
                            if record["state"] as? String == "offered" {
                                ownsRecord = true
                            } else if record["state"] as? String == "paired",
                                      let phoneData = record["phone"] as? Data,
                                      let phone = try? CompanionProtocol.decode(CompanionDevice.self, from: phoneData),
                                      let proof = record["proof"] as? Data {
                                // The phone may have claimed this offer before the Mac receives the update.
                                try CompanionProtocol.verifyPairingProof(proof, code: offerCode,
                                    receipt: CompanionPairingReceipt(pairID: offer.pairID, mac: offer.mac, phone: phone))
                                ownsRecord = true
                            }
                        }
                    }
                }
                if ownsRecord {
                    record["state"] = "revoked"
                    _ = try await cloud.save(record)
                }
            }
            if role == .phone, let capturedTrust {
                try await cloud.removeSubscription(pairID: capturedTrust.pairID)
            }
            clearTrust()
            clearCode()
            pendingRequests = []
            history = []
            refreshSucceeded = true
        }
    }

    func approve(requestID: String) async {
        await decide(requestID: requestID, approved: true)
    }

    func decline(requestID: String) async {
        await decide(requestID: requestID, approved: false)
    }

    func setPhoneApprovalRequired(_ required: Bool) async {
        await perform {
            guard role == .mac else { throw CompanionError.message("Change password approval settings on your Mac.") }
            // A failed read must still permit deliberate, authenticated recovery.
            try? reloadApprovalPolicy()
            guard approvalPolicyNeedsSetup || required != requiresPhoneApproval else { return }
            if required {
                guard trust != nil else { throw CompanionError.notPaired }
            } else {
                try await authenticatePolicyChange()
                try Task.checkCancellation()
            }
            try saveApprovalPolicy(required)
        }
    }

    // The Mac routes every password request through the persisted local policy.
    // Pairing loss or an unavailable cloud account must not select local approval.
    func authorizePasswordAccess(domain: String, username: String, reuseApproval: Bool = false) async throws -> Bool {
        guard role == .mac else { throw CompanionError.message("Password requests must start on your Mac.") }
        try Task.checkCancellation()
        try reloadApprovalPolicy()
        guard !approvalPolicyNeedsSetup else {
            throw CompanionError.message("Choose an approval method in Devices settings before you request a password.")
        }
        guard requiresPhoneApproval else { return false }
        if reuseApproval {
            guard let trust else { throw CompanionError.notPaired }
            _ = try await verifyCurrentPair(trust)
            try Task.checkCancellation()
            return true
        }
        try await requestApproval(domain: domain, username: username)
        return true
    }

    func requestApproval(domain: String, username: String) async throws {
        guard role == .mac else { throw CompanionError.message("Password requests must start on your Mac.") }
        try Task.checkCancellation()
        guard !isBusy else { throw CompanionError.message("A device operation is in progress. Try again.") }
        try await refreshSharedState()
        guard let trust else { throw CompanionError.notPaired }
        let now = Date()
        let request = CompanionRequest(id: UUID().uuidString, pairID: trust.pairID,
            macID: trust.mac.id, phoneID: trust.phone.id, domain: domain, username: username,
            createdAt: now, expiresAt: now.addingTimeInterval(CompanionProtocol.requestLifetime), status: .pending)
        let signed = CompanionSignedRequest(request: request,
            signature: try await signingKey.sign(CompanionProtocol.encode(request), reason: "Request password approval"))
        let record = CKRecord(recordType: CompanionCloudStore.requestRecordType, recordID: CompanionCloudStore.requestID(request.id))
        record["pairID"] = request.pairID
        record["requestID"] = request.id
        record["createdAt"] = request.createdAt
        record["status"] = CompanionRequest.Status.pending.rawValue
        record["request"] = try CompanionProtocol.encode(signed)
        try Task.checkCancellation()
        do {
            _ = try await cloud.save(record)
            pendingRequests.removeAll { $0.id == request.id }
            history.removeAll { $0.id == request.id }
            pendingRequests.insert(request, at: 0)
            try await CompanionCloudStore.retryRecordConflicts {
                while true {
                    try Task.checkCancellation()
                    guard let current = try await cloud.record(record.recordID) else { throw CompanionError.cancelled }
                    let pairRecord = try await verifyCurrentPair(trust)
                    let currentSigned = try signedRequest(current, trust: trust)
                    guard currentSigned.request == request else { throw CompanionError.invalidSignature }
                    let status = current["status"] as? String
                    if status == CompanionRequest.Status.declined.rawValue { throw CompanionError.declined }
                    if status == CompanionRequest.Status.cancelled.rawValue { throw CompanionError.cancelled }
                    if status == CompanionRequest.Status.expired.rawValue || request.expiresAt <= Date() { throw CompanionError.expired }
                    if status == CompanionRequest.Status.approved.rawValue {
                        guard let data = current["response"] as? Data else { throw CompanionError.invalidSignature }
                        let response = try CompanionProtocol.decode(CompanionSignedDecision.self, from: data)
                        try CompanionProtocol.verifyDecision(response, for: signed, trust: trust,
                            consumed: current["consumedAt"] != nil, now: Date())
                        guard response.decision.approved else { throw CompanionError.declined }
                        try Task.checkCancellation()
                        current["consumedAt"] = Date()
                        pairRecord["lastOperation"] = UUID().uuidString
                        try await cloud.save([pairRecord, current])
                        try Task.checkCancellation()
                        return
                    }
                    guard status == CompanionRequest.Status.pending.rawValue else { throw CompanionError.invalidSignature }
                    try await Task.sleep(for: .seconds(1))
                }
            }
            await refresh()
        } catch {
            let finalStatus: CompanionRequest.Status = error is CancellationError ? .cancelled : .expired
            await closeRequest(id: request.id, status: finalStatus)
            throw error
        }
    }

    private func decide(requestID: String, approved: Bool) async {
        await perform {
            guard role == .phone else { throw CompanionError.message("Review this request in the iPhone app.") }
            try await refreshState()
            guard let trust, let record = try await cloud.record(CompanionCloudStore.requestID(requestID)) else {
                throw CompanionError.notPaired
            }
            let signed = try signedRequest(record, trust: trust)
            guard record["status"] as? String == CompanionRequest.Status.pending.rawValue else { throw CompanionError.alreadyUsed }
            guard signed.request.expiresAt > Date() else { throw CompanionError.expired }
            let response: Data?
            if approved {
                let decision = CompanionDecision(requestID: requestID,
                    requestDigest: Data(SHA256.hash(data: try CompanionProtocol.encode(signed.request))),
                    pairID: trust.pairID, phoneID: trust.phone.id, approved: true, decidedAt: Date())
                let signature = try await signingKey.sign(CompanionProtocol.encode(decision),
                    reason: "Approve password access for \(signed.request.username) at \(signed.request.domain)")
                try Task.checkCancellation()
                guard signed.request.expiresAt > Date() else { throw CompanionError.expired }
                response = try CompanionProtocol.encode(CompanionSignedDecision(decision: decision, signature: signature))
            } else {
                response = nil
            }
            // Keep the user's signed decision, but recheck current state after any write conflict.
            try await CompanionCloudStore.retryRecordConflicts {
                guard let current = try await cloud.record(record.recordID) else { throw CompanionError.cancelled }
                let pairRecord = try await verifyCurrentPair(trust)
                let currentSigned = try signedRequest(current, trust: trust)
                guard currentSigned.request == signed.request else { throw CompanionError.invalidSignature }
                guard current["status"] as? String == CompanionRequest.Status.pending.rawValue,
                      current["consumedAt"] == nil else { throw CompanionError.alreadyUsed }
                guard signed.request.expiresAt > Date() else { throw CompanionError.expired }
                try Task.checkCancellation()
                // An unsigned decline can only deny access. Approval needs the phone's signature.
                current["response"] = response
                current["status"] = approved ? CompanionRequest.Status.approved.rawValue : CompanionRequest.Status.declined.rawValue
                current["decisionAt"] = Date()
                pairRecord["lastOperation"] = UUID().uuidString
                try await cloud.save([pairRecord, current])
            }
            try await refreshState()
        }
    }

    private func refreshState() async throws {
        refreshSucceeded = false
        try await checkAccount()
        let record = try await cloud.record(CompanionCloudStore.pairRecordID)
        if let record, record["state"] as? String == "paired" {
            guard let offerData = record["offer"] as? Data, let phoneData = record["phone"] as? Data else {
                throw CompanionError.invalidSignature
            }
            let authenticated = try CompanionProtocol.decode(CompanionAuthenticatedOffer.self, from: offerData)
            let offer = authenticated.offer
            let phone = try CompanionProtocol.decode(CompanionDevice.self, from: phoneData)
            let expected = role == .mac ? offer.mac : phone
            guard expected.id == deviceID, expected.publicKey == (try makeLocalDevice()).publicKey else {
                throw CompanionError.message("Another device is paired with this account. Unpair it before you continue.")
            }
            if let trust {
                guard trust.pairID == offer.pairID, trust.mac == offer.mac, trust.phone == phone else { throw CompanionError.invalidSignature }
            } else {
                guard role == .mac, let code = defaults.string(forKey: "companion.offerCode"),
                      defaults.string(forKey: "companion.offerAccountID") == currentAccountID,
                      defaults.string(forKey: "companion.offerPairID") == offer.pairID,
                      offer.expiresAt > Date(), let proof = record["proof"] as? Data else {
                    throw CompanionError.message("Pairing could not be verified. Unpair the devices and create a new code.")
                }
                _ = try CompanionProtocol.verifyOffer(authenticated, code: code, now: Date())
                try CompanionProtocol.verifyPairingProof(proof, code: code,
                    receipt: CompanionPairingReceipt(pairID: offer.pairID, mac: offer.mac, phone: phone))
                try saveTrust(CompanionTrust(accountID: currentAccountID!, pairID: offer.pairID, mac: offer.mac, phone: phone))
            }
            clearCode()
            if role == .phone, subscribedPairID != offer.pairID {
                try await cloud.subscribe(pairID: offer.pairID)
                subscribedPairID = offer.pairID
            }
            try await refreshRequests()
        } else {
            let state = record?["state"] as? String
            // The Mac can revoke a pair and create its next offer before the phone refreshes.
            if state == "revoked" || state == "offered" { clearTrust() }
            else if trust != nil { throw CompanionError.message("The paired device is not available in iCloud. Unpair the devices and pair them again.") }
            pendingRequests = []
            history = []
            if let expiry = pairingExpiresAt, expiry <= Date() { clearCode() }
        }
        refreshSucceeded = true
    }

    private func refreshRequests() async throws {
        guard let trust else { return }
        let records = try await cloud.requests(pairID: trust.pairID)
        var requests: [CompanionRequest] = []
        for record in records {
            let signed = try signedRequest(record, trust: trust)
            var request = signed.request
            guard let raw = record["status"] as? String, let status = CompanionRequest.Status(rawValue: raw) else {
                throw CompanionError.invalidSignature
            }
            if status == .approved {
                guard let data = record["response"] as? Data else { throw CompanionError.invalidSignature }
                let response = try CompanionProtocol.decode(CompanionSignedDecision.self, from: data)
                // History verifies the signature at decision time; expiry only prevents new consumption.
                try CompanionProtocol.verifyDecision(response, for: signed, trust: trust, consumed: false,
                    now: min(Date(), response.decision.decidedAt))
                guard response.decision.approved else { throw CompanionError.invalidSignature }
                request.decisionAt = response.decision.decidedAt
            } else {
                request.decisionAt = record["decisionAt"] as? Date
            }
            request.status = status
            request.status = request.effectiveStatus()
            requests.append(request)
        }
        pendingRequests = requests.filter { $0.status == .pending }
        history = requests.filter { $0.status != .pending }
    }

    private func signedRequest(_ record: CKRecord, trust: CompanionTrust) throws -> CompanionSignedRequest {
        guard let data = record["request"] as? Data else { throw CompanionError.invalidSignature }
        let signed = try CompanionProtocol.decode(CompanionSignedRequest.self, from: data)
        guard signed.request.id == record.recordID.recordName,
              signed.request.id == record["requestID"] as? String,
              signed.request.pairID == record["pairID"] as? String else { throw CompanionError.invalidSignature }
        try CompanionProtocol.verifyRequest(signed, trust: trust, now: Date())
        return signed
    }

    private func checkAccount() async throws {
        do {
            let account = try await cloud.accountID()
            guard trust == nil || trust?.accountID == account else {
                accountAvailable = false
                accountMessage = "Sign in to the Apple Account used to pair these devices."
                throw CompanionError.accountUnavailable
            }
            currentAccountID = account
            accountAvailable = true
            accountMessage = nil
            try await cloud.prepareZone(accountID: account)
            if role == .mac { try await cloud.subscribeToMacChanges(accountID: account) }
        } catch {
            accountAvailable = false
            currentAccountID = nil
            if accountMessage == nil { accountMessage = userMessage(error) }
            throw error
        }
    }

    private func verifyCurrentPair(_ expected: CompanionTrust) async throws -> CKRecord {
        try await checkAccount()
        guard let record = try await cloud.record(CompanionCloudStore.pairRecordID),
              record["state"] as? String == "paired", record["pairID"] as? String == expected.pairID,
              let offerData = record["offer"] as? Data, let phoneData = record["phone"] as? Data else { throw CompanionError.notPaired }
        let offer = try CompanionProtocol.decode(CompanionAuthenticatedOffer.self, from: offerData).offer
        let phone = try CompanionProtocol.decode(CompanionDevice.self, from: phoneData)
        guard offer.mac == expected.mac, phone == expected.phone else { throw CompanionError.invalidSignature }
        return record
    }

    private func closeRequest(id: String, status: CompanionRequest.Status) async {
        // Run cleanup outside the cancelled caller's task so a cancelled CLI leaves no live prompt.
        let task = Task { @MainActor [cloud] in
            guard let record = try? await cloud.record(CompanionCloudStore.requestID(id)), record["consumedAt"] == nil,
                  let rawStatus = record["status"] as? String,
                  rawStatus == CompanionRequest.Status.pending.rawValue || rawStatus == CompanionRequest.Status.approved.rawValue else { return }
            record["status"] = status.rawValue
            record["decisionAt"] = Date()
            _ = try? await cloud.save(record)
        }
        await task.value
    }

    private func makeLocalDevice() throws -> CompanionDevice {
        let name: String
        #if os(macOS)
        name = Host.current().localizedName ?? "Mac"
        #elseif os(iOS)
        name = UIDevice.current.model
        #else
        name = "Device"
        #endif
        let device = CompanionDevice(id: deviceID, name: name, role: role, publicKey: try signingKey.publicKey())
        localDevice = device
        return device
    }

    private func saveTrust(_ value: CompanionTrust) throws {
        if role == .mac, trust?.pairID != value.pairID { try saveApprovalPolicy(true) }
        trust = value
        defaults.set(try? CompanionProtocol.encode(value), forKey: "companion.trust")
        hasLocalPairing = true
        pairingID = value.pairID
        pairedDevice = role == .mac ? value.phone : value.mac
    }

    private func reloadApprovalPolicy() throws {
        do {
            let required = try policyStore.read()
            setApprovalPolicy(required.map { $0 ? .phone : .local } ?? .unconfigured)
        } catch {
            setApprovalPolicy(.unavailable)
            throw error
        }
    }

    private func saveApprovalPolicy(_ required: Bool) throws {
        try policyStore.write(required)
        setApprovalPolicy(required ? .phone : .local)
    }

    private func setApprovalPolicy(_ policy: ApprovalPolicy) {
        guard approvalPolicy != policy else { return }
        approvalPolicy = policy
        onApprovalPolicyChange?(requiresPhoneApproval)
    }

    private func clearTrust() {
        let hadTrust = trust != nil
        trust = nil
        defaults.removeObject(forKey: "companion.trust")
        hasLocalPairing = false
        pairingID = nil
        pairedDevice = nil
        subscribedPairID = nil
        if role == .mac, hadTrust { onApprovalPolicyChange?(requiresPhoneApproval) }
    }

    private func showCode(_ code: String, expiresAt: Date) {
        pairingCode = stride(from: 0, to: code.count, by: 4).map { String(code.dropFirst($0).prefix(4)) }.joined(separator: "-")
        pairingExpiresAt = expiresAt
        var components = URLComponents()
        components.scheme = "passtrami"
        components.host = "pair"
        components.queryItems = [URLQueryItem(name: "code", value: pairingCode)]
        pairingURL = components.url
    }

    private func clearCode() {
        pairingCode = nil
        pairingURL = nil
        pairingExpiresAt = nil
        defaults.removeObject(forKey: "companion.offerCode")
        defaults.removeObject(forKey: "companion.offerExpiry")
        defaults.removeObject(forKey: "companion.offerAccountID")
        defaults.removeObject(forKey: "companion.offerPairID")
    }

    private func perform(_ operation: () async throws -> Void) async {
        guard !isBusy else { return }
        isBusy = true
        defer {
            isBusy = false
            if remoteRefreshPending {
                Task { [weak self] in await self?.remoteChanged() }
            }
        }
        // A refresh already in flight must finish before a pair/unpair mutation can start.
        if let refreshTask { _ = await refreshTask.result }
        errorMessage = nil
        do {
            try Task.checkCancellation()
            try await operation()
        }
        catch {
            #if DEBUG && os(iOS)
            CompanionDiagnostics.recordError("operation", error: error)
            #endif
            errorMessage = userMessage(error)
        }
    }

    private func userMessage(_ error: any Error) -> String {
        if let error = error as? CompanionError { return error.localizedDescription }
        if let error = error as? CompanionApprovalPolicyStore.StoreError { return error.localizedDescription }
        if let error = error as? CKError {
            switch error.code {
            case .notAuthenticated: return CompanionError.accountUnavailable.localizedDescription
            case .networkFailure, .networkUnavailable: return "Could not connect to iCloud. Check your internet connection and try again."
            case .serverRecordChanged: return "This request changed on another device. Refresh and try again."
            case .quotaExceeded: return "Your iCloud storage is full. Free some space and try again."
            case .permissionFailure, .missingEntitlement, .badContainer: return "iCloud is not available for this app. Check its signing and iCloud settings."
            default: return "iCloud could not complete this request (\(error.code.rawValue)). Try again."
            }
        }
        if error is CancellationError { return "The request was cancelled." }
        return "The request could not be completed. Try again."
    }
}
