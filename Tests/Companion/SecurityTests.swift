import CloudKit
import Foundation

extension UnpairTests {
    static func checkApprovalPolicy() async throws {
        for state in ["revoked", "offered", "missing", "changed pair", "changed account", "offline"] {
            try await withDefaults { defaults in
                try saveTrust(defaults)
                policy.required = true
                let service = makeService(role: .mac, defaults: defaults)
                expect(service.requiresPhoneApproval, "The protected requirement must load at startup")
                CompanionCloudStore.pair = try pairRecord(pairID: state == "changed pair" ? "new-pair" : trust.pairID)
                switch state {
                case "revoked", "offered": CompanionCloudStore.pair?["state"] = state
                case "missing": CompanionCloudStore.pair = nil
                case "changed account": CompanionCloudStore.account = "another-account"
                case "offline": CompanionCloudStore.accountError = CKError(.networkUnavailable)
                default: break
                }
                for reuse in [false, true] {
                    do {
                        _ = try await service.authorizePasswordAccess(domain: "example.invalid", username: "test", reuseApproval: reuse)
                        preconditionFailure("A \(state) pairing must not authorize password access")
                    } catch { }
                }
                expect(service.requiresPhoneApproval && policy.required == true,
                       "A \(state) pairing must retain the protected requirement")
                expect(makeService(role: .mac, defaults: defaults).requiresPhoneApproval,
                       "The requirement must survive restart after \(state)")
                expect(CompanionCloudStore.saveCount == 0, "A failed authorization must not make a request")
            }
        }

        try await withDefaults { defaults in
            try saveTrust(defaults)
            policy.required = true
            CompanionCloudStore.pair = try pairRecord()
            let service = makeService(role: .mac, defaults: defaults)
            let remote = try await service.authorizePasswordAccess(domain: "example.invalid", username: "test", reuseApproval: true)
            expect(remote && CompanionCloudStore.saveCount == 0, "Retained approval must validate pairing without making a new request")
            var revoked = false
            service.onApprovalPolicyChange = { _ in revoked = true }
            await service.unpair()
            expect(revoked, "Unpairing must revoke retained approvals even when the requirement stays enabled")
            expect(!service.hasLocalPairing && service.requiresPhoneApproval && policy.required == true,
                   "Explicit unpair must not disable the separate approval requirement")
        }

        for initial in ["required", "absent", "unreadable"] {
            for allow in [false, true] {
                try await withDefaults { defaults in
                    policy.required = initial == "required" ? true : nil
                    if initial == "unreadable" { policy.readError = CompanionError.message("Test store unavailable") }
                    CompanionCloudStore.accountError = CKError(.networkUnavailable)
                    var authenticationCount = 0
                    let service = makeService(role: .mac, defaults: defaults, authenticatePolicyChange: {
                        authenticationCount += 1
                        if !allow { throw CompanionError.cancelled }
                    })
                    await service.setPhoneApprovalRequired(false)
                    expect(authenticationCount == 1, "Local approval requires explicit authentication from \(initial)")
                    expect(policy.writes == (allow ? [false] : []), "Only successful authentication may write local policy")
                    expect(service.requiresPhoneApproval == (!allow && initial == "required"),
                           "A failed authentication must retain the previous policy")
                    expect(service.approvalPolicyNeedsSetup == (!allow && initial != "required"),
                           "Failed recovery must remain blocked")
                    expect(CompanionCloudStore.accountReads == 0, "Local recovery must work without CloudKit")
                    if allow {
                        policy.readError = nil
                        let remote = try await service.authorizePasswordAccess(domain: "example.invalid", username: "test")
                        expect(!remote, "Authenticated local selection uses Apple's normal local approval")
                        let restarted = makeService(role: .mac, defaults: defaults)
                        expect(!restarted.requiresPhoneApproval && !restarted.approvalPolicyNeedsSetup,
                               "Authenticated local selection must survive restart")
                    }
                }
            }
        }

        for failure in ["absent", "unreadable"] {
            try await withDefaults { defaults in
                if failure == "unreadable" { policy.readError = CompanionError.message("Test store unavailable") }
                defaults.set(false, forKey: "useIPhoneApproval")
                let service = makeService(role: .mac, defaults: defaults)
                expect(!service.requiresPhoneApproval && service.approvalPolicyNeedsSetup,
                       "An unconfigured install must not require the engine's FDA-only recovery")
                expect(policy.writes.isEmpty, "Startup must not create a disabled policy")
                do {
                    _ = try await service.authorizePasswordAccess(domain: "example.invalid", username: "test")
                    preconditionFailure("An \(failure) protected policy must block access")
                } catch { }
                expect(CompanionCloudStore.accountReads == 0, "Policy setup must not access iCloud")
            }
        }

        try await withDefaults { defaults in
            policy.required = true
            for tampering in ["false", "removed", "removed with trust"] {
                if tampering == "false" { defaults.set(false, forKey: "useIPhoneApproval") }
                else { defaults.removeObject(forKey: "useIPhoneApproval") }
                if tampering == "removed with trust" { defaults.removeObject(forKey: "companion.trust") }
                let service = makeService(role: .mac, defaults: defaults)
                expect(service.requiresPhoneApproval, "Defaults tampering must not change protected policy: \(tampering)")
            }
            expect(policy.writes.isEmpty, "Reading defaults must never write protected policy")
        }

        for failure in ["absent", "unreadable"] {
            try await withDefaults { defaults in
                policy.required = false
                let service = makeService(role: .mac, defaults: defaults)
                if failure == "absent" { policy.required = nil }
                else { policy.readError = CompanionError.message("Test store unavailable") }
                do {
                    _ = try await service.authorizePasswordAccess(domain: "example.invalid", username: "test")
                    preconditionFailure("Re-read protected policy before local access when storage is \(failure)")
                } catch { }
                expect(service.approvalPolicyNeedsSetup, "Storage loss must not keep cached local approval")
            }
        }

        try await withDefaults { defaults in
            policy.required = true
            policy.writeError = CompanionError.message("Test write failed")
            let service = makeService(role: .mac, defaults: defaults, authenticatePolicyChange: {})
            await service.setPhoneApprovalRequired(false)
            expect(service.requiresPhoneApproval && policy.required == true && service.errorMessage != nil,
                   "A failed protected write must not disable the requirement")
        }

        try await withDefaults { defaults in
            let record = try await makeOffer(defaults)
            try claimOffer(record, defaults: defaults)
            policy.writeError = CompanionError.message("Test write failed")
            let service = makeService(role: .mac, defaults: defaults)
            await service.refresh()
            expect(!service.hasLocalPairing && defaults.data(forKey: "companion.trust") == nil,
                   "A protected write failure must prevent Mac trust activation")
            expect(service.errorMessage != nil && service.approvalPolicyNeedsSetup,
                   "A failed enrollment must stay blocked and expose its error")
        }

        try await withDefaults { defaults in
            policy.required = true
            let phoneService = makeService(role: .phone, defaults: defaults)
            await phoneService.setPhoneApprovalRequired(false)
            expect(policy.required == true && policy.reads == 0 && policy.writes.isEmpty && phoneService.errorMessage != nil,
                   "Phone actions must not read or write the Mac's approval policy")
        }
        print("Companion policy checks passed: protected policy, defaults tampering, absent/unreadable states, storage loss, authenticated recovery, write failure, and remote loss")
    }

    static func withPhoneDefaults(_ operation: (UserDefaults) async throws -> Void) async throws {
        let suite = "io.zats.Passtrami.tests.phone.\(UUID().uuidString)"
        let defaults = UserDefaults(suiteName: suite)!
        defer { defaults.removePersistentDomain(forName: suite) }
        defaults.set(phone.id, forKey: "companion.deviceID.phone")
        try await operation(defaults)
    }

    static func checkAuthenticatedEnrollment() async throws {
        for inputKind in ["manual", "QR"] {
            try await withDefaults { macDefaults in
                _ = try await makeOffer(macDefaults)
                let code = macDefaults.string(forKey: "companion.offerCode")!
                let input = inputKind == "QR" ? "passtrami://pair?code=\(code)" : code.lowercased()
                try await withPhoneDefaults { phoneDefaults in
                    let phoneService = makeService(role: .phone, defaults: phoneDefaults)
                    await phoneService.pair(code: input)
                    expect(phoneService.hasLocalPairing && phoneService.errorMessage == nil,
                           "The authenticated \(inputKind) offer must pair without an extra confirmation step")
                    let macService = makeService(role: .mac, defaults: macDefaults)
                    var sawPolicyBeforeTrust = false
                    macService.onApprovalPolicyChange = { required in
                        sawPolicyBeforeTrust = required && policy.required == true
                            && macDefaults.data(forKey: "companion.trust") == nil && !macService.hasLocalPairing
                    }
                    await macService.refresh()
                    expect(macService.hasLocalPairing && macService.requiresPhoneApproval,
                           "The real Mac must verify the receipt and require phone approval")
                    expect(sawPolicyBeforeTrust, "Persist and publish the requirement before activating Mac trust")
                }
            }
        }

        for changed in ["Mac key", "Mac ID", "Mac name", "Mac role", "pair ID", "expiry", "purpose", "version", "authentication", "unsigned"] {
            try await withDefaults { macDefaults in
                let record = try await makeOffer(macDefaults)
                let authenticated = try CompanionProtocol.decode(CompanionAuthenticatedOffer.self, from: record["offer"] as! Data)
                let offer = authenticated.offer
                let alteredMac = CompanionDevice(id: changed == "Mac ID" ? "other-mac" : offer.mac.id,
                    name: changed == "Mac name" ? "Other Mac" : offer.mac.name,
                    role: changed == "Mac role" ? .phone : .mac,
                    publicKey: changed == "Mac key" ? Data("other-key".utf8) : offer.mac.publicKey)
                let alteredOffer = CompanionPairingOffer(pairID: changed == "pair ID" ? "other-pair" : offer.pairID,
                    mac: alteredMac, expiresAt: changed == "expiry" ? offer.expiresAt.addingTimeInterval(1) : offer.expiresAt,
                    purpose: changed == "purpose" ? "other-purpose" : offer.purpose,
                    version: changed == "version" ? 2 : offer.version)
                let altered = CompanionAuthenticatedOffer(offer: alteredOffer,
                    authentication: changed == "authentication" ? Data("invalid".utf8) : authenticated.authentication)
                record["pairID"] = alteredOffer.pairID
                record["offer"] = changed == "unsigned" ? try CompanionProtocol.encode(alteredOffer) : try CompanionProtocol.encode(altered)
                let genuineCode = macDefaults.string(forKey: "companion.offerCode")!
                try await withPhoneDefaults { phoneDefaults in
                    let phoneService = makeService(role: .phone, defaults: phoneDefaults)
                    await phoneService.pair(code: "passtrami://pair?code=\(genuineCode)")
                    expect(!phoneService.hasLocalPairing && phoneService.errorMessage != nil,
                           "The genuine QR must not accept a changed \(changed)")
                    expect(phoneDefaults.data(forKey: "companion.trust") == nil && CompanionCloudStore.saveCount == 0,
                           "Reject a changed \(changed) before saving a receipt or phone trust")
                }
            }
        }
        print("Companion enrollment checks passed: manual/QR equivalence, policy-before-trust ordering, complete offer binding, and unsigned-offer rejection")
    }
}
