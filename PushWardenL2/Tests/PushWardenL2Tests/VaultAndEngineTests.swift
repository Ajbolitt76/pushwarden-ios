import Foundation
import Testing
@testable import PushWardenL2

private let key = [UInt8](repeating: 0x42, count: 32)
private let itemId = "item-1"

struct L2VaultTests {
    let crypto = L2Crypto()
    var vault: L2Vault { L2Vault(crypto: crypto, loadKey: { key }) }

    @Test func toL2SealsToCurrentUrisAndDecrypts() throws {
        let vault = vault
        let sealed = try vault.toL2(itemId: itemId, username: "alice", uris: ["https://github.com/login"], L2Secrets(password: "pw", totp: "SEED"))
        #expect(isL2Value(sealed.password) && isL2Value(sealed.totp))
        #expect(vault.decrypt(itemId: itemId, sealed) == L2Secrets(password: "pw", totp: "SEED"))
        #expect(vault.status(itemId: itemId, sealed) == L2ItemStatus(hosts: ["github.com"], username: "alice"))
        #expect(vault.status(itemId: itemId, L2Secrets(password: "pw", totp: nil)) == nil)
    }

    @Test func protectKeepsStoredBindingAndBlocksPlaintext() throws {
        let vault = vault
        let stored = try vault.toL2(itemId: itemId, username: "alice", uris: ["github.com"], L2Secrets(password: "pw", totp: nil))
        let saved = try #require(try vault.protect(itemId: itemId, stored: stored, updated: L2Secrets(password: "new", totp: nil)))
        let plain = try vault.decryptField(itemId: itemId, value: saved.password!, field: .password)
        // An ordinary save never authorizes new hosts or usernames.
        #expect(plain == L2Plain(secret: "new", username: "alice", hosts: ["github.com"]))
        #expect(try vault.protect(itemId: itemId, stored: L2Secrets(password: "l1", totp: nil), updated: L2Secrets(password: "x", totp: nil)) == nil)
    }

    @Test func protectRejectsCiphertextFromAnotherItem() throws {
        let vault = vault
        let stored = try vault.toL2(itemId: itemId, username: "", uris: [], L2Secrets(password: "pw", totp: nil))
        let other = try vault.toL2(itemId: "item-2", username: "", uris: [], L2Secrets(password: "pw2", totp: nil))
        #expect(throws: L2Error.self) { try vault.protect(itemId: itemId, stored: stored, updated: other) }
    }

    @Test func toL1AllowsExactlyOnePlaintextSave() throws {
        let vault = vault
        let stored = try vault.toL2(itemId: itemId, username: "", uris: [], L2Secrets(password: "pw", totp: nil))
        #expect(try vault.toL1(itemId: itemId, stored) == L2Secrets(password: "pw", totp: nil))
        #expect(try vault.protect(itemId: itemId, stored: stored, updated: L2Secrets(password: "pw", totp: nil)) == nil)
        #expect(try vault.protect(itemId: itemId, stored: stored, updated: L2Secrets(password: "pw", totp: nil)) != nil)
    }

    @Test func withoutKeyNothingDecryptsOrSaves() throws {
        let sealed = try vault.toL2(itemId: itemId, username: "", uris: [], L2Secrets(password: "pw", totp: nil))
        let noKey = L2Vault(crypto: crypto, loadKey: { nil })
        #expect(!noKey.isSetUp)
        #expect(noKey.decrypt(itemId: itemId, sealed) == sealed)
        #expect(throws: L2Error.notSetUp) { try noKey.protect(itemId: itemId, stored: sealed, updated: L2Secrets(password: "x", totp: nil)) }
        #expect(noKey.status(itemId: itemId, sealed) == L2ItemStatus(hosts: nil, username: nil))
    }

    @Test func historyFilter() {
        #expect(L2Vault.keepHistoryEntry("l2:v1:abc", storedHistory: []))
        #expect(L2Vault.keepHistoryEntry("old", storedHistory: ["old"]))
        #expect(!L2Vault.keepHistoryEntry("new", storedHistory: ["old"]))
    }
}

// MARK: - Engine

final class FakeRelay: L2RelayTransport, @unchecked Sendable {
    let lock = NSLock()
    var sent = [(to: String, body: String)]()
    var onMessage: (@Sendable (RelayMessage) -> Void)?
    var registrations = 0
    var registeredPushTokens = [String?]()
    var pushTokenUpdates = [String]()

    func register(relayUrl: String, publicKey: String, pushToken: String?) async throws -> (id: String, token: String) {
        lock.lock(); registrations += 1; registeredPushTokens.append(pushToken); lock.unlock()
        return ("ph00-0001", "token")
    }

    func setPushToken(relayUrl: String, token: String, pushToken: String) async throws {
        lock.lock(); pushTokenUpdates.append(pushToken); lock.unlock()
    }

    func connect(relayUrl: String, token: String, onMessage: @escaping @Sendable (RelayMessage) -> Void, onState: @escaping @Sendable (Bool) -> Void) {
        lock.lock(); self.onMessage = onMessage; lock.unlock()
        onState(true)
    }

    func send(to: String, body: String) -> Bool {
        lock.lock(); sent.append((to, body)); lock.unlock()
        return true
    }

    func disconnect() {}

    var sentCount: Int { lock.lock(); defer { lock.unlock() }; return sent.count }
}

final class MemoryStore: L2PcConfigStore, @unchecked Sendable {
    let lock = NSLock()
    var configs = [String: PcAutofillConfig]()
    func load(userId: String) -> PcAutofillConfig? { lock.lock(); defer { lock.unlock() }; return configs[userId] }
    func save(userId: String, config: PcAutofillConfig?) { lock.lock(); configs[userId] = config; lock.unlock() }
}

struct FakeAccess: L2PcVaultAccess {
    var logins: [String: L2PcLogin]
    var premium = true
    func activeUserId() async -> String? { "user" }
    func login(itemId: String) async -> L2PcLogin? { logins[itemId] }
    func isPremium() async -> Bool { premium }
    func totpCode(seed: String, date: Date) async -> String? { seed == "SEED" ? "123456" : nil }
}

final class Clock: @unchecked Sendable {
    var now = Date(timeIntervalSince1970: 1_762_646_400)
}

struct EngineTests {
    let crypto = L2Crypto()
    let relay = FakeRelay()
    let store = MemoryStore()
    let clock = Clock()
    let pc = L2Crypto().boxKeyPair(seed: [UInt8](repeating: 9, count: 32))
    let phone = L2Crypto().boxKeyPair(seed: [UInt8](repeating: 8, count: 32))

    private func engine(hosts: [String] = ["github.com"], l2Totp: Bool = true, premium: Bool = true) throws -> L2PcEngine {
        let vault = L2Vault(crypto: crypto, loadKey: { key })
        let secrets = try vault.toL2(itemId: itemId, username: "alice", uris: hosts, L2Secrets(password: "hunter2", totp: "SEED"))
        let login = L2PcLogin(name: "GitHub", password: secrets.password, totp: l2Totp ? secrets.totp : "SEED", organizationUseTotp: false)
        store.save(userId: "user", config: PcAutofillConfig(
            relayUrl: "http://localhost:8080/",
            deviceId: "ph00-0001",
            token: "token",
            publicKey: b64(phone.publicKey),
            secretKey: b64(phone.secretKey),
            pcs: [PairedPc(id: "pc00-0001", publicKey: b64(pc.publicKey), name: "Chrome on Windows")],
        ))
        let clock = clock
        return L2PcEngine(
            crypto: crypto,
            vault: vault,
            store: store,
            relay: relay,
            access: FakeAccess(logins: [itemId: login], premium: premium),
            now: { clock.now },
        )
    }

    private func fill(_ requestId: String = "MDAwMDAwMDAwMDAwMDAwMA==", origin: String = "https://github.com", timeOffset: TimeInterval = 0) -> String {
        L2JSON.object([
            ("v", .int(1)), ("type", .string("fillRequest")), ("requestId", .string(requestId)),
            ("itemId", .string(itemId)), ("origin", .string(origin)),
            ("time", .int(Int64((clock.now.timeIntervalSince1970 + timeOffset) * 1000))),
        ])
    }

    private func deliver(_ e: L2PcEngine, _ json: String, from: String = "pc00-0001", sender: (publicKey: [UInt8], secretKey: [UInt8])? = nil) async {
        let s = sender ?? pc
        await e.handle(RelayMessage(from: from, fromPk: b64(s.publicKey), body: crypto.seal(json, recipientPk: phone.publicKey, senderSk: s.secretKey)))
    }

    private func lastReply() throws -> [String: Any] {
        let body = try #require(relay.sent.last).body
        let text = try crypto.open(body, senderPk: phone.publicKey, recipientSk: pc.secretKey)
        return try #require(JSONSerialization.jsonObject(with: Data(text.utf8)) as? [String: Any])
    }

    @Test func approvedFillSendsPasswordAndTotp() async throws {
        let e = try engine()
        await e.setActive(true)
        await deliver(e, fill())
        let request = try #require(await e.state.requests.first)
        #expect(request.username == "alice" && request.host == "github.com" && request.pcName == "Chrome on Windows")
        #expect(relay.sentCount == 0)
        await e.approve(requestId: request.requestId)
        let reply = try lastReply()
        #expect(reply["status"] as? String == "approved")
        #expect(reply["password"] as? String == "hunter2")
        #expect(reply["totp"] as? String == "123456")
        #expect(await e.state.requests.isEmpty)
    }

    @Test func l1TotpAndNoPremium() async throws {
        let e = try engine(l2Totp: false, premium: false)
        await deliver(e, fill())
        await e.approve(requestId: "MDAwMDAwMDAwMDAwMDAwMA==")
        let reply = try lastReply()
        #expect(reply["password"] as? String == "hunter2")
        #expect(reply["totp"] == nil)
    }

    @Test func wrongHostIsRejected() async throws {
        let e = try engine()
        await deliver(e, fill(origin: "https://evilgithub.com"))
        #expect(await e.state.requests.isEmpty)
        #expect(try lastReply()["status"] as? String == "rejected")
    }

    @Test func staleAndReplayedRequestsAreRejected() async throws {
        let e = try engine()
        await deliver(e, fill(timeOffset: -61))
        #expect(try lastReply()["status"] as? String == "rejected")
        await deliver(e, fill("MTExMTExMTExMTExMTExMQ=="))
        #expect(await e.state.requests.count == 1)
        await deliver(e, fill("MTExMTExMTExMTExMTExMQ=="))
        #expect(await e.state.requests.count == 1)
        #expect(try lastReply()["status"] as? String == "rejected")
    }

    @Test func atMostThreePendingPerPc() async throws {
        let e = try engine()
        for id in ["MDAwMDAwMDAwMDAwMDAwMA==", "MTExMTExMTExMTExMTExMQ==", "MjIyMjIyMjIyMjIyMjIyMg==", "MzMzMzMzMzMzMzMzMzMzMw=="] {
            await deliver(e, fill(id))
        }
        #expect(await e.state.requests.count == 3)
        #expect(try lastReply()["status"] as? String == "rejected")
    }

    @Test func unpairedSenderIsIgnored() async throws {
        let e = try engine()
        let stranger = crypto.boxKeyPair()
        await deliver(e, fill(), sender: stranger)
        // Right id, wrong key: still a stranger.
        await deliver(e, fill(), from: "pc00-0001", sender: stranger)
        #expect(await e.state.requests.isEmpty)
        #expect(relay.sentCount == 0)
    }

    @Test func deniedAndExpired() async throws {
        let e = try engine()
        await deliver(e, fill())
        await e.deny(requestId: "MDAwMDAwMDAwMDAwMDAwMA==")
        #expect(try lastReply()["status"] as? String == "denied")
        await deliver(e, fill("MTExMTExMTExMTExMTExMQ=="))
        clock.now += 61
        await e.approve(requestId: "MTExMTExMTExMTExMTExMQ==")
        let reply = try lastReply()
        #expect(reply["status"] as? String == "expired")
        #expect(reply["password"] == nil)
    }

    @Test func unpairMessageForgetsPc() async throws {
        let e = try engine()
        await deliver(e, fill())
        await deliver(e, #"{"v":1,"type":"unpair"}"#)
        #expect(await e.state.pcs.isEmpty)
        #expect(await e.state.requests.isEmpty)
        #expect(store.load(userId: "user")?.pcs.isEmpty == true)
    }

    @Test func qrPairingStoresPcAndSendsProof() async throws {
        let e = try engine()
        await e.setActive(true)
        let ext = crypto.boxKeyPair()
        let secret = crypto.random(32)
        let qr = L2QrPair(relayUrl: "http://localhost:8080", extId: "ex00-0002", extPublicKey: ext.publicKey, secret: secret, pcName: "Laptop")
        try await e.pairWithQr(qr, phoneName: "iPhone")
        #expect(relay.registrations == 0) // same relay: keeps its identity
        #expect(await e.state.pcs.map(\.name) == ["Chrome on Windows", "Laptop"])
        let sent = try #require(relay.sent.last)
        #expect(sent.to == "ex00-0002")
        let text = try crypto.open(sent.body, senderPk: phone.publicKey, recipientSk: ext.secretKey)
        let msg = try #require(JSONSerialization.jsonObject(with: Data(text.utf8)) as? [String: Any])
        #expect(msg["type"] as? String == "qrPair")
        #expect(msg["proof"] as? String == b64(crypto.qrProof(secret: secret, phonePk: phone.publicKey, extPk: ext.publicKey)))
    }

    @Test func qrPairingWithAnotherRelayRegistersAgain() async throws {
        let e = try engine()
        let ext = crypto.boxKeyPair()
        let qr = L2QrPair(relayUrl: "https://relay.example", extId: "ex00-0002", extPublicKey: ext.publicKey, secret: crypto.random(32), pcName: "Laptop")
        try await e.pairWithQr(qr, phoneName: "iPhone")
        #expect(relay.registrations == 1)
        // A new identity drops the old pairings.
        #expect(await e.state.pcs.map(\.id) == ["ex00-0002"])
        #expect(store.load(userId: "user")?.relayUrl == "https://relay.example/")
    }

    @Test func pushTokenGoesToRelayAndIntoNewRegistrations() async throws {
        let e = try engine()
        await e.onPushToken("fcm-1")
        #expect(relay.pushTokenUpdates == ["fcm-1"])
        try await e.register(relayUrl: "https://relay.example")
        #expect(relay.registeredPushTokens == ["fcm-1"])
    }
}
