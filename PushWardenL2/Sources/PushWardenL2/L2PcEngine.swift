import Foundation

private let keyBytes = 32
private let maxPendingPerPc = 3

/// How long a fill request may wait for the user (PROTOCOL.md §6).
public let pcFillRequestLifetime: TimeInterval = 60
private let replayWindow: TimeInterval = 10 * 60
private let connectTimeout: TimeInterval = 15

/// A paired browser extension.
public struct PairedPc: Codable, Equatable, Sendable, Identifiable {
    public var id: String
    /// b64 X25519 public key.
    public var publicKey: String
    public var name: String

    public init(id: String, publicKey: String, name: String) {
        self.id = id
        self.publicKey = publicKey
        self.name = name
    }
}

/// This phone's relay identity and paired PCs, stored per user (in the Keychain: it holds the
/// relay token and the X25519 secret key).
public struct PcAutofillConfig: Codable, Equatable, Sendable {
    public var relayUrl: String
    public var deviceId: String
    public var token: String
    public var publicKey: String
    public var secretKey: String
    public var pcs: [PairedPc]

    public init(relayUrl: String, deviceId: String, token: String, publicKey: String, secretKey: String, pcs: [PairedPc] = []) {
        self.relayUrl = relayUrl
        self.deviceId = deviceId
        self.token = token
        self.publicKey = publicKey
        self.secretKey = secretKey
        self.pcs = pcs
    }
}

/// A fill request from a paired PC, waiting for the user.
public struct PcFillRequest: Equatable, Sendable, Identifiable {
    public var id: String { requestId }
    public let requestId: String
    public let pcId: String
    public let pcName: String
    public let itemId: String
    public let itemName: String
    /// The username sealed in the ciphertext; the L1 one could have been renamed on a PC.
    public let username: String
    public let origin: String
    public let host: String
    public let requestTime: Date
}

/// Everything the PC autofill screen and the approval screen show.
public struct PcAutofillState: Equatable, Sendable {
    public var relayUrl: String?
    public var phoneId: String?
    public var connected = false
    public var pcs: [PairedPc] = []
    public var requests: [PcFillRequest] = []

    public init() {}
}

/// A frame the relay delivered to this phone (PROTOCOL.md §3).
public struct RelayMessage: Equatable, Sendable {
    public let from: String
    public let fromPk: String
    public let body: String

    public init(from: String, fromPk: String, body: String) {
        self.from = from
        self.fromPk = fromPk
        self.body = body
    }
}

/// Talks to the relay: registration over HTTPS, messages over one WebSocket.
public protocol L2RelayTransport: AnyObject, Sendable {
    /// Registers this phone; returns its device id and relay token.
    func register(relayUrl: String, publicKey: String, pushToken: String?) async throws -> (id: String, token: String)

    /// Tells the relay this phone's current FCM token.
    func setPushToken(relayUrl: String, token: String, pushToken: String) async throws

    /// Opens the WebSocket and authenticates. `onState` gets `true` once the relay says ready and
    /// `false` when the socket closes.
    func connect(
        relayUrl: String,
        token: String,
        onMessage: @escaping @Sendable (RelayMessage) -> Void,
        onState: @escaping @Sendable (Bool) -> Void
    )

    /// Sends an already sealed body to device `to`. False if not connected.
    @discardableResult
    func send(to: String, body: String) -> Bool

    /// Closes the WebSocket, if open.
    func disconnect()
}

/// Per-user storage for `PcAutofillConfig`.
public protocol L2PcConfigStore: Sendable {
    func load(userId: String) -> PcAutofillConfig?
    func save(userId: String, config: PcAutofillConfig?)
}

/// A login as stored, L2 ciphertext intact.
public struct L2PcLogin: Sendable {
    public var name: String
    public var password: String?
    public var totp: String?
    public var organizationUseTotp: Bool

    public init(name: String, password: String?, totp: String?, organizationUseTotp: Bool) {
        self.name = name
        self.password = password
        self.totp = totp
        self.organizationUseTotp = organizationUseTotp
    }
}

/// What the engine needs from the app's vault and account.
public protocol L2PcVaultAccess: Sendable {
    /// The signed-in user, if any.
    func activeUserId() async -> String?
    /// The login `itemId` as stored, or `nil` if missing, deleted or not a login.
    func login(itemId: String) async -> L2PcLogin?
    /// Whether the account may use TOTP (premium).
    func isPremium() async -> Bool
    /// The current code for a TOTP seed (`otpauth://`, base32 or `steam://`), via the SDK.
    func totpCode(seed: String, date: Date) async -> String?
}

/// Phone side of PC autofill: relay registration, QR pairing, and approving fill requests
/// (DESIGN.md flows 3–4, PROTOCOL.md §5b–6). The app calls `setActive(true)` while it is in the
/// foreground with the vault unlocked, so requests reach the approval screen at once; otherwise
/// the relay queues them for 120 s and pushes an alert that opens the app.
public actor L2PcEngine {
    private let crypto: L2Crypto
    private let vault: L2Vault
    private let store: L2PcConfigStore
    private let relay: L2RelayTransport
    private let access: L2PcVaultAccess
    private let now: @Sendable () -> Date
    private let reconnectDelay: TimeInterval

    /// State changes, for one consumer (the app bridges it to its own publisher).
    public nonisolated let states: AsyncStream<PcAutofillState>
    private let continuation: AsyncStream<PcAutofillState>.Continuation

    /// Current state.
    public private(set) var state = PcAutofillState() {
        didSet { if state != oldValue { continuation.yield(state) } }
    }

    private var wanted = false
    private var pushToken: String?
    private var connectionId = 0
    private var seenRequestIds = [String: Date]()
    private var reconnectTask: Task<Void, Never>?

    public init(
        crypto: L2Crypto,
        vault: L2Vault,
        store: L2PcConfigStore,
        relay: L2RelayTransport,
        access: L2PcVaultAccess,
        now: @escaping @Sendable () -> Date = { Date() },
        reconnectDelay: TimeInterval = 5
    ) {
        self.crypto = crypto
        self.vault = vault
        self.store = store
        self.relay = relay
        self.access = access
        self.now = now
        self.reconnectDelay = reconnectDelay
        (states, continuation) = AsyncStream.makeStream(bufferingPolicy: .bufferingNewest(1))
    }

    /// Foreground with the vault unlocked: the only time requests can be shown and answered.
    public func setActive(_ active: Bool) async {
        guard active != wanted else { return }
        wanted = active
        if active { await connect() } else { disconnect() }
    }

    /// Registers this phone with the relay at `relayUrl`. A new identity: earlier pairings were
    /// with the old key and are dropped.
    public func register(relayUrl: String) async throws {
        guard let user = await access.activeUserId() else { throw L2Error.notSetUp }
        guard let base = L2RelayURL.base(relayUrl) else { throw L2Error.format("relay URL must use https") }
        let (pk, sk) = crypto.boxKeyPair()
        let (id, token) = try await relay.register(relayUrl: base, publicKey: b64(pk), pushToken: pushToken)
        store.save(userId: user, config: PcAutofillConfig(relayUrl: base, deviceId: id, token: token, publicKey: b64(pk), secretKey: b64(sk)))
        await connect()
    }

    /// Pairs with the PC whose QR code was scanned (PROTOCOL.md §5b): registers with its relay
    /// if needed, stores the PC and sends the proof. Call after the user confirmed.
    public func pairWithQr(_ qr: L2QrPair, phoneName: String) async throws {
        guard let user = await access.activeUserId(), let base = L2RelayURL.base(qr.relayUrl) else {
            throw L2Error.notSetUp
        }
        if store.load(userId: user)?.relayUrl != base { try await register(relayUrl: base) }
        if !state.connected { await connect() }
        // Messages sent before the relay's "ready" would arrive before auth.
        let deadline = now().addingTimeInterval(connectTimeout)
        while !state.connected {
            guard now() < deadline else { throw L2Error.format("relay not reachable") }
            try await Task.sleep(nanoseconds: 100_000_000)
        }
        guard var config = store.load(userId: user) else { throw L2Error.notSetUp }
        let extPk = b64(qr.extPublicKey)
        config.pcs = config.pcs.filter { $0.id != qr.extId } + [PairedPc(id: qr.extId, publicKey: extPk, name: qr.pcName)]
        store.save(userId: user, config: config)
        state.pcs = config.pcs
        let proof = try crypto.qrProof(secret: qr.secret, phonePk: unb64(config.publicKey), extPk: qr.extPublicKey)
        try send(config, to: qr.extId, pk: extPk, L2PcReplies.qrPair(proofB64: b64(proof), name: phoneName))
    }

    /// Opens the relay connection and reloads state.
    public func connect() async {
        let config = await currentConfig()
        var fresh = PcAutofillState()
        fresh.relayUrl = config?.relayUrl
        fresh.phoneId = config?.deviceId
        fresh.pcs = config?.pcs ?? []
        state = fresh
        guard let config else { return }
        reconnectTask?.cancel()
        connectionId += 1
        let id = connectionId
        relay.connect(
            relayUrl: config.relayUrl,
            token: config.token,
            onMessage: { [weak self] m in Task { await self?.handle(m) } },
            onState: { [weak self] connected in Task { await self?.connectionChanged(connected, id: id) } }
        )
    }

    /// Closes the relay connection and drops pending requests.
    public func disconnect() {
        reconnectTask?.cancel()
        connectionId += 1
        relay.disconnect()
        state.connected = false
        state.requests = []
    }

    /// Sends the password (and TOTP code) for `requestId`. Call after user verification.
    public func approve(requestId: String) async { await answer(requestId, approve: true) }

    /// Denies `requestId`.
    public func deny(requestId: String) async { await answer(requestId, approve: false) }

    /// Forgets the PC `pcId` and tells it.
    public func unpair(pcId: String) async {
        guard let user = await access.activeUserId(), var config = store.load(userId: user),
              let pc = config.pcs.first(where: { $0.id == pcId })
        else { return }
        try? send(config, to: pc.id, pk: pc.publicKey, L2PcReplies.unpair())
        config.pcs.removeAll { $0.id == pcId }
        store.save(userId: user, config: config)
        state.pcs = config.pcs
        state.requests.removeAll { $0.pcId == pcId }
    }

    /// A new FCM token (Firebase hands one out on every launch): remembered for the next
    /// registration, and sent to the relay if this phone is registered.
    public func onPushToken(_ token: String) async {
        pushToken = token
        guard let config = await currentConfig() else { return }
        // Best effort: on failure the relay can't wake the phone until the next launch.
        try? await relay.setPushToken(relayUrl: config.relayUrl, token: config.token, pushToken: token)
    }

    // MARK: Relay events

    private func connectionChanged(_ connected: Bool, id: Int) {
        // A callback from a socket that was closed or replaced since.
        guard id == connectionId else { return }
        state.connected = connected
        // Dropped while it should be open (network change, relay restart): retry.
        guard !connected, wanted else { return }
        reconnectTask?.cancel()
        let delay = reconnectDelay
        reconnectTask = Task { [weak self] in
            try? await Task.sleep(nanoseconds: UInt64(delay * 1_000_000_000))
            guard !Task.isCancelled else { return }
            await self?.reconnectIfWanted()
        }
    }

    private func reconnectIfWanted() async {
        if wanted, !state.connected { await connect() }
    }

    /// Handles one delivered frame. Internal for tests.
    func handle(_ m: RelayMessage) async {
        guard let user = await access.activeUserId(), let config = store.load(userId: user),
              let fromPk = try? unb64(m.fromPk, length: keyBytes),
              let secretKey = try? unb64(config.secretKey),
              let text = try? crypto.open(m.body, senderPk: fromPk, recipientSk: secretKey),
              let msg = try? L2PcMessage.parse(text),
              // Only paired PCs, by id and key (PROTOCOL.md §3: `fromPk` is checked after pairing).
              let pc = config.pcs.first(where: { $0.id == m.from && $0.publicKey == m.fromPk })
        else { return }
        switch msg {
        case let .fillRequest(requestId, itemId, origin, time):
            await onFillRequest(config, pc, requestId: requestId, itemId: itemId, origin: origin, time: time)
        case .unpair:
            var updated = config
            updated.pcs.removeAll { $0.id == pc.id }
            store.save(userId: user, config: updated)
            state.pcs = updated.pcs
            state.requests.removeAll { $0.pcId == pc.id }
        }
    }

    private func onFillRequest(
        _ config: PcAutofillConfig,
        _ pc: PairedPc,
        requestId: String,
        itemId: String,
        origin: String,
        time: Int64
    ) async {
        let now = now()
        seenRequestIds = seenRequestIds.filter { now.timeIntervalSince($0.value) <= replayWindow }
        let reject = { try? self.send(config, to: pc.id, pk: pc.publicKey, L2PcReplies.fillResult(requestId: requestId, status: .rejected)) }
        let requestTime = Date(timeIntervalSince1970: TimeInterval(time) / 1000)
        let pending = state.requests.filter { $0.pcId == pc.id }.count
        guard abs(now.timeIntervalSince(requestTime)) <= pcFillRequestLifetime,
              seenRequestIds[requestId] == nil,
              pending < maxPendingPerPc
        else {
            reject()
            return
        }
        seenRequestIds[requestId] = now
        guard let login = await access.login(itemId: itemId),
              let password = login.password, isL2Value(password),
              let plain = try? vault.decryptField(itemId: itemId, value: password, field: .password),
              // Only the hosts sealed in the ciphertext count; L1 URIs could be attacker-edited.
              L2Hosts.originAllowed(origin, hosts: plain.hosts),
              // Re-checked: the lookup above suspended, and other requests may have arrived.
              state.requests.filter({ $0.pcId == pc.id }).count < maxPendingPerPc
        else {
            reject()
            return
        }
        state.requests.append(PcFillRequest(
            requestId: requestId,
            pcId: pc.id,
            pcName: pc.name,
            itemId: itemId,
            itemName: login.name,
            username: plain.username,
            origin: origin,
            host: L2Hosts.host(of: origin),
            requestTime: requestTime
        ))
    }

    private func answer(_ requestId: String, approve: Bool) async {
        guard let request = state.requests.first(where: { $0.requestId == requestId }) else { return }
        state.requests.removeAll { $0.requestId == requestId }
        guard let user = await access.activeUserId(), let config = store.load(userId: user),
              let pc = config.pcs.first(where: { $0.id == request.pcId })
        else { return }
        let now = now()
        let reply: String
        if now.timeIntervalSince(request.requestTime) > pcFillRequestLifetime {
            reply = L2PcReplies.fillResult(requestId: requestId, status: .expired)
        } else if !approve {
            reply = L2PcReplies.fillResult(requestId: requestId, status: .denied)
        } else {
            reply = await approvedReply(request, now: now)
        }
        try? send(config, to: pc.id, pk: pc.publicKey, reply)
    }

    private func approvedReply(_ request: PcFillRequest, now: Date) async -> String {
        guard let login = await access.login(itemId: request.itemId),
              let password = login.password, isL2Value(password),
              let plain = try? vault.decryptField(itemId: request.itemId, value: password, field: .password),
              L2Hosts.originAllowed(request.origin, hosts: plain.hosts)
        else { return L2PcReplies.fillResult(requestId: request.requestId, status: .error) }
        var totp: String?
        let mayUseTotp = login.organizationUseTotp ? true : await access.isPremium()
        if let seed = login.totp, !seed.isEmpty, mayUseTotp {
            if isL2Value(seed) {
                // The TOTP value passes its own item, field and host checks (PROTOCOL.md §6).
                if let t = try? vault.decryptField(itemId: request.itemId, value: seed, field: .totp),
                   L2Hosts.originAllowed(request.origin, hosts: t.hosts) {
                    totp = await access.totpCode(seed: t.secret, date: now)
                }
            } else {
                totp = await access.totpCode(seed: seed, date: now)
            }
        }
        // Only 6–8 digit codes are allowed on the wire (PROTOCOL.md §4).
        if let code = totp, code.range(of: "^[0-9]{6,8}$", options: .regularExpression) == nil { totp = nil }
        return L2PcReplies.fillResult(requestId: request.requestId, status: .approved, password: plain.secret, totp: totp)
    }

    // MARK: Helpers

    private func currentConfig() async -> PcAutofillConfig? {
        guard let user = await access.activeUserId() else { return nil }
        return store.load(userId: user)
    }

    private func send(_ config: PcAutofillConfig, to: String, pk: String, _ json: String) throws {
        let body = try crypto.seal(json, recipientPk: unb64(pk, length: keyBytes), senderSk: unb64(config.secretKey))
        relay.send(to: to, body: body)
    }
}
