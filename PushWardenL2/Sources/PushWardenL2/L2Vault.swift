import Foundation

/// A login's two fields that can be L2, as stored or as about to be saved.
public struct L2Secrets: Equatable, Sendable {
    public var password: String?
    public var totp: String?

    public init(password: String?, totp: String?) {
        self.password = password
        self.totp = totp
    }

    /// True when either field holds an `l2:` value.
    public var isL2: Bool { isL2Value(password) || isL2Value(totp) }
}

/// A level 2 item's sealed binding: `hosts` and `username` are `nil` when this phone can't
/// decrypt it (L2 not set up here).
public struct L2ItemStatus: Equatable, Sendable {
    public var hosts: [String]?
    public var username: String?
}

/// Core L2 operations on a login for the active user (PROTOCOL.md §2), independent of
/// the SDK's cipher types: the app maps `CipherView` fields in and out. Reading decrypts L2
/// fields; writing never lets plaintext replace an L2 value.
public final class L2Vault: @unchecked Sendable {
    private let crypto: L2Crypto
    private let loadKey: @Sendable () -> [UInt8]?
    private let lock = NSLock()
    private var downgrades = Set<String>()

    /// `loadKey` returns the active user's L2 key, or `nil` when L2 isn't set up on this phone.
    public init(crypto: L2Crypto, loadKey: @escaping @Sendable () -> [UInt8]?) {
        self.crypto = crypto
        self.loadKey = loadKey
    }

    /// True when this phone holds the L2 key for the active user.
    public var isSetUp: Bool {
        guard var key = loadKey() else { return false }
        wipe(&key)
        return true
    }

    /// `secrets` with L2 fields decrypted; a field that can't be decrypted is kept as is.
    public func decrypt(itemId: String, _ secrets: L2Secrets) -> L2Secrets {
        guard secrets.isL2, var key = loadKey() else { return secrets }
        defer { wipe(&key) }
        func open(_ value: String?, _ field: L2Field) -> String? {
            guard let value, isL2Value(value) else { return value }
            return (try? crypto.decryptField(key: key, field: field, itemId: itemId, value: value).secret) ?? value
        }
        return L2Secrets(password: open(secrets.password, .password), totp: open(secrets.totp, .totp))
    }

    /// `L2ItemStatus` of a stored login, or `nil` if it is level 1.
    public func status(itemId: String, _ stored: L2Secrets) -> L2ItemStatus? {
        guard let (field, value) = firstSealed(stored) else { return nil }
        let plain = try? decryptField(itemId: itemId, value: value, field: field)
        return L2ItemStatus(hosts: plain?.hosts, username: plain?.username)
    }

    /// Decrypts one L2 field of item `itemId`; the caller checks the host.
    public func decryptField(itemId: String, value: String, field: L2Field) throws -> L2Plain {
        try withKey { try crypto.decryptField(key: $0, field: field, itemId: itemId, value: value) }
    }

    /// Write guard: `stored` is the login as currently saved (L2 ciphertext intact), `updated`
    /// what is about to be encrypted and uploaded. Returns `nil` when the save may go ahead
    /// unchanged. Otherwise returns the secrets to save instead: plaintext sealed with the stored
    /// values' `u` and `h` (an ordinary save never authorizes new hosts); the caller then drops
    /// password-history entries for which `keepHistoryEntry` is false. Throws if that needs the
    /// L2 key and it isn't on this phone, or a value belongs to another item.
    public func protect(itemId: String?, stored: L2Secrets?, updated: L2Secrets) throws -> L2Secrets? {
        guard let stored, let (field, value) = firstSealed(stored) else { return nil }
        if let itemId, takeDowngrade(itemId) { return nil }
        guard let itemId else { throw L2Error.format("unsaved item") }
        return try withKey { key in
            // The binding of the stored ciphertext, not the (possibly synced) current URIs.
            let sealedTo = try crypto.decryptField(key: key, field: field, itemId: itemId, value: value)
            let binding = L2Binding(itemId: itemId, username: sealedTo.username, hosts: sealedTo.hosts)
            return try seal(updated, key: key, binding: binding)
        }
    }

    /// The login sealed to its current `username` and the hosts of its current `uris`. The UI
    /// confirms the hosts first. The caller drops every plaintext password-history entry
    /// (`keepHistoryEntry(_:storedHistory: [])`). Existing L2 values are re-sealed so the binding
    /// the user just confirmed applies to them too.
    public func toL2(itemId: String, username: String?, uris: [String?], _ secrets: L2Secrets) throws -> L2Secrets {
        let binding = L2Binding(itemId: itemId, username: username ?? "", hosts: L2Hosts.hostsFromUris(uris))
        return try withKey { key in
            try seal(plainValues(secrets, key: key, itemId: itemId), key: key, binding: binding)
        }
    }

    /// The login with L2 fields decrypted; lets the next `protect` for it store plaintext.
    public func toL1(itemId: String, _ secrets: L2Secrets) throws -> L2Secrets {
        // Already L1: no downgrade allowance, or it would linger until the item is L2 again.
        guard secrets.isL2 else { return secrets }
        let plain = try withKey { try plainValues(secrets, key: $0, itemId: itemId) }
        locked { _ = downgrades.insert(itemId) }
        return plain
    }

    /// Whether a password-history entry may stay after `protect`/`toL2`: L2 values and entries
    /// that were already stored stay, new plaintext goes.
    public static func keepHistoryEntry(_ password: String, storedHistory: [String]) -> Bool {
        isL2Value(password) || storedHistory.contains(password)
    }

    // MARK: Private

    private func takeDowngrade(_ itemId: String) -> Bool {
        locked { downgrades.remove(itemId) != nil }
    }

    // `NSLock.withLock` needs iOS 16.
    private func locked<T>(_ body: () -> T) -> T {
        lock.lock()
        defer { lock.unlock() }
        return body()
    }

    private func firstSealed(_ s: L2Secrets) -> (L2Field, String)? {
        if let p = s.password, isL2Value(p) { return (.password, p) }
        if let t = s.totp, isL2Value(t) { return (.totp, t) }
        return nil
    }

    private func plainValues(_ s: L2Secrets, key: [UInt8], itemId: String) throws -> L2Secrets {
        func open(_ value: String?, _ field: L2Field) throws -> String? {
            guard let value, isL2Value(value) else { return value }
            return try crypto.decryptField(key: key, field: field, itemId: itemId, value: value).secret
        }
        return try L2Secrets(password: open(s.password, .password), totp: open(s.totp, .totp))
    }

    private func seal(_ s: L2Secrets, key: [UInt8], binding: L2Binding) throws -> L2Secrets {
        func seal(_ value: String?, _ field: L2Field) throws -> String? {
            guard let value, !value.isEmpty else { return value }
            if isL2Value(value) {
                // Already ciphertext: kept as is. A value copied from another item fails the `i`
                // check here, so the save fails instead.
                _ = try crypto.decryptField(key: key, field: field, itemId: binding.itemId, value: value)
                return value
            }
            return crypto.encryptField(key: key, field: field, binding: binding, secret: value)
        }
        return try L2Secrets(password: seal(s.password, .password), totp: seal(s.totp, .totp))
    }

    private func withKey<T>(_ body: ([UInt8]) throws -> T) throws -> T {
        guard var key = loadKey() else { throw L2Error.notSetUp }
        defer { wipe(&key) }
        return try body(key)
    }
}
