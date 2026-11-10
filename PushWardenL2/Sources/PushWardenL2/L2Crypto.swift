import Clibsodium
import Foundation

private let keyBytes = 32
private let saltBytes = 16
private let nonceBytes = 24
private let macBytes = 16
private let wrappedBytes = nonceBytes + macBytes + keyBytes
private let argon2id13: Int32 = 2
private let opsRange = 3 ... 10
private let memMiBRange = 64 ... 1024

/// Prefix of every L2 field value (PROTOCOL.md §2).
public let l2Prefix = "l2:v1:"

/// Name of the hidden custom field that holds the L2 key item (PROTOCOL.md §1).
public let l2KeyFieldName = "l2key"

/// Display name for a newly created key item. Clients find it by `l2KeyFieldName`.
public let l2KeyItemName = "PushWarden key – do not edit"

/// Largest decoded relay `body` (PROTOCOL.md §3).
public let l2MaxBodyBytes = 8 * 1024

/// Any `l2:` value. Unknown versions must not be treated as plaintext.
public func isL2Value(_ value: String?) -> Bool {
    value?.hasPrefix("l2:") == true
}

/// Errors from L2 crypto and parsing.
public enum L2Error: Error, Equatable {
    /// The L2 password didn't unwrap the key.
    case wrongPassword
    /// Malformed, tampered, out-of-bounds or wrong-field L2 data.
    case format(String)
    /// L2 isn't set up on this phone, so an L2 item can't be encrypted or decrypted.
    case notSetUp
}

/// The two login fields that can hold L2 values.
public enum L2Field: String, Sendable {
    case password
    case totp
}

/// Argon2id cost for wrapping the L2 key.
public struct L2KdfParams: Equatable, Sendable {
    public var ops: Int
    public var memMiB: Int

    public init(ops: Int, memMiB: Int) {
        self.ops = ops
        self.memMiB = memMiB
    }

    public static let `default` = L2KdfParams(ops: 3, memMiB: 256)
}

/// What an L2 value is sealed to besides its field (PROTOCOL.md §2: `i`, `u`, `h`).
public struct L2Binding: Equatable, Sendable {
    public var itemId: String
    public var username: String
    public var hosts: [String]

    public init(itemId: String, username: String, hosts: [String]) {
        self.itemId = itemId
        self.username = username
        self.hosts = hosts
    }
}

/// A decrypted L2 field: the secret, the username shown on approval, and the allowed hosts.
public struct L2Plain: Equatable, Sendable {
    public var secret: String
    public var username: String
    public var hosts: [String]
}

private struct KeyItemJSON: Decodable {
    let v: Int
    let kdf: String
    let ops: Int
    let memMiB: Int
    let salt: String
    let wrappedKey: String
}

private struct FieldPayload: Decodable {
    let f: String
    let i: String
    let u: String
    let v: String
    let h: [String]
}

/// Swift port of `protocol/src/l2.ts` and `pairing.ts`. Must produce byte-identical output for
/// the shared vectors in `protocol/vectors/v1.json`.
public struct L2Crypto: Sendable {
    public init() {
        precondition(sodium_init() >= 0, "libsodium failed to initialize")
    }

    /// 32 random bytes.
    public func createKey() -> [UInt8] { random(keyBytes) }

    /// Wraps `key` under `password`; returns the `l2key` field value.
    public func wrapKey(
        _ key: [UInt8],
        password: String,
        params: L2KdfParams = .default,
        salt: [UInt8]? = nil,
        nonce: [UInt8]? = nil
    ) throws -> String {
        try checkParams(ops: params.ops, memMiB: params.memMiB)
        precondition(key.count == keyBytes, "L2 key must be 32 bytes")
        let salt = salt ?? random(saltBytes)
        let nonce = nonce ?? random(nonceBytes)
        var kek = try self.kek(password, salt: salt, params: params)
        defer { wipe(&kek) }
        var boxed = [UInt8](repeating: 0, count: macBytes + key.count)
        precondition(crypto_secretbox_easy(&boxed, key, UInt64(key.count), nonce, kek) == 0)
        return L2JSON.object([
            ("v", .int(1)),
            ("kdf", .string("argon2id")),
            ("ops", .int(Int64(params.ops))),
            ("memMiB", .int(Int64(params.memMiB))),
            ("salt", .string(b64(salt))),
            ("wrappedKey", .string(b64(nonce + boxed))),
        ])
    }

    /// Unwraps the L2 key; throws `L2Error.wrongPassword` or `L2Error.format`.
    public func unwrapKey(_ fieldValue: String, password: String) throws -> [UInt8] {
        let item: KeyItemJSON
        do {
            item = try JSONDecoder().decode(KeyItemJSON.self, from: Data(fieldValue.utf8))
        } catch {
            throw L2Error.format("malformed L2 key item")
        }
        guard item.v == 1, item.kdf == "argon2id" else { throw L2Error.format("unsupported key item") }
        try checkParams(ops: item.ops, memMiB: item.memMiB)
        let salt = try unb64(item.salt, length: saltBytes)
        let wrapped = try unb64(item.wrappedKey, length: wrappedBytes)
        var kek = try self.kek(password, salt: salt, params: L2KdfParams(ops: item.ops, memMiB: item.memMiB))
        defer { wipe(&kek) }
        var key = [UInt8](repeating: 0, count: keyBytes)
        let boxed = Array(wrapped[nonceBytes...])
        let nonce = Array(wrapped[..<nonceBytes])
        guard crypto_secretbox_open_easy(&key, boxed, UInt64(boxed.count), nonce, kek) == 0 else {
            throw L2Error.wrongPassword
        }
        return key
    }

    private func checkParams(ops: Int, memMiB: Int) throws {
        guard opsRange.contains(ops), memMiBRange.contains(memMiB) else {
            throw L2Error.format("L2 key item KDF parameters out of bounds")
        }
    }

    private func kek(_ password: String, salt: [UInt8], params: L2KdfParams) throws -> [UInt8] {
        var out = [UInt8](repeating: 0, count: keyBytes)
        // Trailing NUL so the buffer is never empty; it isn't part of the length.
        var pw = Array(password.utf8) + [0]
        defer { wipe(&pw) }
        let rc = pw.withUnsafeBufferPointer { buf in
            buf.baseAddress!.withMemoryRebound(to: CChar.self, capacity: buf.count) { p in
                crypto_pwhash(
                    &out,
                    UInt64(out.count),
                    p,
                    UInt64(buf.count - 1),
                    salt,
                    UInt64(params.ops),
                    params.memMiB * 1024 * 1024,
                    argon2id13
                )
            }
        }
        guard rc == 0 else { throw L2Error.format("crypto_pwhash failed (out of memory?)") }
        return out
    }

    /// Encrypts `secret` for `field`, sealed to `binding`.
    public func encryptField(
        key: [UInt8],
        field: L2Field,
        binding: L2Binding,
        secret: String,
        nonce: [UInt8]? = nil
    ) -> String {
        precondition(!binding.itemId.isEmpty, "L2 values need the item id")
        let nonce = nonce ?? random(nonceBytes)
        var payload = Array(L2JSON.object([
            ("f", .string(field.rawValue)),
            ("i", .string(binding.itemId)),
            ("u", .string(binding.username)),
            ("v", .string(secret)),
            ("h", .strings(binding.hosts)),
        ]).utf8)
        defer { wipe(&payload) }
        var boxed = [UInt8](repeating: 0, count: macBytes + payload.count)
        precondition(crypto_secretbox_easy(&boxed, payload, UInt64(payload.count), nonce, key) == 0)
        return l2Prefix + b64(nonce + boxed)
    }

    /// Decrypts an L2 value read from `field` of item `itemId`; throws `L2Error.format`.
    public func decryptField(key: [UInt8], field: L2Field, itemId: String, value: String) throws -> L2Plain {
        guard value.hasPrefix(l2Prefix) else { throw L2Error.format("not an l2:v1 value") }
        let raw = try unb64(String(value.dropFirst(l2Prefix.count)))
        guard raw.count >= nonceBytes + macBytes else { throw L2Error.format("L2 value too short") }
        let boxed = Array(raw[nonceBytes...])
        var plain = [UInt8](repeating: 0, count: boxed.count - macBytes)
        defer { wipe(&plain) }
        guard crypto_secretbox_open_easy(&plain, boxed, UInt64(boxed.count), Array(raw[..<nonceBytes]), key) == 0
        else { throw L2Error.format("L2 value doesn't decrypt") }
        guard String(bytes: plain, encoding: .utf8) != nil else { throw L2Error.format("invalid UTF-8") }
        let payload: FieldPayload
        do {
            payload = try JSONDecoder().decode(FieldPayload.self, from: Data(plain))
        } catch {
            throw L2Error.format("malformed L2 payload")
        }
        guard payload.f == field.rawValue else {
            throw L2Error.format("L2 value is for field \(payload.f), read from \(field.rawValue)")
        }
        guard payload.i == itemId else { throw L2Error.format("L2 value belongs to another item") }
        return L2Plain(secret: payload.v, username: payload.u, hosts: payload.h)
    }

    /// `b64(nonce ‖ crypto_box_easy(json))` (PROTOCOL.md §4).
    public func seal(_ json: String, recipientPk: [UInt8], senderSk: [UInt8], nonce: [UInt8]? = nil) -> String {
        let nonce = nonce ?? random(nonceBytes)
        let msg = Array(json.utf8)
        var boxed = [UInt8](repeating: 0, count: macBytes + msg.count)
        precondition(crypto_box_easy(&boxed, msg, UInt64(msg.count), nonce, recipientPk, senderSk) == 0)
        return b64(nonce + boxed)
    }

    /// Opens a box from `senderPk`; throws `L2Error.format` if it doesn't authenticate.
    public func open(_ body: String, senderPk: [UInt8], recipientSk: [UInt8]) throws -> String {
        let raw = try unb64(body)
        guard raw.count <= l2MaxBodyBytes, raw.count >= nonceBytes + macBytes else {
            throw L2Error.format("bad body length")
        }
        let boxed = Array(raw[nonceBytes...])
        var plain = [UInt8](repeating: 0, count: boxed.count - macBytes)
        guard crypto_box_open_easy(
            &plain, boxed, UInt64(boxed.count), Array(raw[..<nonceBytes]), senderPk, recipientSk
        ) == 0 else { throw L2Error.format("message doesn't authenticate") }
        guard let text = String(bytes: plain, encoding: .utf8) else { throw L2Error.format("invalid UTF-8") }
        return text
    }

    /// New X25519 keypair.
    public func boxKeyPair(seed: [UInt8]? = nil) -> (publicKey: [UInt8], secretKey: [UInt8]) {
        var pk = [UInt8](repeating: 0, count: keyBytes)
        var sk = [UInt8](repeating: 0, count: keyBytes)
        let rc = seed.map { crypto_box_seed_keypair(&pk, &sk, $0) } ?? crypto_box_keypair(&pk, &sk)
        precondition(rc == 0)
        return (pk, sk)
    }

    /// `HMAC-SHA256(secret, "l2-qr-v1" ‖ phonePk ‖ extPk)`: proof the QR code was scanned (§5b).
    public func qrProof(secret: [UInt8], phonePk: [UInt8], extPk: [UInt8]) -> [UInt8] {
        precondition(secret.count == keyBytes, "QR secret must be 32 bytes")
        let input = Array("l2-qr-v1".utf8) + phonePk + extPk
        var out = [UInt8](repeating: 0, count: keyBytes)
        precondition(crypto_auth_hmacsha256(&out, input, UInt64(input.count), secret) == 0)
        return out
    }

    /// Random bytes from libsodium.
    public func random(_ count: Int) -> [UInt8] {
        var out = [UInt8](repeating: 0, count: count)
        randombytes_buf(&out, count)
        return out
    }
}

/// Overwrites `bytes` with zeros.
public func wipe(_ bytes: inout [UInt8]) {
    let count = bytes.count
    bytes.withUnsafeMutableBytes { sodium_memzero($0.baseAddress, count) }
}

/// Standard base64 with padding.
public func b64(_ bytes: [UInt8]) -> String { Data(bytes).base64EncodedString() }

/// Decodes standard base64; throws `L2Error.format` if malformed or not `length` bytes.
public func unb64(_ text: String, length: Int? = nil) throws -> [UInt8] {
    guard let data = Data(base64Encoded: text) else { throw L2Error.format("bad base64") }
    if let length, data.count != length { throw L2Error.format("expected \(length) bytes") }
    return Array(data)
}

/// Decodes base64url without padding (the QR code's `k` and `s`); `nil` if malformed.
func unb64url(_ text: String) -> [UInt8]? {
    var s = text.replacingOccurrences(of: "-", with: "+").replacingOccurrences(of: "_", with: "/")
    guard !s.contains("=") else { return nil }
    s += String(repeating: "=", count: (4 - s.count % 4) % 4)
    return Data(base64Encoded: s).map(Array.init)
}
