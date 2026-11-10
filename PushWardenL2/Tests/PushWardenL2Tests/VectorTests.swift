import Foundation
import Testing
@testable import PushWardenL2

/// The shared vectors in `protocol/vectors/v1.json` (copied here by `scripts/sync-to-ios.sh`).
struct Vectors: Decodable {
    struct KeyItem: Decodable {
        let password: String
        let ops: Int
        let memMiB: Int
        let saltHex: String
        let nonceHex: String
        let keyHex: String
        let fieldValue: String
    }

    struct Field: Decodable {
        let keyHex: String
        let field: String
        let itemId: String
        let username: String
        let hosts: [String]
        let secret: String
        let nonceHex: String
        let value: String
    }

    struct Box: Decodable {
        struct Message: Decodable, Equatable {
            let v: Int
            let type: String
            let requestId: String
            let itemId: String
            let origin: String
            let time: Int64
        }

        let senderSeedHex: String
        let recipientSeedHex: String
        let senderPkHex: String
        let recipientPkHex: String
        let nonceHex: String
        let message: Message
        let body: String
    }

    struct Pairing: Decodable {
        let phonePkHex: String
        let extPkHex: String
        let qrSecretHex: String
        let qrProofHex: String
    }

    struct HostMatch: Decodable {
        let origin: String
        let hosts: [String]
        let allowed: Bool
    }

    let keyItem: KeyItem
    let fields: [Field]
    let box: Box
    let pairing: Pairing
    let hostMatch: [HostMatch]

    static let shared: Vectors = {
        let url = Bundle.module.url(forResource: "v1", withExtension: "json")!
        return try! JSONDecoder().decode(Vectors.self, from: Data(contentsOf: url))
    }()
}

func hex(_ s: String) -> [UInt8] {
    var out = [UInt8]()
    var i = s.startIndex
    while i < s.endIndex {
        let j = s.index(i, offsetBy: 2)
        out.append(UInt8(s[i ..< j], radix: 16)!)
        i = j
    }
    return out
}

func toHex(_ b: [UInt8]) -> String { b.map { String(format: "%02x", $0) }.joined() }

struct VectorTests {
    let crypto = L2Crypto()
    let v = Vectors.shared

    @Test func keyItemWrapMatchesVector() throws {
        let k = v.keyItem
        let value = try crypto.wrapKey(
            hex(k.keyHex),
            password: k.password,
            params: L2KdfParams(ops: k.ops, memMiB: k.memMiB),
            salt: hex(k.saltHex),
            nonce: hex(k.nonceHex),
        )
        #expect(value == k.fieldValue)
        #expect(try crypto.unwrapKey(k.fieldValue, password: k.password) == hex(k.keyHex))
    }

    @Test func keyItemWrongPasswordAndBounds() {
        #expect(throws: L2Error.wrongPassword) { try crypto.unwrapKey(v.keyItem.fieldValue, password: "nope") }
        let cheap = v.keyItem.fieldValue.replacingOccurrences(of: #""ops":3"#, with: #""ops":1"#)
        #expect(throws: L2Error.self) { try crypto.unwrapKey(cheap, password: v.keyItem.password) }
        #expect(throws: L2Error.self) { try crypto.unwrapKey("{}", password: "x") }
    }

    @Test func fieldsMatchVectors() throws {
        for f in v.fields {
            let field = try #require(L2Field(rawValue: f.field))
            let binding = L2Binding(itemId: f.itemId, username: f.username, hosts: f.hosts)
            let value = crypto.encryptField(key: hex(f.keyHex), field: field, binding: binding, secret: f.secret, nonce: hex(f.nonceHex))
            #expect(value == f.value)
            let plain = try crypto.decryptField(key: hex(f.keyHex), field: field, itemId: f.itemId, value: f.value)
            #expect(plain == L2Plain(secret: f.secret, username: f.username, hosts: f.hosts))
        }
    }

    @Test func fieldChecksItemAndFieldBinding() throws {
        let f = v.fields[0]
        #expect(throws: L2Error.self) {
            try crypto.decryptField(key: hex(f.keyHex), field: .password, itemId: "another-item", value: f.value)
        }
        #expect(throws: L2Error.self) {
            try crypto.decryptField(key: hex(f.keyHex), field: .totp, itemId: f.itemId, value: f.value)
        }
        #expect(throws: L2Error.self) {
            try crypto.decryptField(key: hex(f.keyHex), field: .password, itemId: f.itemId, value: f.value + "A")
        }
    }

    @Test func boxMatchesVector() throws {
        let b = v.box
        let sender = crypto.boxKeyPair(seed: hex(b.senderSeedHex))
        let recipient = crypto.boxKeyPair(seed: hex(b.recipientSeedHex))
        #expect(toHex(sender.publicKey) == b.senderPkHex)
        #expect(toHex(recipient.publicKey) == b.recipientPkHex)
        let m = b.message
        let json = L2JSON.object([
            ("v", .int(1)), ("type", .string(m.type)), ("requestId", .string(m.requestId)),
            ("itemId", .string(m.itemId)), ("origin", .string(m.origin)), ("time", .int(m.time)),
        ])
        #expect(crypto.seal(json, recipientPk: recipient.publicKey, senderSk: sender.secretKey, nonce: hex(b.nonceHex)) == b.body)
        let opened = try crypto.open(b.body, senderPk: sender.publicKey, recipientSk: recipient.secretKey)
        #expect(try L2PcMessage.parse(opened) == .fillRequest(requestId: m.requestId, itemId: m.itemId, origin: m.origin, time: m.time))
        #expect(throws: L2Error.self) { try crypto.open(b.body, senderPk: recipient.publicKey, recipientSk: recipient.secretKey) }
    }

    @Test func qrProofMatchesVector() {
        let p = v.pairing
        #expect(toHex(crypto.qrProof(secret: hex(p.qrSecretHex), phonePk: hex(p.phonePkHex), extPk: hex(p.extPkHex))) == p.qrProofHex)
    }

    @Test func hostMatchVectors() {
        for h in v.hostMatch {
            #expect(L2Hosts.originAllowed(h.origin, hosts: h.hosts) == h.allowed, "\(h.origin)")
        }
    }
}
