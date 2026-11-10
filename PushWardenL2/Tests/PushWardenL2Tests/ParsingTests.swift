import Foundation
import Testing
@testable import PushWardenL2

struct ParsingTests {
    private let k = String(repeating: "A", count: 43) // 32 zero bytes, base64url without padding

    @Test func qrPairParsesValidUri() throws {
        let uri = "pushwarden://pair?v=1&r=https%3A%2F%2Frelay.example%2Fx&e=ab12-cd34&k=\(k)&s=\(k)&n=Chrome%20on%20Windows"
        let qr = try #require(L2QrPair.parse(uri))
        #expect(qr.relayUrl == "https://relay.example/x")
        #expect(qr.extId == "ab12-cd34")
        #expect(qr.extPublicKey == [UInt8](repeating: 0, count: 32))
        #expect(qr.pcName == "Chrome on Windows")
    }

    @Test func qrPairRejectsBadInput() {
        let good = "pushwarden://pair?v=1&r=https%3A%2F%2Frelay.example&e=ab12-cd34&k=\(k)&s=\(k)"
        #expect(L2QrPair.parse(good)?.pcName == "PC")
        for bad in [
            good.replacingOccurrences(of: "v=1", with: "v=2"),
            good.replacingOccurrences(of: "https%3A", with: "http%3A"),
            good.replacingOccurrences(of: "ab12-cd34", with: "AB12-CD34"),
            good.replacingOccurrences(of: "k=\(k)", with: "k=AAAA"),
            good.replacingOccurrences(of: "pushwarden://pair", with: "pushwarden://other"),
            "otpauth://totp/x?secret=ABC",
        ] {
            #expect(L2QrPair.parse(bad) == nil, "\(bad)")
        }
        #expect(L2QrPair.parse(good.replacingOccurrences(of: "https%3A%2F%2Frelay.example", with: "http%3A%2F%2Flocalhost%3A8080")) != nil)
    }

    @Test func messageParsingValidatesFields() throws {
        let rid = "MDAwMDAwMDAwMDAwMDAwMA=="
        let ok = #"{"v":1,"type":"fillRequest","requestId":"\#(rid)","itemId":"x","origin":"https://a.com","time":1}"#
        #expect(try L2PcMessage.parse(ok) == .fillRequest(requestId: rid, itemId: "x", origin: "https://a.com", time: 1))
        #expect(try L2PcMessage.parse(#"{"v":1,"type":"unpair"}"#) == .unpair)
        #expect(try L2PcMessage.parse(#"{"v":1,"type":"pairRequest","name":"x","commit":"y"}"#) == nil)
        #expect(throws: L2Error.self) { try L2PcMessage.parse(#"{"v":2,"type":"unpair"}"#) }
        #expect(throws: L2Error.self) { try L2PcMessage.parse(ok.replacingOccurrences(of: rid, with: "AAAA")) }
        let longOrigin = "https://" + String(repeating: "a", count: 2048)
        #expect(throws: L2Error.self) { try L2PcMessage.parse(ok.replacingOccurrences(of: "https://a.com", with: longOrigin)) }
        #expect(throws: L2Error.self) { try L2PcMessage.parse("not json") }
    }

    @Test func repliesCarrySecretsOnlyWhenApproved() {
        #expect(L2PcReplies.fillResult(requestId: "r", status: .denied, password: "p") == #"{"v":1,"type":"fillResult","requestId":"r","status":"denied"}"#)
        #expect(L2PcReplies.fillResult(requestId: "r", status: .approved, password: "p\"", totp: "123456")
            == #"{"v":1,"type":"fillResult","requestId":"r","status":"approved","password":"p\"","totp":"123456"}"#)
        #expect(L2PcReplies.qrPair(proofB64: "x", name: String(repeating: "é", count: 70)).contains(String(repeating: "é", count: 64) + "\""))
    }

    @Test func jsonEscapingMatchesJsonStringify() {
        #expect(L2JSON.quote("a\"b\\c\n\u{01}/é😀") == #""a\"b\\c\n\u0001/é😀""#)
    }

    @Test func hostsFromUris() {
        #expect(L2Hosts.hostsFromUris([
            "https://GitHub.com/login", "github.com", "http://localhost:3000", "androidapp://com.x", nil, "",
            "https://accounts.example.org:8443/x",
        ]) == ["github.com", "localhost", "accounts.example.org"])
    }

    @Test func relayBaseUrl() {
        #expect(L2RelayURL.base("https://Relay.example:8443/some/path") == "https://relay.example:8443/")
        #expect(L2RelayURL.base("http://localhost:8080") == "http://localhost:8080/")
        #expect(L2RelayURL.base("http://relay.example") == nil)
    }
}
