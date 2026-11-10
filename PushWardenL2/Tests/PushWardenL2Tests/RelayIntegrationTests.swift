import Foundation
import Testing
@testable import PushWardenL2

/// Talks to a real relay: `PW_RELAY_URL=http://localhost:8080 swift test`. The WebSocket part
/// needs a libcurl with WebSocket support on Linux (Ubuntu 24.04's lacks it); run it on macOS.
struct RelayIntegrationTests {
    static let relayUrl = ProcessInfo.processInfo.environment["PW_RELAY_URL"]

    @Test(.enabled(if: relayUrl != nil)) func registersOverHttp() async throws {
        let reg = try await L2URLSessionRelay().register(relayUrl: try #require(Self.relayUrl), publicKey: b64(L2Crypto().boxKeyPair().publicKey), pushToken: "push-test")
        #expect(reg.id.range(of: "^[0-9a-z]{4}-[0-9a-z]{4}$", options: .regularExpression) != nil)
        #expect(try unb64(reg.token).count == 32)
        try await L2URLSessionRelay().setPushToken(relayUrl: try #require(Self.relayUrl), token: reg.token, pushToken: "push-test-2")
    }

    @Test(.enabled(if: relayUrl != nil), .timeLimit(.minutes(1))) func twoDevicesExchangeSealedMessage() async throws {
        let url = try #require(Self.relayUrl)
        let crypto = L2Crypto()
        let a = crypto.boxKeyPair()
        let b = crypto.boxKeyPair()
        let relayA = L2URLSessionRelay()
        let relayB = L2URLSessionRelay()
        let regA = try await relayA.register(relayUrl: url, publicKey: b64(a.publicKey), pushToken: nil)
        let regB = try await relayB.register(relayUrl: url, publicKey: b64(b.publicKey), pushToken: nil)

        let (stream, cont) = AsyncStream.makeStream(of: String.self)
        relayA.connect(relayUrl: url, token: regA.token, onMessage: { _ in }, onState: { cont.yield($0 ? "a-ready" : "a-closed") })
        relayB.connect(relayUrl: url, token: regB.token, onMessage: { m in
            cont.yield((try? crypto.open(m.body, senderPk: unb64(m.fromPk), recipientSk: b.secretKey)) ?? "bad")
        }, onState: { cont.yield($0 ? "b-ready" : "b-closed") })
        defer {
            relayA.disconnect()
            relayB.disconnect()
        }

        var events = stream.makeAsyncIterator()
        var ready = Set<String>()
        while ready.count < 2, let e = await events.next() {
            try #require(e.hasSuffix("-ready"), "socket closed before ready")
            ready.insert(e)
        }
        #expect(relayA.send(to: regB.id, body: crypto.seal(#"{"v":1,"type":"unpair"}"#, recipientPk: b.publicKey, senderSk: a.secretKey)))
        #expect(await events.next() == #"{"v":1,"type":"unpair"}"#)
    }
}
