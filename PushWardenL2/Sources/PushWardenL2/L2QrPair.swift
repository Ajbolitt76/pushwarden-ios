import Foundation

private let keyBytes = 32
private let pcNameMax = 64

/// What the extension's pairing QR code carries (PROTOCOL.md §5b).
public struct L2QrPair: Equatable, Sendable {
    public let relayUrl: String
    public let extId: String
    public let extPublicKey: [UInt8]
    public let secret: [UInt8]
    public let pcName: String

    /// Parses `pushwarden://pair?...`; `nil` for anything else or malformed values.
    public static func parse(_ text: String) -> L2QrPair? {
        guard let parts = URLComponents(string: text.trimmingCharacters(in: .whitespacesAndNewlines)),
              parts.scheme == "pushwarden", parts.host == "pair"
        else { return nil }
        var q = [String: String]()
        for item in parts.queryItems ?? [] where q[item.name] == nil {
            q[item.name] = item.value
        }
        guard q["v"] == "1",
              let relay = q["r"], L2RelayURL.base(relay) != nil,
              let extId = q["e"], extId.range(of: "^[0-9a-z]{4}-[0-9a-z]{4}$", options: .regularExpression) != nil,
              let pk = q["k"].flatMap(unb64url), pk.count == keyBytes,
              let secret = q["s"].flatMap(unb64url), secret.count == keyBytes
        else { return nil }
        let name = truncateUTF16((q["n"] ?? "").trimmingCharacters(in: .whitespaces), pcNameMax)
        return L2QrPair(relayUrl: relay, extId: extId, extPublicKey: pk, secret: secret, pcName: name.isEmpty ? "PC" : name)
    }
}

/// Relay URL rules: https, or http only for localhost.
public enum L2RelayURL {
    /// `https://relay.example/` with path stripped; `nil` if not allowed.
    public static func base(_ input: String) -> String? {
        guard let parts = URLComponents(string: input.trimmingCharacters(in: .whitespaces)),
              let scheme = parts.scheme?.lowercased(),
              let host = parts.host?.lowercased(), !host.isEmpty
        else { return nil }
        let local = host == "localhost" || host == "127.0.0.1"
        guard scheme == "https" || (scheme == "http" && local) else { return nil }
        return "\(scheme)://\(host)\(parts.port.map { ":\($0)" } ?? "")/"
    }
}
