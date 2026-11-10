import Foundation

/// Host rules from PROTOCOL.md §2.
public enum L2Hosts {
    /// Lowercased web hostnames from an item's URIs.
    ///
    /// shortcut: hosts with non-ASCII characters are skipped (no punycode conversion), so such an
    /// item can't be filled on a PC when sealed on iOS; add IDNA encoding if anyone needs it.
    public static func hostsFromUris(_ uris: [String?]) -> [String] {
        var seen = Set<String>()
        return uris.compactMap { uri -> String? in
            guard let uri = uri?.trimmingCharacters(in: .whitespaces), !uri.isEmpty else { return nil }
            let hasScheme = uri.range(of: "^[A-Za-z][A-Za-z0-9+.-]*://", options: .regularExpression) != nil
            guard let parts = URLComponents(string: hasScheme ? uri : "https://" + uri),
                  let scheme = parts.scheme?.lowercased(), scheme == "http" || scheme == "https",
                  let host = parts.host?.lowercased(), !host.isEmpty,
                  host.unicodeScalars.allSatisfy(\.isASCII)
            else { return nil }
            return seen.insert(host).inserted ? host : nil
        }
    }

    /// True when `origin` may receive a secret allowed on `hosts`.
    public static func originAllowed(_ origin: String, hosts: [String]) -> Bool {
        guard let parts = URLComponents(string: origin),
              let host = parts.host?.lowercased(), !host.isEmpty,
              let scheme = parts.scheme?.lowercased()
        else { return false }
        let local = host == "localhost" || host == "127.0.0.1"
        guard scheme == "https" || (scheme == "http" && local) else { return false }
        return hosts.contains { raw in
            let x = raw.lowercased()
            return !x.isEmpty && (host == x || host.hasSuffix("." + x))
        }
    }

    /// The host of an origin, for display.
    public static func host(of origin: String) -> String {
        URLComponents(string: origin)?.host ?? origin
    }
}
