import Foundation

private let requestIdBytes = 16
private let itemIdMax = 64
private let originMax = 2048
private let nameMax = 64

/// The end-to-end messages the phone handles (PROTOCOL.md §4), parsed and validated.
///
/// shortcut: the iOS phone only pairs by QR code (§5b), so `pairRequest`/`pairReveal` (manual
/// pairing, §5) are ignored; port them from Android's `L2PcAutofillManager` if needed.
public enum L2PcMessage: Equatable {
    /// Extension asks to fill an item.
    case fillRequest(requestId: String, itemId: String, origin: String, time: Int64)
    /// Either side ends the pairing.
    case unpair

    private struct Raw: Decodable {
        let v: Int?
        let type: String?
        let requestId: String?
        let itemId: String?
        let origin: String?
        let time: Int64?
    }

    /// Parses `text`; `nil` for types the phone ignores. Throws on malformed input.
    public static func parse(_ text: String) throws -> L2PcMessage? {
        let raw: Raw
        do {
            raw = try JSONDecoder().decode(Raw.self, from: Data(text.utf8))
        } catch {
            throw L2Error.format("bad message JSON")
        }
        guard raw.v == 1 else { throw L2Error.format("unsupported message version") }
        switch raw.type {
        case "fillRequest":
            guard let requestId = raw.requestId,
                  let itemId = raw.itemId, itemId.utf16.count <= itemIdMax,
                  let origin = raw.origin, origin.utf16.count <= originMax,
                  let time = raw.time
            else { throw L2Error.format("bad fillRequest") }
            _ = try unb64(requestId, length: requestIdBytes)
            return .fillRequest(requestId: requestId, itemId: itemId, origin: origin, time: time)
        case "unpair":
            return .unpair
        default:
            return nil
        }
    }
}

/// JSON for the messages the phone sends (PROTOCOL.md §4).
public enum L2PcReplies {
    /// Status of a `fillResult`.
    public enum Status: String {
        case approved, denied, expired, rejected, error
    }

    /// `unpair`.
    public static func unpair() -> String { msg("unpair", []) }

    /// `qrPair`: proves this phone scanned the PC's QR code (PROTOCOL.md §5b).
    public static func qrPair(proofB64: String, name: String) -> String {
        msg("qrPair", [("proof", .string(proofB64)), ("name", .string(truncateUTF16(name, nameMax)))])
    }

    /// `fillResult`; secrets only with `approved`.
    public static func fillResult(
        requestId: String,
        status: Status,
        password: String? = nil,
        totp: String? = nil
    ) -> String {
        var fields: [(String, L2JSON.Value)] = [("requestId", .string(requestId)), ("status", .string(status.rawValue))]
        if status == .approved {
            if let password { fields.append(("password", .string(password))) }
            if let totp { fields.append(("totp", .string(totp))) }
        }
        return msg("fillResult", fields)
    }

    private static func msg(_ type: String, _ fields: [(String, L2JSON.Value)]) -> String {
        L2JSON.object([("v", .int(1)), ("type", .string(type))] + fields)
    }
}

/// `s` cut to at most `max` UTF-16 code units, never splitting a character.
func truncateUTF16(_ s: String, _ max: Int) -> String {
    var out = ""
    for c in s {
        if out.utf16.count + c.utf16.count > max { break }
        out.append(c)
    }
    return out
}
