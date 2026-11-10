/// Writes JSON with a fixed key order and `JSON.stringify` escaping, because the shared vectors
/// depend on the exact bytes (PROTOCOL.md §2) and `JSONEncoder` guarantees neither.
enum L2JSON {
    enum Value {
        case string(String)
        case int(Int64)
        case strings([String])
    }

    static func object(_ pairs: [(String, Value)]) -> String {
        "{" + pairs.map { key, value in quote(key) + ":" + encode(value) }.joined(separator: ",") + "}"
    }

    private static func encode(_ value: Value) -> String {
        switch value {
        case let .string(s): quote(s)
        case let .int(n): String(n)
        case let .strings(a): "[" + a.map(quote).joined(separator: ",") + "]"
        }
    }

    static func quote(_ s: String) -> String {
        var out = "\""
        for scalar in s.unicodeScalars {
            switch scalar {
            case "\"": out += "\\\""
            case "\\": out += "\\\\"
            case "\u{08}": out += "\\b"
            case "\u{0C}": out += "\\f"
            case "\n": out += "\\n"
            case "\r": out += "\\r"
            case "\t": out += "\\t"
            case _ where scalar.value < 0x20:
                let hex = String(scalar.value, radix: 16)
                out += "\\u" + String(repeating: "0", count: 4 - hex.count) + hex
            default: out.unicodeScalars.append(scalar)
            }
        }
        return out + "\""
    }
}
