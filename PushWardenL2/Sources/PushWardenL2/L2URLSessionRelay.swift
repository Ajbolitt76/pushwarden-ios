import Foundation
#if canImport(FoundationNetworking)
import FoundationNetworking
#endif

private let pingInterval: UInt64 = 20_000_000_000

/// `L2RelayTransport` over `URLSession`: HTTPS for registration, one WebSocket for messages.
public final class L2URLSessionRelay: L2RelayTransport, @unchecked Sendable {
    private let session: URLSession
    private let lock = NSLock()
    private var task: URLSessionWebSocketTask?
    private var pinger: Task<Void, Never>?

    public init(session: URLSession = .shared) {
        self.session = session
    }

    public func register(relayUrl: String, publicKey: String, pushToken: String?) async throws -> (id: String, token: String) {
        guard let base = L2RelayURL.base(relayUrl), let url = URL(string: base + "v1/devices") else {
            throw L2Error.format("relay URL must use https")
        }
        var request = URLRequest(url: url)
        request.httpMethod = "POST"
        request.setValue("application/json", forHTTPHeaderField: "Content-Type")
        var body: [(String, L2JSON.Value)] = [("publicKey", .string(publicKey)), ("kind", .string("phone"))]
        if let pushToken { body.append(("pushToken", .string(pushToken))) }
        request.httpBody = Data(L2JSON.object(body).utf8)
        let (data, response) = try await session.data(for: request)
        guard (response as? HTTPURLResponse)?.statusCode == 201 else {
            throw L2Error.format("relay registration failed: \((response as? HTTPURLResponse)?.statusCode ?? 0)")
        }
        struct Registered: Decodable { let id: String; let token: String }
        let r = try JSONDecoder().decode(Registered.self, from: data)
        return (r.id, r.token)
    }

    public func setPushToken(relayUrl: String, token: String, pushToken: String) async throws {
        guard let base = L2RelayURL.base(relayUrl), let url = URL(string: base + "v1/devices/me") else {
            throw L2Error.format("relay URL must use https")
        }
        var request = URLRequest(url: url)
        request.httpMethod = "PUT"
        request.setValue("application/json", forHTTPHeaderField: "Content-Type")
        request.setValue("Bearer \(token)", forHTTPHeaderField: "Authorization")
        request.httpBody = Data(L2JSON.object([("pushToken", .string(pushToken))]).utf8)
        let (_, response) = try await session.data(for: request)
        guard (response as? HTTPURLResponse)?.statusCode == 204 else {
            throw L2Error.format("relay rejected the push token: \((response as? HTTPURLResponse)?.statusCode ?? 0)")
        }
    }

    public func connect(
        relayUrl: String,
        token: String,
        onMessage: @escaping @Sendable (RelayMessage) -> Void,
        onState: @escaping @Sendable (Bool) -> Void
    ) {
        disconnect()
        guard let base = L2RelayURL.base(relayUrl),
              let url = URL(string: base.replacingOccurrences(of: "^http", with: "ws", options: .regularExpression) + "v1/ws")
        else {
            onState(false)
            return
        }
        let task = session.webSocketTask(with: url)
        let pinger = Task { [weak task] in
            // App-level pings: they keep the relay connection busy (PROTOCOL.md §3).
            while !Task.isCancelled {
                try? await Task.sleep(nanoseconds: pingInterval)
                guard !Task.isCancelled, let task else { return }
                try? await task.send(.string(#"{"t":"ping"}"#))
            }
        }
        lock.lock()
        self.task = task
        self.pinger = pinger
        lock.unlock()
        task.resume()
        task.send(.string(L2JSON.object([("t", .string("auth")), ("token", .string(token))]))) { error in
            if error != nil { onState(false) }
        }
        receive(task, onMessage: onMessage, onState: onState)
    }

    private func receive(
        _ task: URLSessionWebSocketTask,
        onMessage: @escaping @Sendable (RelayMessage) -> Void,
        onState: @escaping @Sendable (Bool) -> Void
    ) {
        task.receive { [weak self] result in
            switch result {
            case let .failure(error):
                _ = error
                onState(false)
            case let .success(message):
                if case let .string(text) = message { Self.dispatch(text, onMessage: onMessage, onState: onState) }
                self?.receive(task, onMessage: onMessage, onState: onState)
            }
        }
    }

    private struct Frame: Decodable {
        let t: String?
        let from: String?
        let fromPk: String?
        let body: String?
    }

    private static func dispatch(
        _ text: String,
        onMessage: (RelayMessage) -> Void,
        onState: (Bool) -> Void
    ) {
        guard let frame = try? JSONDecoder().decode(Frame.self, from: Data(text.utf8)) else { return }
        switch frame.t {
        case "ready":
            onState(true)
        case "msg":
            if let from = frame.from, let fromPk = frame.fromPk, let body = frame.body {
                onMessage(RelayMessage(from: from, fromPk: fromPk, body: body))
            }
        default:
            break
        }
    }

    @discardableResult
    public func send(to: String, body: String) -> Bool {
        lock.lock()
        let task = task
        lock.unlock()
        guard let task else { return false }
        let frame = L2JSON.object([("t", .string("send")), ("to", .string(to)), ("body", .string(body))])
        task.send(.string(frame)) { _ in }
        return true
    }

    public func disconnect() {
        lock.lock()
        let task = task
        let pinger = pinger
        self.task = nil
        self.pinger = nil
        lock.unlock()
        pinger?.cancel()
        task?.cancel(with: .normalClosure, reason: nil)
    }
}
