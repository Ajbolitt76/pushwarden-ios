// swift-tools-version: 5.9
import PackageDescription

// Platform-independent PushWarden L2 code (PROTOCOL.md): builds and tests on Linux too.
let package = Package(
    name: "PushWardenL2",
    platforms: [.iOS(.v15), .macOS(.v13)],
    products: [
        .library(name: "PushWardenL2", targets: ["PushWardenL2"]),
    ],
    dependencies: [
        .package(url: "https://github.com/jedisct1/swift-sodium.git", exact: "0.11.0"),
    ],
    targets: [
        .target(
            name: "PushWardenL2",
            dependencies: [.product(name: "Clibsodium", package: "swift-sodium")]
        ),
        .testTarget(
            name: "PushWardenL2Tests",
            dependencies: ["PushWardenL2"],
            resources: [.copy("v1.json")]
        ),
    ]
)
