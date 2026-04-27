// swift-tools-version:5.10
import PackageDescription

let package = Package(
    name: "RLKit",
    platforms: [.iOS(.v16)],
    products: [
        .library(name: "RLKit", targets: ["RLKit"]),
    ],
    dependencies: [
        .package(url: "https://github.com/krzyzanowskim/CryptoSwift", from: "1.8.0"),
    ],
    targets: [
        .target(
            name: "RLKit",
            dependencies: []
        ),
        .testTarget(
            name: "RLKitTests",
            dependencies: ["RLKit", "CryptoSwift"],
            path: "Tests/RLKitTests"
        ),
    ]
)
