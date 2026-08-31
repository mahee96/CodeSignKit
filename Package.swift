// swift-tools-version:5.9

import PackageDescription

#if canImport(Darwin)
let openSSLBinaryTargets: [Target] = [
    .binaryTarget(
        name: "OpenSSL",
        url: "https://github.com/krzyzanowskim/OpenSSL/releases/download/3.6.2000/OpenSSL.xcframework.zip",
        checksum: "37846a8bd302cb2443eff47f1045ab844d0cd40bf82cc6159cfad9aa5c3eff9e"
    )
]
let openSSLTestDependencies: [Target.Dependency] = [
    .target(name: "OpenSSL")
]
#else
let openSSLBinaryTargets: [Target] = []
let openSSLTestDependencies: [Target.Dependency] = []
#endif

let package = Package(
    name: "CodeSignKit",
    platforms: [
        .iOS(.v14),
        .macOS(.v11),
        .tvOS(.v14),
        .watchOS(.v7),
        .visionOS(.v1)
    ],
    products: [
        .library(
            name: "CodeSignKit",
            targets: ["CodeSignKit"]
        ),
        .executable(
            name: "codesigntoolkit",
            targets: ["codesigntoolkit"]
        )
    ],
    dependencies: [
        .package(url: "https://github.com/apple/swift-crypto.git", exact: "4.3.1"),
        .package(url: "https://github.com/apple/swift-asn1.git",   exact: "1.6.0")
    ],
    targets: [
        .target(
            name: "CodeSignKit",
            dependencies: [
                .product(name: "Crypto",        package: "swift-crypto"),
                .product(name: "CryptoExtras",  package: "swift-crypto"),
                .product(name: "SwiftASN1",     package: "swift-asn1")
            ],
            path: "Sources"
        ),
        .executableTarget(
            name: "codesigntoolkit",
            dependencies: [
                "CodeSignKit"
            ],
            path: "CLI"
        ),
        .testTarget(
            name: "CodeSignKitTests",
            dependencies: [
                "CodeSignKit",
                .product(name: "Crypto",        package: "swift-crypto"),
                .product(name: "CryptoExtras",  package: "swift-crypto"),
                .product(name: "SwiftASN1",     package: "swift-asn1")
            ] + openSSLTestDependencies,
            path: "Tests"
        )
    ] + openSSLBinaryTargets
)
