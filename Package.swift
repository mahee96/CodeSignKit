// swift-tools-version:5.9

import PackageDescription

let package = Package(
    name: "CodeSignKit",
    platforms: [
        .iOS(.v14),
        .macOS(.v11)
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
    dependencies: [],
    targets: [
        .binaryTarget(
            name: "OpenSSL",
            url: "https://github.com/krzyzanowskim/OpenSSL/releases/download/3.6.2000/OpenSSL.xcframework.zip",
            checksum: "37846a8bd302cb2443eff47f1045ab844d0cd40bf82cc6159cfad9aa5c3eff9e"
        ),
        .target(
            name: "CodeSignKit",
            dependencies: [
                .target(name: "OpenSSL")
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
                "CodeSignKit"
            ],
            path: "Tests"
        )
    ]
)


