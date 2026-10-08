// swift-tools-version: 5.7.0
// The swift-tools-version declares the minimum version of Swift required to build this package.

import PackageDescription

let package = Package(
    name: "VCIClient",
    platforms: [
        .iOS(.v14),
    ],
    products: [
        .library(
            name: "VCIClient",
            targets: ["VCIClient"]),
    ],
    dependencies: [
        .package(url: "https://github.com/valpackett/SwiftCBOR", .upToNextMajor(from: "0.5.0")),
        .package(url: "https://github.com/inji/inji-openid4vp-ios-swift", branch: "develop"),
        .package(url: "https://github.com/beatt83/jose-swift.git", "4.0.2" ..< "4.0.3")
    ],
    targets: [
        .target(
            name: "VCIClient",
            dependencies: [
                "SwiftCBOR",
                .product(name: "OpenID4VP", package: "inji-openid4vp-ios-swift"),
                .product(name: "jose-swift", package: "jose-swift"),
                "OpenID4VPBridge"
            ]
        ),
        .testTarget(
            name: "VCIClientTests",
            dependencies: [
                "VCIClient",
                "SwiftCBOR",
                .product(name: "OpenID4VP", package: "inji-openid4vp-ios-swift"),
                .product(name: "jose-swift", package: "jose-swift")
            ]
        ),
        .target(
                name: "OpenID4VPBridge",
                dependencies: [
                    .product(name: "OpenID4VP", package: "inji-openid4vp-ios-swift")
                ]
            )
    ]
)
