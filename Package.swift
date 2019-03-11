// swift-tools-version:4.2

import PackageDescription

let package = Package(
    name: "SwiftPaillier",
    products: [
        .library(
            name: "SwiftPaillier",
            targets: ["SwiftPaillier"])
    ],
    dependencies: [
        .package(url: "https://github.com/attaswift/BigInt.git", from: "3.1.0"),
        .package(url: "https://github.com/code28/BignumGMP.git", from: "1.1.0")
    ],
    targets: [
        .target(
            name: "SwiftPaillier",
            dependencies: ["BigInt", "Bignum"]),
        .testTarget(
            name: "SwiftPaillierTests",
            dependencies: ["SwiftPaillier"])
    ]
)
