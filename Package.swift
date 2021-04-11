// swift-tools-version:5.3
// The swift-tools-version declares the minimum version of Swift required to build this package.

import PackageDescription

let package = Package(
  name: "SwiftNoise",
  platforms: [
    .macOS(.v10_15),
    .iOS(.v13),
    .watchOS(.v6),
    .tvOS(.v13),
  ],
  products: [
    .library(name: "SwiftNoise", targets: ["SwiftNoise"])
  ],
  dependencies: [
    // Dependencies declare other packages that this package depends on.
    .package(url: "https://github.com/apple/swift-crypto.git", from: "1.0.0"),
  ],
  targets: [
    // Targets are the basic building blocks of a package. A target can define a module or a test suite.
    // Targets can depend on other targets in this package, and on products in packages which this package depends on.
    .target(
      name: "SwiftNoise",
      dependencies: [
        .product(name: "Crypto", package: "swift-crypto")
      ]),
    .testTarget(
      name: "SwiftNoiseTests",
      dependencies: ["SwiftNoise"],
      resources: [
        .copy("SnowTestVectors.json")
      ]
    )
  ]
)
