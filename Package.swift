// swift-tools-version:5.1
// The swift-tools-version declares the minimum version of Swift required to build this package.

import PackageDescription

let package = Package(
  name: "SwiftNoise",
  products: [
    .library(name: "SwiftNoise", targets: ["SwiftNoise"]),
  ],
  dependencies: [
    // Dependencies declare other packages that this package depends on.
    .package(url: "https://github.com/krzyzanowskim/CryptoSwift.git", from: "1.3.0"),
    .package(url: "https://github.com/christophhagen/CryptoKit25519", from: "0.4.0")
  ],
  targets: [
    // Targets are the basic building blocks of a package. A target can define a module or a test suite.
    // Targets can depend on other targets in this package, and on products in packages which this package depends on.
    .target(
      name: "SwiftNoise",
      dependencies: [
        "CryptoSwift",
        "CryptoKit25519"
      ]),
    .testTarget(
      name: "SwiftNoiseTests",
      dependencies: [
        "SwiftNoise"
      ]),
  ]
)
