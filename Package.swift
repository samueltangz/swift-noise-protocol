// swift-tools-version:5.1
// The swift-tools-version declares the minimum version of Swift required to build this package.

import PackageDescription

let package = Package(
  name: "NoiseProtocol",
  dependencies: [
    // Dependencies declare other packages that this package depends on.
    .package(url: "https://github.com/krzyzanowskim/CryptoSwift.git", from: "1.3.0"),
    .package(url: "https://github.com/IBM-Swift/BlueECC.git", from: "1.2.5"),
    .package(url: "https://github.com/jedisct1/swift-sodium.git", from: "0.8.0")
  ],
  targets: [
    // Targets are the basic building blocks of a package. A target can define a module or a test suite.
    // Targets can depend on other targets in this package, and on products in packages which this package depends on.
    .target(
      name: "NoiseProtocol",
      dependencies: [
        "CryptoSwift",
        "CryptorECC",
        "Sodium"
      ]),
    .testTarget(
      name: "NoiseProtocolTests",
      dependencies: [
        "NoiseProtocol"
      ]),
  ]
)
