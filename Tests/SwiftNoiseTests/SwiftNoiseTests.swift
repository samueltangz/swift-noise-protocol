import XCTest
import SwiftNoise

final class SwiftNoiseTests: XCTestCase {
  static var allTests = [
    ("testN", testN),
    ("testNRandomKeyPair", testNRandomKeyPair),
    ("testX", testX),
    ("testIK", testIK),
    ("testKK", testKK),
    ("testKN", testKN)
  ]

  // Noise_N_25519_AESGCM_SHA256
  // https://github.com/mcginty/snow/blob/master/tests/vectors/snow.txt#L106
  func testN() {
    let responderStaticKeyPair = constructKeyPair(secretKey: Data(hex: "2a1c15dc684bd84612e9b2d84f740c76789042390af00fd02f71ec14dd213231"))
    let initiatorEphemeralKeyPair = constructKeyPair(secretKey: Data(hex: "3b40bcbafac8be41b4e52af1caf6edb1cc6f9f48a1b9579e69a25d6bf66c10cd"))
    let responderEphemeralKeyPair = constructKeyPair(secretKey: Data(hex: "fa96ea6cb4e79f59412fb8fdbe6beac212939840f2f9f1afef0877eae5ff527c"))

    let prologue = Data(hex: "5468657265206973206e6f20726967687420616e642077726f6e672e2054686572652773206f6e6c792066756e20616e6420626f72696e672e")

    let initiatorState = try! HandshakeState(
      pattern: .N,
      initiator: true,
      prologue: prologue,
      e: initiatorEphemeralKeyPair,
      rs: responderStaticKeyPair.publicKey
    )
    let responderState = try! HandshakeState(
      pattern: .N,
      initiator: false,
      prologue: prologue,
      s: responderStaticKeyPair,
      e: responderEphemeralKeyPair
    )

    // -> e, es
    let payload0 = Data(hex: "0855d5bc3c0bec5270363f3ed1d3cdf28aabcf3da8c5a0871d2ada89f0661b30")
    let initiatorTx = try! initiatorState.writeMessage(payload: payload0)
    assert(try! responderState.readMessage(message: initiatorTx) == payload0)
    assert(responderState.remoteE! == initiatorEphemeralKeyPair.publicKey)

    let ciphertext0b = Data(hex: "aa83fbe6881be6f3b853d17e05f998df0e6ba0d370c5208e03b8f7c6c1fdc575d630e6f82b7736831479e0d3b6c2ab6bf9048d0dbc0377f147e223649d4fc95efb9774fbc577d249e2e2907d60154a57")

    assert(initiatorTx == ciphertext0b)

    let responderSplits = try! responderState.split()
    let initiatorSplits = try! initiatorState.split()

    let plaintext1 = Data("hello world".utf8)
    let ciphertext1 = initiatorSplits.0.encryptWithAd(ad: Data(), plaintext: plaintext1)
    assert(responderSplits.0.decryptWithAd(ad: Data(), ciphertext: ciphertext1) == plaintext1)

    let plaintext2 = Data("hello world, too".utf8)
    let ciphertext2 = responderSplits.1.encryptWithAd(ad: Data(), plaintext: plaintext2)
    assert(initiatorSplits.1.decryptWithAd(ad: Data(), ciphertext: ciphertext2) == plaintext2)
  }

  func testNRandomKeyPair() {
    let responderStaticKeyPair = generateKeyPair()
    let initiatorEphemeralKeyPair = generateKeyPair()
    let responderEphemeralKeyPair = generateKeyPair()

    let prologue = Data()

    let initiatorState = try! HandshakeState(
      pattern: .N,
      initiator: true,
      prologue: prologue,
      e: initiatorEphemeralKeyPair,
      rs: responderStaticKeyPair.publicKey
    )
    let responderState = try! HandshakeState(
      pattern: .N,
      initiator: false,
      prologue: prologue,
      s: responderStaticKeyPair,
      e: responderEphemeralKeyPair
    )

    // -> e, es
    let initiatorTx = try! initiatorState.writeMessage(payload: Data())
    assert(try! responderState.readMessage(message: initiatorTx) == Data())
    assert(responderState.remoteE! == initiatorEphemeralKeyPair.publicKey)

    let responderSplits = try! responderState.split()
    let initiatorSplits = try! initiatorState.split()

    let plaintext1 = Data("hello world".utf8)
    let ciphertext1 = initiatorSplits.0.encryptWithAd(ad: Data(), plaintext: plaintext1)
    assert(responderSplits.0.decryptWithAd(ad: Data(), ciphertext: ciphertext1) == plaintext1)

    let plaintext2 = Data("hello world, too".utf8)
    let ciphertext2 = responderSplits.1.encryptWithAd(ad: Data(), plaintext: plaintext2)
    assert(initiatorSplits.1.decryptWithAd(ad: Data(), ciphertext: ciphertext2) == plaintext2)
  }

  // Noise_X_25519_AESGCM_SHA256
  // https://github.com/mcginty/snow/blob/master/tests/vectors/snow.txt#L248
  func testX() {
    let initiatorStaticKeyPair = constructKeyPair(secretKey: Data(hex: "94e7f031803c6ed2acb0eb1528a93c7a1c446eef4b69af38443cf820e69d960e"))
    let responderStaticKeyPair = constructKeyPair(secretKey: Data(hex: "4b9d66860c39de31492bdb3b090527bf66ef1ea75f105bb6f87328dfbb9fe337"))
    let initiatorEphemeralKeyPair = constructKeyPair(secretKey: Data(hex: "f587d5ff11066818e6a685a05be677f0618837b40271ec058b1c1d9dcbe3346f"))
    let responderEphemeralKeyPair = constructKeyPair(secretKey: Data(hex: "c99e75600766e8ec8de995b4b00085c3b90387191b3c1568ca20867761fa65e8"))

    let prologue = Data(hex: "5468657265206973206e6f20726967687420616e642077726f6e672e2054686572652773206f6e6c792066756e20616e6420626f72696e672e")

    let initiatorState = try! HandshakeState(
      pattern: .X,
      initiator: true,
      prologue: prologue,
      s: initiatorStaticKeyPair,
      e: initiatorEphemeralKeyPair,
      rs: responderStaticKeyPair.publicKey
    )
    let responderState = try! HandshakeState(
      pattern: .X,
      initiator: false,
      prologue: prologue,
      s: responderStaticKeyPair,
      e: responderEphemeralKeyPair
    )

    // -> e, es, s, ss
    let payload0 = Data(hex: "81df37247729d0b3f5f712be3796b5f7cc4fa39dde314cd7e81fb5e574db63c0")
    let initiatorTx = try! initiatorState.writeMessage(payload: payload0)
    assert(try! responderState.readMessage(message: initiatorTx) == payload0)
    assert(responderState.remoteE! == initiatorEphemeralKeyPair.publicKey)

    let ciphertext0b = Data(hex: "6f8eaa3373069db1383b3ca7a697a54d4543e8c4ba086e4b4b6052147c40c87c95c86a7f909f2fa0141a00a6708349dd80fa5349c42257dc3581a6156a383cb8a13bcdc99a50fec8f458225bd799839b63482c4fa2167aae247fc49966712890c8d566e78fddc01f6ae2bfa6a096ec8fd788a02b5bfcfb8f6060c6cfb9647680")

    assert(initiatorTx == ciphertext0b)

    let responderSplits = try! responderState.split()
    let initiatorSplits = try! initiatorState.split()

    let plaintext1 = Data("hello world".utf8)
    let ciphertext1 = initiatorSplits.0.encryptWithAd(ad: Data(), plaintext: plaintext1)
    assert(responderSplits.0.decryptWithAd(ad: Data(), ciphertext: ciphertext1) == plaintext1)

    let plaintext2 = Data("hello world, too".utf8)
    let ciphertext2 = responderSplits.1.encryptWithAd(ad: Data(), plaintext: plaintext2)
    assert(initiatorSplits.1.decryptWithAd(ad: Data(), ciphertext: ciphertext2) == plaintext2)
  }

  // Noise_IK_25519_AESGCM_SHA256
  // https://github.com/mcginty/snow/blob/master/tests/vectors/snow.txt#L2336
  func testIK() {
    let initiatorStaticKeyPair = constructKeyPair(secretKey: Data(hex: "834923a2cbc86100d56854892049a7d6afbf2b2231b4450028cfc9b7a1993fb1"))
    let responderStaticKeyPair = constructKeyPair(secretKey: Data(hex: "067d24b814b15993f11a68b9270779889ef87b865a4f579bdf138f5a7d69b8d2"))
    let initiatorEphemeralKeyPair = constructKeyPair(secretKey: Data(hex: "9f77df6db1e5fa790cff942e5db226c71375988ab2cfb8193817c1a716f679ed"))
    let responderEphemeralKeyPair = constructKeyPair(secretKey: Data(hex: "68ca5c7901e604433e2ecd950576060c5b002f9fe2edc2eb1d46468601d995eb"))

    let prologue = Data(hex: "5468657265206973206e6f20726967687420616e642077726f6e672e2054686572652773206f6e6c792066756e20616e6420626f72696e672e")

    let initiatorState = try! HandshakeState(
      pattern: .IK,
      initiator: true,
      prologue: prologue,
      s: initiatorStaticKeyPair,
      e: initiatorEphemeralKeyPair,
      rs: responderStaticKeyPair.publicKey
    )
    let responderState = try! HandshakeState(
      pattern: .IK,
      initiator: false,
      prologue: prologue,
      s: responderStaticKeyPair,
      e: responderEphemeralKeyPair
    )

    // -> e, es, s, ss
    let payload0 = Data(hex: "41f6bee49109aa96c3c80d787445b08b96cd35d195bc19805688189516f02d7e")
    let initiatorTx = try! initiatorState.writeMessage(payload: payload0)
    assert(try! responderState.readMessage(message: initiatorTx) == payload0)
    assert(responderState.remoteE! == initiatorEphemeralKeyPair.publicKey)

    // <- e, ee, se
    let payload1 = Data(hex: "bb6c9b156337fece15f0efd89a0ec934e0d414522ed7561eb3a6b1a7b028de9f")
    let responderTx = try! responderState.writeMessage(payload: payload1)
    assert(try! initiatorState.readMessage(message: responderTx) == payload1)
    assert(initiatorState.remoteE! == responderEphemeralKeyPair.publicKey)

    let ciphertext0b = Data(hex: "72e3811d48022216bb2695f7dbd8cb9c0d9e954147ffe6fe96822d63bbcd3164a8d64f8886104f56ede0c7f35e5d13f27b0607a2693f9e2899b24fe0eae8101cbfcca90a9a50657429ade64223af6e2c660f2c00e512a5cbdbc0de0ce9c62ab0cbe98e348a61fd113c576a75aedf3ee5227be8327b2dccb343ad05523f961298")
    let ciphertext1b = Data(hex: "1b690be6976fc8d2e9c687be8ff298637f90f59ea34af404c53578fd3a73804668fc97497b2085820ce1f62a0d9a0a0378f9544ae492be9e7b9219603404cfcb85cccdce9f6d946b1ccce04cfaab9df1")

    assert(initiatorTx == ciphertext0b)
    assert(responderTx == ciphertext1b)

    let responderSplits = try! responderState.split()
    let initiatorSplits = try! initiatorState.split()

    let plaintext1 = Data("hello world".utf8)
    let ciphertext1 = initiatorSplits.0.encryptWithAd(ad: Data(), plaintext: plaintext1)
    assert(responderSplits.0.decryptWithAd(ad: Data(), ciphertext: ciphertext1) == plaintext1)

    let plaintext2 = Data("hello world, too".utf8)
    let ciphertext2 = responderSplits.1.encryptWithAd(ad: Data(), plaintext: plaintext2)
    assert(initiatorSplits.1.decryptWithAd(ad: Data(), ciphertext: ciphertext2) == plaintext2)
  }

  // Noise_KK_25519_AESGCM_SHA256
  // https://github.com/mcginty/snow/blob/master/tests/vectors/snow.txt#L1822
  func testKK() {
    let initiatorStaticKeyPair = constructKeyPair(secretKey: Data(hex: "faebb0194fee50fb819b7127c6f4a24dab85af4ac4ebb263eb1a44e8a7f60d41"))
    let responderStaticKeyPair = constructKeyPair(secretKey: Data(hex: "fae0883f3bcbb944236fbfeefaaa03427920d940b05c4cd1016070ce7c420c0a"))
    let initiatorEphemeralKeyPair = constructKeyPair(secretKey: Data(hex: "4747e3766bf863acda954fb093d1ed3d438019b9fc1f0dfcbe995d27ea14c825"))
    let responderEphemeralKeyPair = constructKeyPair(secretKey: Data(hex: "772bcda9330c8849a1763365a4faa47f6cf9c0ef8f6d170d41ddff6c0cfb1a37"))

    let prologue = Data(hex: "5468657265206973206e6f20726967687420616e642077726f6e672e2054686572652773206f6e6c792066756e20616e6420626f72696e672e")

    let initiatorState = try! HandshakeState(
      pattern: .KK,
      initiator: true,
      prologue: prologue,
      s: initiatorStaticKeyPair,
      e: initiatorEphemeralKeyPair,
      rs: responderStaticKeyPair.publicKey
    )
    let responderState = try! HandshakeState(
      pattern: .KK,
      initiator: false,
      prologue: prologue,
      s: responderStaticKeyPair,
      e: responderEphemeralKeyPair,
      rs: initiatorStaticKeyPair.publicKey
    )

    // -> e, es, ss
    let payload0 = Data(hex: "cb0ff664bfede40c881d02768dc417d6a210606ab2a959ae029d292171691551")
    let initiatorTx = try! initiatorState.writeMessage(payload: payload0)
    assert(try! responderState.readMessage(message: initiatorTx) == payload0)
    assert(responderState.remoteE! == initiatorEphemeralKeyPair.publicKey)

    // <- e, ee, se
    let payload1 = Data(hex: "e546bfd27b0c80b137af4ef3bcfb664c1e42edb732b65adb468ead8973a16d55")
    let responderTx = try! responderState.writeMessage(payload: payload1)
    assert(try! initiatorState.readMessage(message: responderTx) == payload1)
    assert(initiatorState.remoteE! == responderEphemeralKeyPair.publicKey)

    let ciphertext0b = Data(hex: "32ca8ed53e4a68e52ecda4d0160bd8c6d22e736b28cee8d151c2c52e37a3123ee45510fd8c5f8caa63d7394d9dfe97fd40b22ec4b7bf0ea360c9f58a22a06e7ee1af57389c2651ee93e82d38ca1be1fc")
    let ciphertext1b = Data(hex: "6571c26d443f64388cb42967e73d4b09d9f496586d87f2517ec73507b4bd54579bc86e337166ca0b985745a18ba002eb0ed778e1ce2e9389d1095f3e6a14dccae295a8edb489c6b9b91ffd72d8bbe94a")

    assert(initiatorTx == ciphertext0b)
    assert(responderTx == ciphertext1b)

    let responderSplits = try! responderState.split()
    let initiatorSplits = try! initiatorState.split()

    let plaintext1 = Data("hello world".utf8)
    let ciphertext1 = initiatorSplits.0.encryptWithAd(ad: Data(), plaintext: plaintext1)
    assert(responderSplits.0.decryptWithAd(ad: Data(), ciphertext: ciphertext1) == plaintext1)

    let plaintext2 = Data("hello world, too".utf8)
    let ciphertext2 = responderSplits.1.encryptWithAd(ad: Data(), plaintext: plaintext2)
    assert(initiatorSplits.1.decryptWithAd(ad: Data(), ciphertext: ciphertext2) == plaintext2)
  }

  // Noise_KN_25519_AESGCM_SHA256
  // https://github.com/mcginty/snow/blob/master/tests/vectors/snow.txt#L1822
  func testKN() {
    let initiatorStaticKeyPair = constructKeyPair(secretKey: Data(hex: "0af697329178e8280df75138f810feb73fed7955a5dd65f04a4ce6b945a68793"))
    let initiatorEphemeralKeyPair = constructKeyPair(secretKey: Data(hex: "0e2ea3a5ac8634d2842243eeff55550005bc1c621f1048f119d38450ba564fde"))
    let responderEphemeralKeyPair = constructKeyPair(secretKey: Data(hex: "a45a2a9915c2bcbf577226d3428b8d339d483ac19ce5d533603dedbe20811083"))

    let prologue = Data(hex: "5468657265206973206e6f20726967687420616e642077726f6e672e2054686572652773206f6e6c792066756e20616e6420626f72696e672e")

    let initiatorState = try! HandshakeState(
      pattern: .KN,
      initiator: true,
      prologue: prologue,
      s: initiatorStaticKeyPair,
      e: initiatorEphemeralKeyPair
    )
    let responderState = try! HandshakeState(
      pattern: .KN,
      initiator: false,
      prologue: prologue,
      e: responderEphemeralKeyPair,
      rs: initiatorStaticKeyPair.publicKey
    )

    // -> e
    let payload0 = Data(hex: "fe3fe994e39ccde3905e752e3f57c5789566da9f88a643648bb5917000861664")
    let initiatorTx = try! initiatorState.writeMessage(payload: payload0)
    assert(try! responderState.readMessage(message: initiatorTx) == payload0)
    assert(responderState.remoteE! == initiatorEphemeralKeyPair.publicKey)

    // <- e, ee, se
    let payload1 = Data(hex: "4fae341955f12859d2ed8b2c4b6dffc1ae7af52703702d60ffe9f33e600542a9")
    let responderTx = try! responderState.writeMessage(payload: payload1)
    assert(try! initiatorState.readMessage(message: responderTx) == payload1)
    assert(initiatorState.remoteE! == responderEphemeralKeyPair.publicKey)

    let ciphertext0b = Data(hex: "85f2fdb3e506ad2164dfd2f336179bdf3424f6b1569983bb311e386b5918de44fe3fe994e39ccde3905e752e3f57c5789566da9f88a643648bb5917000861664")
    let ciphertext1b = Data(hex: "83b47272d61f51e2d8da84c60ec210253a1af6d2677ff22726524047e4fa912cf65f03492573c4a4643ff8eff6eb496b11ddc3af0ae055424f48b75e740c4d57b8bf07d5c7079dfc9532ad1638927488")

    assert(initiatorTx == ciphertext0b)
    assert(responderTx == ciphertext1b)

    let responderSplits = try! responderState.split()
    let initiatorSplits = try! initiatorState.split()

    let plaintext1 = Data("hello world".utf8)
    let ciphertext1 = initiatorSplits.0.encryptWithAd(ad: Data(), plaintext: plaintext1)
    assert(responderSplits.0.decryptWithAd(ad: Data(), ciphertext: ciphertext1) == plaintext1)

    let plaintext2 = Data("hello world, too".utf8)
    let ciphertext2 = responderSplits.1.encryptWithAd(ad: Data(), plaintext: plaintext2)
    assert(initiatorSplits.1.decryptWithAd(ad: Data(), ciphertext: ciphertext2) == plaintext2)
  }
}
