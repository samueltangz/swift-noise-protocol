/*
import Foundation
import Sodium
import CryptoKit25519

func constructKeyPair(secretKey: SecretKey) -> KeyPair {
  let secretKeyObj = try! Curve25519.KeyAgreement.PrivateKey(rawRepresentation: Data(normalize(secretKey: secretKey)))
  let publicKey = Array(secretKeyObj.publicKey.rawRepresentation)
  return KeyPair(publicKey: publicKey, secretKey: secretKey)
}

extension Sequence where Element == UInt8 {
    var data: Data { .init(self) }
    var hexa: String { map { .init(format: "%02x", $0) }.joined() }
}

// Noise_N_25519_AESGCM_SHA256
// https://github.com/mcginty/snow/blob/master/tests/vectors/snow.txt#L106
func testN() {
  let serverStaticKeyPair = constructKeyPair(secretKey: Array<UInt8>.init(hex: "2a1c15dc684bd84612e9b2d84f740c76789042390af00fd02f71ec14dd213231"))
  let clientEphemeralKeyPair = constructKeyPair(secretKey: Array<UInt8>.init(hex: "3b40bcbafac8be41b4e52af1caf6edb1cc6f9f48a1b9579e69a25d6bf66c10cd"))
  let serverEphemeralKeyPair = constructKeyPair(secretKey: Array<UInt8>.init(hex: "fa96ea6cb4e79f59412fb8fdbe6beac212939840f2f9f1afef0877eae5ff527c"))

  let prologue = Array<UInt8>.init(
    hex: "5468657265206973206e6f20726967687420616e642077726f6e672e2054686572652773206f6e6c792066756e20616e6420626f72696e672e")

  let clientState = try! HandshakeState(
    pattern: .N,
    initiator: true,
    prologue: prologue,
    e: clientEphemeralKeyPair,
    rs: serverStaticKeyPair.publicKey
  )
  let serverState = try! HandshakeState(
    pattern: .N,
    initiator: false,
    prologue: prologue,
    s: serverStaticKeyPair,
    e: serverEphemeralKeyPair
  )

  // -> e, es
  let payload0 = Array<UInt8>.init(hex: "0855d5bc3c0bec5270363f3ed1d3cdf28aabcf3da8c5a0871d2ada89f0661b30")
  let clientTx = try! clientState.writeMessage(payload: payload0)
  assert(try! serverState.readMessage(message: clientTx) == payload0)
  assert(serverState.re! == clientEphemeralKeyPair.publicKey)

  // let serverSplits = try! serverState.split()
  // let clientSplits = try! clientState.split()

  let ciphertext0b = Array<UInt8>.init(hex: "aa83fbe6881be6f3b853d17e05f998df0e6ba0d370c5208e03b8f7c6c1fdc575d630e6f82b7736831479e0d3b6c2ab6bf9048d0dbc0377f147e223649d4fc95efb9774fbc577d249e2e2907d60154a57")

  assert(clientTx == ciphertext0b)
}

// Noise_X_25519_AESGCM_SHA256
// https://github.com/mcginty/snow/blob/master/tests/vectors/snow.txt#L248
func testX() {
  let clientStaticKeyPair = KeyPair(
    publicKey: Array<UInt8>.init(hex: "7281aff40cd24f66eca78913e02651b543a09be9c78d420a38282b2889690912"),
    secretKey: Array<UInt8>.init(hex: "94e7f031803c6ed2acb0eb1528a93c7a1c446eef4b69af38443cf820e69d960e"))
  let serverStaticKeyPair = KeyPair(
    publicKey: Array<UInt8>.init(hex: "1ede233080a9305f658aeced07ef04ced370b5f1bba099b3abc39ec7b4f5a83f"),
    secretKey: Array<UInt8>.init(hex: "4b9d66860c39de31492bdb3b090527bf66ef1ea75f105bb6f87328dfbb9fe337"))
  let clientEphemeralKeyPair = KeyPair(
    publicKey: Array<UInt8>.init(hex: "6f8eaa3373069db1383b3ca7a697a54d4543e8c4ba086e4b4b6052147c40c87c"),
    secretKey: Array<UInt8>.init(hex: "f587d5ff11066818e6a685a05be677f0618837b40271ec058b1c1d9dcbe3346f"))
  let serverEphemeralKeyPair = KeyPair(
    publicKey: Array<UInt8>.init(hex: "9c1e3f8f295e2baa0382f970b9cbc2cb0c18066f7f6ad44e97ddb68b212d5121"),
    secretKey: Array<UInt8>.init(hex: "c99e75600766e8ec8de995b4b00085c3b90387191b3c1568ca20867761fa65e8"))

  let prologue = Array<UInt8>.init(
    hex: "5468657265206973206e6f20726967687420616e642077726f6e672e2054686572652773206f6e6c792066756e20616e6420626f72696e672e")

  let clientState = try! HandshakeState(
    pattern: .X,
    initiator: true,
    prologue: prologue,
    s: clientStaticKeyPair,
    e: clientEphemeralKeyPair,
    rs: serverStaticKeyPair.publicKey
  )
  let serverState = try! HandshakeState(
    pattern: .X,
    initiator: false,
    prologue: prologue,
    s: serverStaticKeyPair,
    e: serverEphemeralKeyPair
  )

  // -> e, es, s, ss
  let payload0 = Array<UInt8>.init(hex: "81df37247729d0b3f5f712be3796b5f7cc4fa39dde314cd7e81fb5e574db63c0")
  let clientTx = try! clientState.writeMessage(payload: payload0)
  assert(try! serverState.readMessage(message: clientTx) == payload0)
  assert(serverState.re! == clientEphemeralKeyPair.publicKey)

  // let serverSplits = try! serverState.split()
  // let clientSplits = try! clientState.split()

  let ciphertext0b = Array<UInt8>.init(hex: "6f8eaa3373069db1383b3ca7a697a54d4543e8c4ba086e4b4b6052147c40c87c95c86a7f909f2fa0141a00a6708349dd80fa5349c42257dc3581a6156a383cb8a13bcdc99a50fec8f458225bd799839b63482c4fa2167aae247fc49966712890c8d566e78fddc01f6ae2bfa6a096ec8fd788a02b5bfcfb8f6060c6cfb9647680")

  assert(clientTx == ciphertext0b)
}

// Noise_IK_25519_AESGCM_SHA256
// https://github.com/mcginty/snow/blob/master/tests/vectors/snow.txt#L2336
func testIK() {
  let clientStaticKeyPair = KeyPair(
    publicKey: Array<UInt8>.init(hex: "1b9aac560791b3b39d3f1625f4a758a5d8bd864963ae3dc5771567e58499cf60"),
    secretKey: Array<UInt8>.init(hex: "834923a2cbc86100d56854892049a7d6afbf2b2231b4450028cfc9b7a1993fb1"))
  let serverStaticKeyPair = KeyPair(
    publicKey: Array<UInt8>.init(hex: "5c95fe4f7018b5f22379f35b87db8cb938c63a6cd42b6fe48a802e583d05822d"),
    secretKey: Array<UInt8>.init(hex: "067d24b814b15993f11a68b9270779889ef87b865a4f579bdf138f5a7d69b8d2"))
  let clientEphemeralKeyPair = KeyPair(
    publicKey: Array<UInt8>.init(hex: "72e3811d48022216bb2695f7dbd8cb9c0d9e954147ffe6fe96822d63bbcd3164"),
    secretKey: Array<UInt8>.init(hex: "9f77df6db1e5fa790cff942e5db226c71375988ab2cfb8193817c1a716f679ed"))
  let serverEphemeralKeyPair = KeyPair(
    publicKey: Array<UInt8>.init(hex: "1b690be6976fc8d2e9c687be8ff298637f90f59ea34af404c53578fd3a738046"),
    secretKey: Array<UInt8>.init(hex: "68ca5c7901e604433e2ecd950576060c5b002f9fe2edc2eb1d46468601d995eb"))
  let prologue = Array<UInt8>.init(
    hex: "5468657265206973206e6f20726967687420616e642077726f6e672e2054686572652773206f6e6c792066756e20616e6420626f72696e672e")

  let clientState = try! HandshakeState(
    pattern: .IK,
    initiator: true,
    prologue: prologue,
    s: clientStaticKeyPair,
    e: clientEphemeralKeyPair,
    rs: serverStaticKeyPair.publicKey
  )
  let serverState = try! HandshakeState(
    pattern: .IK,
    initiator: false,
    prologue: prologue,
    s: serverStaticKeyPair,
    e: serverEphemeralKeyPair
  )

  // -> e, es, s, ss
  let payload0 = Array<UInt8>.init(hex: "41f6bee49109aa96c3c80d787445b08b96cd35d195bc19805688189516f02d7e")
  let clientTx = try! clientState.writeMessage(payload: payload0)
  assert(try! serverState.readMessage(message: clientTx) == payload0)
  assert(serverState.re! == clientEphemeralKeyPair.publicKey)

  // <- e, ee, se
  let payload1 = Array<UInt8>.init(hex: "bb6c9b156337fece15f0efd89a0ec934e0d414522ed7561eb3a6b1a7b028de9f")
  let serverTx = try! serverState.writeMessage(payload: payload1)
  assert(try! clientState.readMessage(message: serverTx) == payload1)
  assert(clientState.re! == serverEphemeralKeyPair.publicKey)

  // let serverSplits = try! serverState.split()
  // let clientSplits = try! clientState.split()

  let ciphertext0b = Array<UInt8>.init(hex: "72e3811d48022216bb2695f7dbd8cb9c0d9e954147ffe6fe96822d63bbcd3164a8d64f8886104f56ede0c7f35e5d13f27b0607a2693f9e2899b24fe0eae8101cbfcca90a9a50657429ade64223af6e2c660f2c00e512a5cbdbc0de0ce9c62ab0cbe98e348a61fd113c576a75aedf3ee5227be8327b2dccb343ad05523f961298")
  let ciphertext1b = Array<UInt8>.init(hex: "1b690be6976fc8d2e9c687be8ff298637f90f59ea34af404c53578fd3a73804668fc97497b2085820ce1f62a0d9a0a0378f9544ae492be9e7b9219603404cfcb85cccdce9f6d946b1ccce04cfaab9df1")

  assert(clientTx == ciphertext0b)
  assert(serverTx == ciphertext1b)
}

// Noise_KK_25519_AESGCM_SHA256
// https://github.com/mcginty/snow/blob/master/tests/vectors/snow.txt#L1822
func testKK() {
  let clientStaticKeyPair = KeyPair(
    publicKey: Array<UInt8>.init(hex: "04fff412b2575df4d1cb69cb28425cfd20a6dd7c7c88a99c57362a3f55b88774"),
    secretKey: Array<UInt8>.init(hex: "faebb0194fee50fb819b7127c6f4a24dab85af4ac4ebb263eb1a44e8a7f60d41"))
  let serverStaticKeyPair = KeyPair(
    publicKey: Array<UInt8>.init(hex: "17929481f738a90ac46dea716405024deb3742f717a6a689123df8d6b7a81f32"),
    secretKey: Array<UInt8>.init(hex: "fae0883f3bcbb944236fbfeefaaa03427920d940b05c4cd1016070ce7c420c0a"))
  let clientEphemeralKeyPair = KeyPair(
    publicKey: Array<UInt8>.init(hex: "32ca8ed53e4a68e52ecda4d0160bd8c6d22e736b28cee8d151c2c52e37a3123e"),
    secretKey: Array<UInt8>.init(hex: "4747e3766bf863acda954fb093d1ed3d438019b9fc1f0dfcbe995d27ea14c825"))
  let serverEphemeralKeyPair = KeyPair(
    publicKey: Array<UInt8>.init(hex: "6571c26d443f64388cb42967e73d4b09d9f496586d87f2517ec73507b4bd5457"),
    secretKey: Array<UInt8>.init(hex: "772bcda9330c8849a1763365a4faa47f6cf9c0ef8f6d170d41ddff6c0cfb1a37"))
  let prologue = Array<UInt8>.init(
    hex: "5468657265206973206e6f20726967687420616e642077726f6e672e2054686572652773206f6e6c792066756e20616e6420626f72696e672e")

  let clientState = try! HandshakeState(
    pattern: .KK,
    initiator: true,
    prologue: prologue,
    s: clientStaticKeyPair,
    e: clientEphemeralKeyPair,
    rs: serverStaticKeyPair.publicKey
  )
  let serverState = try! HandshakeState(
    pattern: .KK,
    initiator: false,
    prologue: prologue,
    s: serverStaticKeyPair,
    e: serverEphemeralKeyPair,
    rs: clientStaticKeyPair.publicKey
  )

  // -> e, es, ss
  let payload0 = Array<UInt8>.init(hex: "cb0ff664bfede40c881d02768dc417d6a210606ab2a959ae029d292171691551")
  let clientTx = try! clientState.writeMessage(payload: payload0)
  assert(try! serverState.readMessage(message: clientTx) == payload0)
  assert(serverState.re! == clientEphemeralKeyPair.publicKey)

  // <- e, ee, se
  let payload1 = Array<UInt8>.init(hex: "e546bfd27b0c80b137af4ef3bcfb664c1e42edb732b65adb468ead8973a16d55")
  let serverTx = try! serverState.writeMessage(payload: payload1)
  assert(try! clientState.readMessage(message: serverTx) == payload1)
  assert(clientState.re! == serverEphemeralKeyPair.publicKey)

  // let serverSplits = try! serverState.split()
  // let clientSplits = try! clientState.split()

  let ciphertext0b = Array<UInt8>.init(hex: "32ca8ed53e4a68e52ecda4d0160bd8c6d22e736b28cee8d151c2c52e37a3123ee45510fd8c5f8caa63d7394d9dfe97fd40b22ec4b7bf0ea360c9f58a22a06e7ee1af57389c2651ee93e82d38ca1be1fc")
  let ciphertext1b = Array<UInt8>.init(hex: "6571c26d443f64388cb42967e73d4b09d9f496586d87f2517ec73507b4bd54579bc86e337166ca0b985745a18ba002eb0ed778e1ce2e9389d1095f3e6a14dccae295a8edb489c6b9b91ffd72d8bbe94a")

  assert(clientTx == ciphertext0b)
  assert(serverTx == ciphertext1b)
}

// Noise_KN_25519_AESGCM_SHA256
// https://github.com/mcginty/snow/blob/master/tests/vectors/snow.txt#L1822
func testKN() {
  let clientStaticKeyPair = KeyPair(
    publicKey: Array<UInt8>.init(hex: "2a7a291ee10b846815a6875d21d9a5319a2b41eb4a91926aa12242fa17897229"),
    secretKey: Array<UInt8>.init(hex: "0af697329178e8280df75138f810feb73fed7955a5dd65f04a4ce6b945a68793"))
  let clientEphemeralKeyPair = KeyPair(
    publicKey: Array<UInt8>.init(hex: "85f2fdb3e506ad2164dfd2f336179bdf3424f6b1569983bb311e386b5918de44"),
    secretKey: Array<UInt8>.init(hex: "0e2ea3a5ac8634d2842243eeff55550005bc1c621f1048f119d38450ba564fde"))
  let serverEphemeralKeyPair = KeyPair(
    publicKey: Array<UInt8>.init(hex: "83b47272d61f51e2d8da84c60ec210253a1af6d2677ff22726524047e4fa912c"),
    secretKey: Array<UInt8>.init(hex: "a45a2a9915c2bcbf577226d3428b8d339d483ac19ce5d533603dedbe20811083"))
  let prologue = Array<UInt8>.init(
    hex: "5468657265206973206e6f20726967687420616e642077726f6e672e2054686572652773206f6e6c792066756e20616e6420626f72696e672e")

  let clientState = try! HandshakeState(
    pattern: .KN,
    initiator: true,
    prologue: prologue,
    s: clientStaticKeyPair,
    e: clientEphemeralKeyPair
  )
  let serverState = try! HandshakeState(
    pattern: .KN,
    initiator: false,
    prologue: prologue,
    e: serverEphemeralKeyPair,
    rs: clientStaticKeyPair.publicKey
  )

  // -> e
  let payload0 = Array<UInt8>.init(hex: "fe3fe994e39ccde3905e752e3f57c5789566da9f88a643648bb5917000861664")
  let clientTx = try! clientState.writeMessage(payload: payload0)
  assert(try! serverState.readMessage(message: clientTx) == payload0)
  assert(serverState.re! == clientEphemeralKeyPair.publicKey)

  // <- e, ee, se
  let payload1 = Array<UInt8>.init(hex: "4fae341955f12859d2ed8b2c4b6dffc1ae7af52703702d60ffe9f33e600542a9")
  let serverTx = try! serverState.writeMessage(payload: payload1)
  assert(try! clientState.readMessage(message: serverTx) == payload1)
  assert(clientState.re! == serverEphemeralKeyPair.publicKey)

  // let serverSplits = try! serverState.split()
  // let clientSplits = try! clientState.split()

  let ciphertext0b = Array<UInt8>.init(hex: "85f2fdb3e506ad2164dfd2f336179bdf3424f6b1569983bb311e386b5918de44fe3fe994e39ccde3905e752e3f57c5789566da9f88a643648bb5917000861664")
  let ciphertext1b = Array<UInt8>.init(hex: "83b47272d61f51e2d8da84c60ec210253a1af6d2677ff22726524047e4fa912cf65f03492573c4a4643ff8eff6eb496b11ddc3af0ae055424f48b75e740c4d57b8bf07d5c7079dfc9532ad1638927488")

  assert(clientTx == ciphertext0b)
  assert(serverTx == ciphertext1b)
}

testN()
testX()
testIK()
testKK()
testKN()
*/