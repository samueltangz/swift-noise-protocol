import Sodium

// let clientStaticKeyPair = generateKeyPair()
// let serverStaticKeyPair = generateKeyPair()

let sodium = Sodium()
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
let clientTx = try! clientState.writeMessage(payload: Array("".utf8))
try! serverState.readMessage(message: clientTx)
print(serverState.re! == clientEphemeralKeyPair.publicKey)

// <- e, ee, se
let serverTx = try! serverState.writeMessage(payload: Array("".utf8))
try! clientState.readMessage(message: serverTx)
print(clientState.re! == serverEphemeralKeyPair.publicKey)

let serverSplits = try! serverState.split()
let clientSplits = try! clientState.split()

let ciphertext0b = Array<UInt8>.init(hex: "32ca8ed53e4a68e52ecda4d0160bd8c6d22e736b28cee8d151c2c52e37a3123ee45510fd8c5f8caa63d7394d9dfe97fd40b22ec4b7bf0ea360c9f58a22a06e7ee1af57389c2651ee93e82d38ca1be1fc")

let plaintext0 = Array<UInt8>.init(hex: "cb0ff664bfede40c881d02768dc417d6a210606ab2a959ae029d292171691551")
let ciphertext0 = serverSplits.0.encryptWithAd(ad: [], plaintext: plaintext0)
let plaintext0b = clientSplits.0.decryptWithAd(ad: [], ciphertext: ciphertext0)
print(plaintext0 == plaintext0b)
print(ciphertext0)
let plaintext1 = Array<UInt8>.init(hex: "cb0ff664bfede40c881d02768dc417d6a210606ab2a959ae029d292171691551")
let ciphertext1 = clientSplits.1.encryptWithAd(ad: [], plaintext: plaintext1)
let plaintext1b = serverSplits.1.decryptWithAd(ad: [], ciphertext: ciphertext1)
print(plaintext1 == plaintext1b)
print(ciphertext1)

print(ciphertext0b, "expected")