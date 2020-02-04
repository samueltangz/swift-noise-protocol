# SwiftNoise

Noise protocol implemented with Swift.

## Installation

### Swift Package Manager

Add the following lines to `Package.swift`.

```swift
dependencies: [
  ...,
  .package(url: "https://github.com/samueltangz/swift-noise-protocol.git", from: "0.2.1")
  ...
],
targets: (
  ...
  dependencies: [
    ...,
    "SwiftNoise",
    ...
  ],
  ...
)
```

### Import package

```swift
import SwiftNoise
```



## Supported features

### DH functions, cipher functions, and hash functions

The functions are supported based on [session 12 of the specification](https://noiseprotocol.org/noise.html#dh-functions-cipher-functions-and-hash-functions).

#### Diffie-Hellman curves

* [X] Curve25519
* [ ] Curve448

#### Cipher functions

* [ ] ChaChaPoly
* [X] AESGCM

#### Hash functions

* [X] SHA256
* [ ] SHA512
* [ ] BLAKE2s
* [ ] BLAKE2b

### Handshake patterns

The handshake patterns defined in [session 7 of the specification](https://noiseprotocol.org/noise.html#handshake-patterns) will be supported.

* [X] `N`
* [X] `K`
* [X] `X`
* [X] `NN`
* [X] `NK`
* [X] `NX`
* [X] `KN`
* [X] `KK`
* [X] `KX`
* [X] `XN`
* [X] `XK`
* [X] `XX`
* [X] `IN`
* [X] `IK`
* [X] `IX`
  
## Example usage

The following is an example usage for Noise with `Noise_X_25519_AESGCM_SHA256`.

```swift
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
```