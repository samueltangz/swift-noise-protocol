# SwiftNoise

Noise protocol implemented with Swift.

## Installation

### Swift Package Manager

Add the following lines to `Package.swift`.

```swift
dependencies: [
  ...,
  .package(url: "https://github.com/samueltangz/swift-noise-protocol.git", from: "0.1.0")
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
* [ ] `K`
* [X] `X`
* [ ] `NN`
* [ ] `NK`
* [ ] `NX`
* [X] `KN`
* [X] `KK`
* [ ] `KX`
* [ ] `XN`
* [ ] `XK`
* [ ] `XX`
* [ ] `IN`
* [X] `IK`
* [ ] `IX`
  
## Example usage

The following is an example usage for Noise with `Noise_X_25519_AESGCM_SHA256`.

```swift
let initiatorStaticKeyPair = generateKeyPair()
let responderStaticKeyPair = generateKeyPair()
let initiatorEphemeralKeyPair = generateKeyPair()
let responderEphemeralKeyPair = generateKeyPair()

let initiatorState = try! HandshakeState(
  pattern: .X,
  initiator: true,
  s: initiatorStaticKeyPair,
  e: initiatorEphemeralKeyPair,
  rs: responderStaticKeyPair.publicKey
)
let responderState = try! HandshakeState(
  pattern: .X,
  initiator: false,
  s: responderStaticKeyPair,
  e: responderEphemeralKeyPair
)

// -> e, es, s, ss
let initiatorTx = try! initiatorState.writeMessage(payload: [])
assert(try! responderState.readMessage(message: initiatorTx) == [])

let responderSplits = try! responderState.split()
let initiatorSplits = try! initiatorState.split()

let plaintext1 = Array("hello world".utf8)
let ciphertext1 = initiatorSplits.0.encryptWithAd(ad: [], plaintext: plaintext1)
assert(responderSplits.0.decryptWithAd(ad: [], ciphertext: ciphertext1) == plaintext1)

let plaintext2 = Array("hello world, too".utf8)
let ciphertext2 = responderSplits.1.encryptWithAd(ad: [], plaintext: plaintext2)
assert(initiatorSplits.1.decryptWithAd(ad: [], ciphertext: ciphertext2) == plaintext2)
```