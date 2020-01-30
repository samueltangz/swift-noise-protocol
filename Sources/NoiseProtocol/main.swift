let clientStaticKeyPair = generateKeyPair()
let serverStaticKeyPair = generateKeyPair()

let clientState = HandshakeState(pattern: .KK, initiator: true, s: clientStaticKeyPair, rs: serverStaticKeyPair.publicKey)
let serverState = HandshakeState(pattern: .KK, initiator: false, s: serverStaticKeyPair, rs: clientStaticKeyPair.publicKey)

// -> e, es, ss
let clientTx = clientState.writeMessage(payload: Array("".utf8))
serverState.readMessage(message: clientTx)

// <- e, ee, se
let serverTx = serverState.writeMessage(payload: Array("".utf8))
clientState.readMessage(message: serverTx)

let serverSplits = serverState.split()
let clientSplits = clientState.split()

let ciphertext0 = serverSplits.0.encryptWithAd(ad: [], plaintext: Array("test".utf8))
let plaintext0 = clientSplits.0.decryptWithAd(ad: [], ciphertext: ciphertext0)
print(plaintext0 == Array("test".utf8))

let ciphertext1 = clientSplits.1.encryptWithAd(ad: [], plaintext: Array("test".utf8))
let plaintext1 = serverSplits.1.decryptWithAd(ad: [], ciphertext: ciphertext1)
print(plaintext1 == Array("test".utf8))
