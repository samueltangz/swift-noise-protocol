// let clientStaticKeyPair = generateKeyPair()
// let serverStaticKeyPair = generateKeyPair()

// print(clientStaticKeyPair)
// print(serverStaticKeyPair)

// let clientState = HandshakeState(pattern: .KK, initiator: true, s: clientStaticKeyPair, rs: serverStaticKeyPair.publicKey)
// let serverState = HandshakeState(pattern: .KK, initiator: false, s: serverStaticKeyPair, rs: clientStaticKeyPair.publicKey)

// // -> e, es, ss
// let clientTx = clientState.writeMessage(payload: Array("".utf8))
// serverState.readMessage(message: clientTx)

// // <- e, ee, se
// let serverTx = serverState.writeMessage(payload: Array("".utf8))
// clientState.readMessage(message: serverTx)

// let serverSplits = serverState.split()
// let clientSplits = clientState.split()

// print(serverSplits.0)
// print(serverSplits.1)
// print(clientSplits.0)
// print(clientSplits.1)