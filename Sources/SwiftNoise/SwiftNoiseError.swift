enum HandshakeStateError: Error {
  case invalidPattern // should not happen in normal use case
  case invalidKey // should not happen in normal use case
  case invalidPremessagePattern
  case invalidMessagePattern
  case missingStaticKey
  case missingRemoteStaticKey
  case staticKeyAlreadyExist
  case missingEphemeralKey
  case missingRemoteEphemeralKey
  case ephemeralKeyAlreadyExist
  case incompleteHandshake
  case completedHandshake
  case messageTooShort
}

enum NonceError: Error {
  case nonceOverflow
}

enum CipherStateError: Error {
  case invalidKeySize
}

enum CipherError: Error {
  case cannotInstantiateCipher(error: Error)
  case invalidPlaintext(error: Error)
  case invalidCiphertext(error: Error)
}

enum DHError: Error {}

enum HashError: Error {
  case tooLittleOutputs
  case tooManyOutputs
}
