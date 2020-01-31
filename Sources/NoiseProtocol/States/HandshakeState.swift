enum HandshakeStateError: Error {
  case invalidPattern // should not happen in normal use case
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

public enum HandshakePattern: String {
  case X
  case IK
  case KK
}

public enum Token {
  case s
  case e
  case es
  case se
  case ee
  case ss
  case psk
}
struct HandshakePatternDetails {
  var initiatorPremessages: [Token]
  var responderPremessages: [Token]
  var messagePatterns: [[Token]]
}

// TODO: PSK
let patterns: [HandshakePattern: HandshakePatternDetails] = [
  .X: HandshakePatternDetails(
    initiatorPremessages: [],
    responderPremessages: [ .s ],
    messagePatterns: [
      [ .e, .es, .s, .ss ]
    ]
  ),
  .IK: HandshakePatternDetails(
    initiatorPremessages: [],
    responderPremessages: [ .s ],
    messagePatterns: [
      [ .e, .es, .s, .ss ],
      [ .e, .ee, .se ]
    ]
  ),
  .KK: HandshakePatternDetails(
    initiatorPremessages: [ .s ],
    responderPremessages: [ .s ],
    messagePatterns: [
      [ .e, .es, .ss ],
      [ .e, .ee, .se ]
    ]
  )
]

func getStaticKey(s: KeyPair?, rs: PublicKey?, own: Bool) throws -> PublicKey {
  if own {
    if s == nil {
      throw HandshakeStateError.missingStaticKey
    }
    return s!.publicKey
  } else {
    if rs == nil {
      throw HandshakeStateError.missingRemoteStaticKey
    }
    return rs!
  }
}

func getEphemeralKey(e: KeyPair?, re: PublicKey?, own: Bool) throws -> PublicKey {
  if own {
    if e == nil {
      throw HandshakeStateError.missingEphemeralKey
    }
    return e!.publicKey
  } else {
    if re == nil {
      throw HandshakeStateError.missingRemoteEphemeralKey
    }
    return re!
  }
}

// https://noiseprotocol.org/noise.html#the-handshakestate-object
public class HandshakeState {
  // s: The local static key pair
  var s: KeyPair?
  // e: The local ephemeral key pair
  var e: KeyPair?
  // rs: The remote party's static public key
  var rs: PublicKey?
  // re: The remote party's ephemeral public key
  var re: PublicKey?
  // initiator: A boolean indicating the initiator or responder role.
  var initiator: Bool
  // message_patterns: A sequence of message patterns. Each message pattern is a sequence of tokens
  // from the set ("e", "s", "ee", "es", "se", "ss").
  var messagePatterns: [[Token]]
  var symmetricState: SymmetricState

  public init(pattern: HandshakePattern, initiator: Bool, prologue: [UInt8] = [], s: KeyPair? = nil, e: KeyPair? = nil, rs: PublicKey? = nil, re: PublicKey? = nil) throws {
    // Derives a protocol_name byte sequence by combining the names for the handshake pattern and
    // crypto functions, as specified in Section 8. Calls InitializeSymmetric(protocol_name).
    let protocolName = "Noise_\(pattern)_25519_AESGCM_SHA256"
    self.symmetricState = SymmetricState(protocolName: protocolName)

    // Calls MixHash(prologue).
    self.symmetricState.mixHash(data: prologue)

    // Sets the initiator, s, e, rs, and re variables to the corresponding arguments.
    self.initiator = initiator
    self.s = s
    self.e = e
    self.rs = rs
    self.re = re

    // Calls MixHash() once for each public key listed in the pre-messages from handshake_pattern,
    // with the specified public key as input (see Section 7 for an explanation of pre-messages).
    // If both initiator and responder have pre-messages, the initiator's public keys are hashed
    // first. If multiple public keys are listed in either party's pre-message, the public keys are
    // hashed in the order that they are listed.
    let patternDetails = patterns[pattern]

    if patternDetails == nil {
      throw HandshakeStateError.invalidPattern
    }

    for token in patternDetails!.initiatorPremessages {
      switch token {
        case .s:
          let s = try getStaticKey(s: self.s, rs: self.rs, own: self.initiator)
          self.symmetricState.mixHash(data: s)
        case .e:
          let e = try getEphemeralKey(e: self.e, re: self.re, own: self.initiator)
          self.symmetricState.mixHash(data: e)
        default:
          throw HandshakeStateError.invalidPremessagePattern
      } 
    }

    for token in patternDetails!.responderPremessages {
      switch token {
        case .s:
          let s = try getStaticKey(s: self.s, rs: self.rs, own: !self.initiator)
          self.symmetricState.mixHash(data: s)
        case .e:
          let e = try getEphemeralKey(e: self.e, re: self.re, own: !self.initiator)
          self.symmetricState.mixHash(data: e)
        default:
          throw HandshakeStateError.invalidPremessagePattern
      } 
    }

    // Sets message_patterns to the message patterns from handshake_pattern.
    self.messagePatterns = patternDetails!.messagePatterns
  }
  public func writeMessage(payload: [UInt8]) throws -> [UInt8] {
    if self.messagePatterns.count == 0 {
      throw HandshakeStateError.completedHandshake
    }
    var out: [[UInt8]] = []
    let messagePattern = self.messagePatterns[0]
    self.messagePatterns.removeFirst(1)

    // Fetches and deletes the next message pattern from message_patterns, then sequentially
    // processes each token from the message pattern:
    for token in messagePattern {
      switch token {
        // For "e": Sets e (which must be empty) to GENERATE_KEYPAIR(). Appends e.public_key to the
        // buffer. Calls MixHash(e.public_key).
        case .e:
          #if !DEBUG
          if self.e != nil {
            throw HandshakeStateError.ephemeralKeyAlreadyExist
          }
          #endif
          let e = self.e ?? generateKeyPair()
          self.e = e
          out.append(e.publicKey)
          self.symmetricState.mixHash(data: e.publicKey)
        // For "s": Appends EncryptAndHash(s.public_key) to the buffer.
        case .s:
          if self.s == nil {
            throw HandshakeStateError.missingStaticKey
          }
          let s = self.s!.publicKey
          out.append(self.symmetricState.encryptAndHash(plaintext: s))
        // For "ee": Calls MixKey(DH(e, re)).
        case .ee:
          if self.e == nil {
            throw HandshakeStateError.missingEphemeralKey
          } else if self.re == nil {
            throw HandshakeStateError.missingRemoteEphemeralKey
          }
          let dh: [UInt8] = diffieHellman(keyPair: self.e!, publicKey: self.re!)
          self.symmetricState.mixKey(inputKeyMaterial: dh)
        // For "es": Calls MixKey(DH(e, rs)) if initiator, MixKey(DH(s, re)) if responder.
        case .es:
          if self.initiator {
            if self.e == nil {
              throw HandshakeStateError.missingEphemeralKey
            } else if self.rs == nil {
              throw HandshakeStateError.missingRemoteStaticKey
            }
            let dh: [UInt8] = diffieHellman(keyPair: self.e!, publicKey: self.rs!)
            self.symmetricState.mixKey(inputKeyMaterial: dh)
          } else {
            if self.s == nil {
              throw HandshakeStateError.missingStaticKey
            } else if self.re == nil {
              throw HandshakeStateError.missingRemoteEphemeralKey
            }
            let dh: [UInt8] = diffieHellman(keyPair: self.s!, publicKey: self.re!)
            self.symmetricState.mixKey(inputKeyMaterial: dh)
          }
        // For "se": Calls MixKey(DH(s, re)) if initiator, MixKey(DH(e, rs)) if responder.
        case .se:
          if !self.initiator {
            if self.e == nil {
              throw HandshakeStateError.missingEphemeralKey
            } else if self.rs == nil {
              throw HandshakeStateError.missingRemoteStaticKey
            }
            let dh: [UInt8] = diffieHellman(keyPair: self.e!, publicKey: self.rs!)
            self.symmetricState.mixKey(inputKeyMaterial: dh)
          } else {
            if self.s == nil {
              throw HandshakeStateError.missingStaticKey
            } else if self.re == nil {
              throw HandshakeStateError.missingRemoteEphemeralKey
            }
            let dh: [UInt8] = diffieHellman(keyPair: self.s!, publicKey: self.re!)
            self.symmetricState.mixKey(inputKeyMaterial: dh)
          }
        // For "ss": Calls MixKey(DH(s, rs)).
        case .ss:
          if self.s == nil {
            throw HandshakeStateError.missingStaticKey
          } else if self.rs == nil {
            throw HandshakeStateError.missingRemoteStaticKey
          }
          let dh: [UInt8] = diffieHellman(keyPair: self.s!, publicKey: self.rs!)
          self.symmetricState.mixKey(inputKeyMaterial: dh)
        default:
          throw HandshakeStateError.invalidMessagePattern
      }
    }
    // Appends EncryptAndHash(payload) to the buffer.
    out.append(self.symmetricState.encryptAndHash(plaintext: payload))

    // If there are no more message patterns returns two new CipherState objects by calling Split().
    return out.reduce([], +)
  }
  public func readMessage(message: [UInt8]) throws -> [UInt8] {
    if self.messagePatterns.count == 0 {
      throw HandshakeStateError.completedHandshake
    }
    var messageBuffer = message
    let messagePattern = self.messagePatterns[0]
    self.messagePatterns.removeFirst(1)

    // Fetches and deletes the next message pattern from message_patterns, then sequentially
    // processes each token from the message pattern:
    for token in messagePattern {
      switch token {
        // For "e": Sets re (which must be empty) to the next DHLEN bytes from the message. Calls
        // MixHash(re.public_key).
        case .e:
          if message.count < 32 {
            throw HandshakeStateError.messageTooShort
          }
          let re = PublicKey(messageBuffer[..<32])
          self.re = re
          messageBuffer = Array(messageBuffer[32...])
          self.symmetricState.mixHash(data: re)
        // For "s": Sets temp to the next DHLEN + 16 bytes of the message if HasKey() == True, or to
        // the next DHLEN bytes otherwise. Sets rs (which must be empty) to DecryptAndHash(temp).
        case .s:
          if self.rs != nil {
            throw HandshakeStateError.staticKeyAlreadyExist
          }
          if self.symmetricState.cipherState.hasKey() {
            if message.count < 48 {
              throw HandshakeStateError.messageTooShort
            }
            let rs = PublicKey(self.symmetricState.decryptAndHash(ciphertext: Array(messageBuffer[..<48])))
            messageBuffer = Array(messageBuffer[48...])
            self.rs = rs
          } else {
            if message.count < 32 {
              throw HandshakeStateError.messageTooShort              
            }
            let rs = PublicKey(messageBuffer[..<32])
            messageBuffer = Array(messageBuffer[32...])
            self.rs = rs
          }
        // For "ee": Calls MixKey(DH(e, re)).
        case .ee:
          if self.e == nil {
            throw HandshakeStateError.missingEphemeralKey
          } else if self.re == nil {
            throw HandshakeStateError.missingRemoteEphemeralKey
          }
          let dh: [UInt8] = diffieHellman(keyPair: self.e!, publicKey: self.re!)
          self.symmetricState.mixKey(inputKeyMaterial: dh)
        // For "es": Calls MixKey(DH(e, rs)) if initiator, MixKey(DH(s, re)) if responder.
        case .es:
          if self.initiator {
            if self.e == nil {
              throw HandshakeStateError.missingEphemeralKey
            } else if self.rs == nil {
              throw HandshakeStateError.missingRemoteStaticKey
            }
            let dh: [UInt8] = diffieHellman(keyPair: self.e!, publicKey: self.rs!)
            self.symmetricState.mixKey(inputKeyMaterial: dh)
          } else {
            if self.s == nil {
              throw HandshakeStateError.missingStaticKey
            } else if self.re == nil {
              throw HandshakeStateError.missingRemoteEphemeralKey
            }
            let dh: [UInt8] = diffieHellman(keyPair: self.s!, publicKey: self.re!)
            self.symmetricState.mixKey(inputKeyMaterial: dh)
          }
        // For "se": Calls MixKey(DH(s, re)) if initiator, MixKey(DH(e, rs)) if responder.
        case .se:
          if !self.initiator {
            if self.e == nil {
              throw HandshakeStateError.missingEphemeralKey
            } else if self.rs == nil {
              throw HandshakeStateError.missingRemoteStaticKey
            }
            let dh: [UInt8] = diffieHellman(keyPair: self.e!, publicKey: self.rs!)
            self.symmetricState.mixKey(inputKeyMaterial: dh)
          } else {
            if self.s == nil {
              throw HandshakeStateError.missingStaticKey
            } else if self.re == nil {
              throw HandshakeStateError.missingRemoteEphemeralKey
            }
            let dh: [UInt8] = diffieHellman(keyPair: self.s!, publicKey: self.re!)
            self.symmetricState.mixKey(inputKeyMaterial: dh)
          }
        // For "ss": Calls MixKey(DH(s, rs)).
        case .ss:
          if self.s == nil {
            throw HandshakeStateError.missingStaticKey
          } else if self.rs == nil {
            throw HandshakeStateError.missingRemoteStaticKey
          }
          let dh: [UInt8] = diffieHellman(keyPair: self.s!, publicKey: self.rs!)
          self.symmetricState.mixKey(inputKeyMaterial: dh)
        default:
          throw HandshakeStateError.invalidMessagePattern
      }
    }
    // Calls DecryptAndHash() on the remaining bytes of the message and stores the output into
    // payload_buffer.
    // If there are no more message patterns returns two new CipherState objects by calling Split().
    return []
  }

  func split() throws -> (CipherState, CipherState) {
    if self.messagePatterns.count > 0 {
      throw HandshakeStateError.incompleteHandshake
    }
    return self.symmetricState.split()
  }
}
