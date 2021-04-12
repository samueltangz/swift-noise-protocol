import Foundation

// If own is true, returns the public static key of oneself. Otherwise return the public static key
// of the opposite party.
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

// If own is true, returns the public ephemeral key of oneself. Otherwise return the public
// ephemeral key of the opposite party.
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

public enum Key {
  case e  // Ephemeral key
  case s  // Static key
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

  var curveHelper: Curve

  #if DEBUG
    public var remoteS: PublicKey? {
      return rs
    }
    public var remoteE: PublicKey? {
      return re
    }
  #endif

  // Returns a public key according to the arguments:
  // - If `own` is true, returns a key from the current party. Otherwise return a key from the opposite party.
  // - `key` specifies which key to return. Supports `.e` for ephemeral key and `.s` for static key.
  private func getPublicKey(own: Bool, key: Key) throws -> PublicKey {
    if own {
      if key == .e {
        guard let e = self.e else {
          throw HandshakeStateError.missingEphemeralKey
        }
        return e.publicKey
      } else if key == .s {
        guard let s = self.s else {
          throw HandshakeStateError.missingStaticKey
        }
        return s.publicKey
      }
      throw HandshakeStateError.invalidKey
    } else {
      if key == .e {
        guard let e = self.re else {
          throw HandshakeStateError.missingRemoteEphemeralKey
        }
        return e
      } else if key == .s {
        guard let s = self.rs else {
          throw HandshakeStateError.missingRemoteStaticKey
        }
        return s
      }
      throw HandshakeStateError.invalidKey
    }
  }

  // Returns a key pair according to the argument:
  // - `key` specifies which key to return. Supports `.e` for ephemeral key and `.s` for static key.
  private func getKeyPair(key: Key) throws -> KeyPair {
    if key == .e {
      guard let e = self.e else {
        throw HandshakeStateError.missingEphemeralKey
      }
      return e
    } else if key == .s {
      guard let s = self.s else {
        throw HandshakeStateError.missingStaticKey
      }
      return s
    }
    throw HandshakeStateError.invalidKey
  }

  public init(
    pattern: HandshakePattern, initiator: Bool, prologue: Data = Data(), s: KeyPair? = nil,
    e: KeyPair? = nil, rs: PublicKey? = nil
  ) throws {
    // Derives a protocol_name byte sequence by combining the names for the handshake pattern and
    // crypto functions, as specified in Section 8. Calls InitializeSymmetric(protocol_name).
    let protocolName = "Noise_\(pattern)_25519_AESGCM_SHA256"
    self.symmetricState = try SymmetricState(protocolName: protocolName)

    self.curveHelper = Curves.C25519()

    // Calls MixHash(prologue).
    self.symmetricState.mixHash(data: prologue)

    // Sets the initiator, s, e, rs, and re variables to the corresponding arguments.
    self.initiator = initiator
    self.s = s
    self.e = e
    self.rs = rs
    self.re = nil

    // Calls MixHash() once for each public key listed in the pre-messages from handshake_pattern,
    // with the specified public key as input (see Section 7 for an explanation of pre-messages).
    // If both initiator and responder have pre-messages, the initiator's public keys are hashed
    // first. If multiple public keys are listed in either party's pre-message, the public keys are
    // hashed in the order that they are listed.
    guard let patternDetails = patterns[pattern] else {
      throw HandshakeStateError.invalidPattern
    }

    // Sets message_patterns to the message patterns from handshake_pattern.
    self.messagePatterns = patternDetails.messagePatterns

    for token in patternDetails.initiatorPremessages {
      switch token {
      case .s:
        let s = try self.getPublicKey(own: self.initiator, key: .s)
        self.symmetricState.mixHash(data: s)
      case .e:
        let e = try self.getPublicKey(own: self.initiator, key: .e)
        self.symmetricState.mixHash(data: e)
      default:
        throw HandshakeStateError.invalidPremessagePattern
      }
    }

    for token in patternDetails.responderPremessages {
      switch token {
      case .s:
        let s = try self.getPublicKey(own: !self.initiator, key: .s)
        self.symmetricState.mixHash(data: s)
      case .e:
        let e = try self.getPublicKey(own: !self.initiator, key: .e)
        self.symmetricState.mixHash(data: e)
      default:
        throw HandshakeStateError.invalidPremessagePattern
      }
    }
  }
}

// Maintains the helper functions for the handshake state. Those function should be kept private.
extension HandshakeState {

  // For "e": Sets e (which must be empty) to GENERATE_KEYPAIR(). Appends e.public_key to the
  // buffer. Calls MixHash(e.public_key).
  private func writeE() throws -> Data {
    #if !DEBUG
      if self.e != nil {
        throw HandshakeStateError.ephemeralKeyAlreadyExist
      }
    #endif
    let e = try self.e ?? self.curveHelper.generateKeyPair()
    self.e = e
    self.symmetricState.mixHash(data: e.publicKey)
    return e.publicKey
  }

  // For "s": Appends EncryptAndHash(s.public_key) to the buffer.
  private func writeS() throws -> Data {
    let s = try self.getPublicKey(own: true, key: .s)
    return try self.symmetricState.encryptAndHash(plaintext: s)
  }

  // For "ee": Calls MixKey(DH(e, re)).
  private func writeEE() throws -> Data {
    let e = try self.getKeyPair(key: .e)
    let re = try self.getPublicKey(own: false, key: .e)
    let dh = try self.curveHelper.dh(keyPair: e, publicKey: re)
    try self.symmetricState.mixKey(inputKeyMaterial: dh)
    return Data()
  }

  // For "es": Calls MixKey(DH(e, rs)) if initiator, MixKey(DH(s, re)) if responder.
  private func writeES() throws -> Data {
    let keyPair = try self.getKeyPair(key: self.initiator ? .e : .s)
    let remotePublicKey = try self.getPublicKey(own: false, key: self.initiator ? .s : .e)
    let dh = try self.curveHelper.dh(keyPair: keyPair, publicKey: remotePublicKey)
    try self.symmetricState.mixKey(inputKeyMaterial: dh)
    return Data()
  }

  // For "se": Calls MixKey(DH(s, re)) if initiator, MixKey(DH(e, rs)) if responder.
  private func writeSE() throws -> Data {
    let keyPair = try self.getKeyPair(key: self.initiator ? .s : .e)
    let remotePublicKey = try self.getPublicKey(own: false, key: self.initiator ? .e : .s)
    let dh = try self.curveHelper.dh(keyPair: keyPair, publicKey: remotePublicKey)
    try self.symmetricState.mixKey(inputKeyMaterial: dh)
    return Data()
  }

  // For "ss": Calls MixKey(DH(s, rs)).
  private func writeSS() throws -> Data {
    let s = try self.getKeyPair(key: .s)
    let rs = try self.getPublicKey(own: false, key: .s)
    let dh = try self.curveHelper.dh(keyPair: s, publicKey: rs)
    try self.symmetricState.mixKey(inputKeyMaterial: dh)
    return Data()
  }

  private func dispatchWriteToken(token: Token) throws -> Data {
    switch token {
    case .e:
      return try self.writeE()
    case .s:
      return try self.writeS()
    case .ee:
      return try self.writeEE()
    case .es:
      return try self.writeES()
    case .se:
      return try self.writeSE()
    case .ss:
      return try self.writeSS()
    default:
      throw HandshakeStateError.invalidMessagePattern
    }
  }

  // For "e": Sets re (which must be empty) to the next DHLEN bytes from the message. Calls
  // MixHash(re.public_key).
  private func readE(_ messageBuffer: Data) throws -> Data {
    if messageBuffer.count < 32 {
      throw HandshakeStateError.messageTooShort
    }
    let re = PublicKey(messageBuffer.prefix(32))
    self.re = re
    self.symmetricState.mixHash(data: re)
    return messageBuffer.suffix(messageBuffer.count - 32)
  }

  // For "s": Sets temp to the next DHLEN + 16 bytes of the message if HasKey() == True, or to
  // the next DHLEN bytes otherwise. Sets rs (which must be empty) to DecryptAndHash(temp).
  private func readS(_ messageBuffer: Data) throws -> Data {
    if self.rs != nil {
      throw HandshakeStateError.staticKeyAlreadyExist
    }
    let size = self.symmetricState.cipherState.hasKey() ? 48 : 32
    if messageBuffer.count < size {
      throw HandshakeStateError.messageTooShort
    }
    let rs = try self.symmetricState.decryptAndHash(ciphertext: messageBuffer.prefix(size))
    self.rs = rs
    return messageBuffer.suffix(messageBuffer.count - size)
  }

  // For "ee": Calls MixKey(DH(e, re)).
  private func readEE(_ messageBuffer: Data) throws -> Data {
    let e = try self.getKeyPair(key: .e)
    let re = try self.getPublicKey(own: false, key: .e)
    let dh = try self.curveHelper.dh(keyPair: e, publicKey: re)
    try self.symmetricState.mixKey(inputKeyMaterial: dh)
    return messageBuffer
  }

  // For "es": Calls MixKey(DH(e, rs)) if initiator, MixKey(DH(s, re)) if responder.
  private func readES(_ messageBuffer: Data) throws -> Data {
    let keyPair = try self.getKeyPair(key: self.initiator ? .e : .s)
    let remotePublicKey = try self.getPublicKey(own: false, key: self.initiator ? .s : .e)
    let dh = try self.curveHelper.dh(keyPair: keyPair, publicKey: remotePublicKey)
    try self.symmetricState.mixKey(inputKeyMaterial: dh)
    return messageBuffer
  }

  // For "se": Calls MixKey(DH(s, re)) if initiator, MixKey(DH(e, rs)) if responder.
  private func readSE(_ messageBuffer: Data) throws -> Data {
    let keyPair = try self.getKeyPair(key: self.initiator ? .s : .e)
    let remotePublicKey = try self.getPublicKey(own: false, key: self.initiator ? .e : .s)
    let dh = try self.curveHelper.dh(keyPair: keyPair, publicKey: remotePublicKey)
    try self.symmetricState.mixKey(inputKeyMaterial: dh)
    return messageBuffer
  }

  // For "ss": Calls MixKey(DH(s, rs)).
  private func readSS(_ messageBuffer: Data) throws -> Data {
    let s = try self.getKeyPair(key: .s)
    let rs = try self.getPublicKey(own: false, key: .s)
    let dh = try self.curveHelper.dh(keyPair: s, publicKey: rs)
    try self.symmetricState.mixKey(inputKeyMaterial: dh)
    return messageBuffer
  }

  private func dispatchReadToken(_ messageBuffer: Data, token: Token) throws -> Data {
    switch token {
    case .e:
      return try self.readE(messageBuffer)
    case .s:
      return try self.readS(messageBuffer)
    case .ee:
      return try self.readEE(messageBuffer)
    case .es:
      return try self.readES(messageBuffer)
    case .se:
      return try self.readSE(messageBuffer)
    case .ss:
      return try self.readSS(messageBuffer)
    default:
      throw HandshakeStateError.invalidMessagePattern
    }
  }
}

extension HandshakeState {

  public func writeMessage(payload: Data) throws -> Data {
    if self.messagePatterns.count == 0 {
      throw HandshakeStateError.completedHandshake
    }
    var out: [Data] = []
    let messagePattern = self.messagePatterns[0]
    self.messagePatterns.removeFirst(1)

    // Fetches and deletes the next message pattern from message_patterns, then sequentially
    // processes each token from the message pattern:
    for token in messagePattern {
      out.append(try self.dispatchWriteToken(token: token))
    }
    // Appends EncryptAndHash(payload) to the buffer.
    out.append(try self.symmetricState.encryptAndHash(plaintext: payload))

    // If there are no more message patterns returns two new CipherState objects by calling Split().
    return Data(out.joined())
  }

  public func readMessage(message: Data) throws -> Data {
    if self.messagePatterns.count == 0 {
      throw HandshakeStateError.completedHandshake
    }
    var messageBuffer = message
    let messagePattern = self.messagePatterns[0]
    self.messagePatterns.removeFirst(1)

    // Fetches and deletes the next message pattern from message_patterns, then sequentially
    // processes each token from the message pattern:
    for token in messagePattern {
      messageBuffer = try self.dispatchReadToken(messageBuffer, token: token)
    }
    // Calls DecryptAndHash() on the remaining bytes of the message and stores the output into
    // payload_buffer.
    // If there are no more message patterns returns two new CipherState objects by calling Split().
    return try self.symmetricState.decryptAndHash(ciphertext: messageBuffer)
  }

  public func getHandshakeHash() -> Data {
    return self.symmetricState.getHandshakeHash()
  }

  public func split() throws -> (CipherState, CipherState) {
    if self.messagePatterns.count > 0 {
      throw HandshakeStateError.incompleteHandshake
    }
    return try self.symmetricState.split()
  }
}
