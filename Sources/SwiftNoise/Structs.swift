import Foundation

public typealias PublicKey = Data
public typealias SecretKey = Data

public struct KeyPair: Codable {
  public let publicKey: PublicKey
  public let secretKey: SecretKey
}

public typealias Nonce = UInt64

extension Nonce {
  mutating func increment() throws {
    if self == 0xffffffff {
      throw NonceError.nonceOverflow
    }
    self += 1
  }
}

// Enumerates the handshake patterns.
public enum HandshakePattern: String, CaseIterable {
  case N
  case K
  case X
  case NN
  case NK
  case NX
  case KN
  case KK
  case KX
  case XN
  case XK
  case XX
  case IN
  case IK
  case IX
}

// Enumerates the handshake tokens.
public enum Token {
  case s
  case e
  case es
  case se
  case ee
  case ss
  case psk
}

// Defines the structure of the pattern details.
struct PatternDetails {
  var initiatorPremessages: [Token]
  var responderPremessages: [Token]
  var messagePatterns: [[Token]]
}

// Enumerates the pattern details.
let patterns: [HandshakePattern: PatternDetails] = [
  .N: PatternDetails(
    initiatorPremessages: [],
    responderPremessages: [.s],
    messagePatterns: [
      [.e, .es]
    ]
  ),
  .K: PatternDetails(
    initiatorPremessages: [.s],
    responderPremessages: [.s],
    messagePatterns: [
      [.e, .es, .ss]
    ]
  ),
  .X: PatternDetails(
    initiatorPremessages: [],
    responderPremessages: [.s],
    messagePatterns: [
      [.e, .es, .s, .ss]
    ]
  ),
  .NN: PatternDetails(
    initiatorPremessages: [],
    responderPremessages: [],
    messagePatterns: [
      [.e],
      [.e, .ee],
    ]
  ),
  .NK: PatternDetails(
    initiatorPremessages: [],
    responderPremessages: [.s],
    messagePatterns: [
      [.e, .es],
      [.e, .ee],
    ]
  ),
  .NX: PatternDetails(
    initiatorPremessages: [],
    responderPremessages: [],
    messagePatterns: [
      [.e],
      [.e, .ee, .s, .es],
    ]
  ),
  .KN: PatternDetails(
    initiatorPremessages: [.s],
    responderPremessages: [],
    messagePatterns: [
      [.e],
      [.e, .ee, .se],
    ]
  ),
  .KK: PatternDetails(
    initiatorPremessages: [.s],
    responderPremessages: [.s],
    messagePatterns: [
      [.e, .es, .ss],
      [.e, .ee, .se],
    ]
  ),
  .KX: PatternDetails(
    initiatorPremessages: [.s],
    responderPremessages: [],
    messagePatterns: [
      [.e],
      [.e, .ee, .se, .s, .es],
    ]
  ),
  .XN: PatternDetails(
    initiatorPremessages: [],
    responderPremessages: [],
    messagePatterns: [
      [.e],
      [.e, .ee],
      [.s, .se],
    ]
  ),
  .XK: PatternDetails(
    initiatorPremessages: [],
    responderPremessages: [.s],
    messagePatterns: [
      [.e, .es],
      [.e, .ee],
      [.s, .se],
    ]
  ),
  .XX: PatternDetails(
    initiatorPremessages: [],
    responderPremessages: [],
    messagePatterns: [
      [.e],
      [.e, .ee, .s, .es],
      [.s, .se],
    ]
  ),
  .IN: PatternDetails(
    initiatorPremessages: [],
    responderPremessages: [],
    messagePatterns: [
      [.e, .s],
      [.e, .ee, .se],
    ]
  ),
  .IK: PatternDetails(
    initiatorPremessages: [],
    responderPremessages: [.s],
    messagePatterns: [
      [.e, .es, .s, .ss],
      [.e, .ee, .se],
    ]
  ),
  .IX: PatternDetails(
    initiatorPremessages: [],
    responderPremessages: [],
    messagePatterns: [
      [.e, .s],
      [.e, .ee, .se, .s, .es],
    ]
  ),
]

public struct NoiseCipherSuite {

  public let dh: DHFunction
  public let cipher: Cipher
  public let hash: Hash

  public init(dh: DHFunction, cipher: Cipher, hash: Hash) {
    self.dh = dh
    self.cipher = cipher
    self.hash = hash
  }

}

public struct NoiseProtocol {

  public let handshake: HandshakePattern
  public let cipherSuite: NoiseCipherSuite

  public var name: String {
    let handshake = self.handshake.rawValue
    let dhFunction = type(of: self.cipherSuite.dh).identifier
    let cipherFunction = type(of: self.cipherSuite.cipher).identifier
    let hashFunction = type(of: self.cipherSuite.hash).identifier

    return "Noise_\(handshake)_\(dhFunction)_\(cipherFunction)_\(hashFunction)"
  }

  public init(name: String) throws {
    let components = try protocolComponents(name: name)

    self.handshake = components.handshake
    self.cipherSuite = NoiseCipherSuite(dh: components.dh, cipher: components.cipher, hash: components.hash)
  }

}

public func protocolComponents(name: String) throws -> (handshake: HandshakePattern, dh: DHFunction, cipher: Cipher, hash: Hash) {
  let components = name.components(separatedBy: "_")

  guard components.count == 5 else {
    throw ProtocolError.invalid
  }

  guard let handshake = HandshakePattern(rawValue: components[1]) else {
    throw ProtocolError.unsupported
  }

  guard let dhFunction = DHFunctions.dhFunction(named: components[2]) else {
    throw ProtocolError.unsupported
  }

  guard let cipher = Ciphers.cipher(named: components[3]) else {
    throw ProtocolError.unsupported
  }

  guard let hash = Hashes.hash(named: components[4]) else {
    throw ProtocolError.unsupported
  }

  return (handshake: handshake, dh: dhFunction, cipher: cipher, hash: hash)
}
