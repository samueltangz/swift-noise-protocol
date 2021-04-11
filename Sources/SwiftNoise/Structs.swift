import Foundation

public typealias PublicKey = Data
public typealias SecretKey = Data

public struct KeyPair {
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
public enum HandshakePattern: String {
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
