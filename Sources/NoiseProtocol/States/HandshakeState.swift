public enum HandshakePattern {
  case KK
}

// https://noiseprotocol.org/noise.html#the-handshakestate-object
public class HandshakeState {
  public init(pattern: HandshakePattern, initiator: Bool, prologue: [UInt8] = [], s: KeyPair? = nil, e: KeyPair? = nil, rs: PublicKey? = nil, re: PublicKey? = nil) {}
  public func writeMessage(payload: [UInt8]) -> [UInt8] {
    return []
  }
  public func readMessage(message: [UInt8]) -> [UInt8] {
    return []
  }
  public func split() -> (CipherState, CipherState) {
    return (CipherState(), CipherState())
  }
}
