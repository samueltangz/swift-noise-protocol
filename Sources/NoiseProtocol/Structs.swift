import Sodium

public typealias PublicKey = Box.KeyPair.PublicKey
public typealias KeyPair = Box.KeyPair

enum NonceError: Error {
  case nonceOverflow
}

public typealias Nonce = UInt64

extension Nonce {
  mutating func increment() throws {
    if self == 0xffffffff {
      throw NonceError.nonceOverflow
    }
    self = self+1
  }
}