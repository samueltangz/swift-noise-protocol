import Foundation

public typealias PublicKey = Data
public typealias SecretKey = Data

public struct KeyPair {
  public var publicKey: PublicKey
  public var secretKey: SecretKey
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