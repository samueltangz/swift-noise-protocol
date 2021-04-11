import Foundation
import Crypto

// https://noiseprotocol.org/noise.html#cipher-functions
public protocol Cipher {
  static var identifier: String { get }

  // Encrypts plaintext using the cipher key k of 32 bytes and an 8-byte unsigned integer nonce n
  // which must be unique for the key k. Returns the ciphertext. Encryption must be done with an
  // "AEAD" encryption mode with the associated data ad (using the terminology from [1]) and
  // returns a ciphertext that is the same size as the plaintext plus 16 bytes for authentication
  // data. The entire ciphertext must be indistinguishable from random if the key is secret (note
  // that this is an additional requirement that isn't necessarily met by all AEAD schemes).
  func encrypt(k: Data, n: Nonce, ad: Data, plaintext: Data) throws -> Data

  // Decrypts ciphertext using a cipher key k of 32 bytes, an 8-byte unsigned integer nonce n, and
  // associated data ad. Returns the plaintext, unless authentication fails, in which case an error
  // is signaled to the caller.
  func decrypt(k: Data, n: Nonce, ad: Data, ciphertext: Data) throws -> Data

  // Returns a new 32-byte cipher key as a pseudorandom function of k. If this function is not
  // specifically defined for some set of cipher functions, then it defaults to returning the first
  // 32 bytes from ENCRYPT(k, maxnonce, zerolen, zeros), where maxnonce equals 2^64-1, zerolen is a
  // zero-length byte sequence, and zeros is a sequence of 32 bytes filled with zeros.
  func rekey(k: Data) throws -> Data
}

extension Cipher {
  func rekey(k: Data) throws -> Data {
    return try self.encrypt(k: k, n: 0xffffffffffffffff, ad: Data(), plaintext: Data(repeating: 0, count: 32))
  }
}

// A helper method to convert Nonce (which is a 64-bit unsigned integer) to Data.
func nonceToDataBig(n: Nonce) -> Data {
  var be = CFSwapInt64HostToBig(n)
  let data = Data(bytes: &be, count: MemoryLayout<UInt64>.size)

  let padding = Data(repeating: 0, count: 4)
  return padding + data
}

func nonceToDataLittle(n: Nonce) -> Data {
  var be = CFSwapInt64HostToLittle(n)
  let data = Data(bytes: &be, count: MemoryLayout<UInt64>.size)

  let padding = Data(repeating: 0, count: 4)
  return padding + data
}

public enum Ciphers {
  public static let supported = [AESGCM.identifier, ChaChaPoly.identifier]

  public static func cipher(named name: String) -> Cipher? {
    switch name {
    case AESGCM.identifier:
      return Ciphers.AESGCM()
    case ChaChaPoly.identifier:
      return Ciphers.ChaChaPoly()
    default:
      return nil
    }
  }
}

extension Ciphers {
  struct AESGCM: Cipher {
    static let identifier: String = "AESGCM"

    // https://github.com/apple/swift-crypto/blob/3bea268b223651c4ab7b7b9ad62ef9b2d4143eb6/Sources/Crypto/AEADs/AES/GCM/AES-GCM.swift#L29
    static let tagByteCount = 16

    func encrypt(k: Data, n: Nonce, ad: Data, plaintext: Data) throws -> Data {
      let key = SymmetricKey(data: k)
      let nonce = try AES.GCM.Nonce(data: nonceToDataBig(n: n))

      let box = try AES.GCM.seal(plaintext, using: key, nonce: nonce, authenticating: ad)
      return box.ciphertext + box.tag
    }

    func decrypt(k: Data, n: Nonce, ad: Data, ciphertext: Data) throws -> Data {
      let key = SymmetricKey(data: k)
      let nonce = try AES.GCM.Nonce(data: nonceToDataBig(n: n))
      let box = try AES.GCM.SealedBox(combined: nonce + ciphertext)

      return try AES.GCM.open(box, using: key, authenticating: ad)
    }
  }

}

extension Ciphers {
  struct ChaChaPoly: Cipher {
    static let identifier: String = "ChaChaPoly"

    // https://github.com/apple/swift-crypto/blob/3bea268b223651c4ab7b7b9ad62ef9b2d4143eb6/Sources/Crypto/AEADs/ChachaPoly/ChaChaPoly.swift#L28
    static let tagByteCount = 16

    func encrypt(k: Data, n: Nonce, ad: Data, plaintext: Data) throws -> Data {
      let key = SymmetricKey(data: k)
      let nonce = try Crypto.ChaChaPoly.Nonce(data: nonceToDataLittle(n: n))

      let box = try Crypto.ChaChaPoly.seal(plaintext, using: key, nonce: nonce, authenticating: ad)
      return box.ciphertext + box.tag
    }

    func decrypt(k: Data, n: Nonce, ad: Data, ciphertext: Data) throws -> Data {
      let key = SymmetricKey(data: k)
      let nonce = try Crypto.ChaChaPoly.Nonce(data: nonceToDataLittle(n: n))
      let box = try Crypto.ChaChaPoly.SealedBox(combined: nonce + ciphertext)

      return try Crypto.ChaChaPoly.open(box, using: key, authenticating: ad)
    }
  }
}
