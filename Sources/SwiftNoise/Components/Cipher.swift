import Foundation
import Crypto

// https://noiseprotocol.org/noise.html#cipher-functions
public protocol Cipher {
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

public enum Ciphers {
  public static func cipher(named name: String) -> Cipher? {
    switch name {
    case "AESGCM":
      return Ciphers.AESGCM()
    default:
      return nil
    }
  }
}

extension Ciphers {
  struct AESGCM: Cipher {

    // A helper method to convert Nonce (which is a 64-bit unsigned integer) to Data.
    func nonceToData(n: Nonce) -> Data {
      var be = CFSwapInt64HostToBig(n)
      let data = Data(bytes: &be, count: MemoryLayout<UInt64>.size)

      let padding = Data(repeating: 0, count: 4)
      return padding + data
    }

    func encrypt(k: Data, n: Nonce, ad: Data, plaintext: Data) throws -> Data {
      let key = SymmetricKey(data: k)
      let nonce = try AES.GCM.Nonce(data: nonceToData(n: n))
      let box = try AES.GCM.seal(plaintext, using: key, nonce: nonce, authenticating: ad)

      return box.ciphertext + box.tag
    }

    func decrypt(k: Data, n: Nonce, ad: Data, ciphertext: Data) throws -> Data {
      let key = SymmetricKey(data: k)
      let nonce = try AES.GCM.Nonce(data: nonceToData(n: n))

      let ctext = ciphertext.prefix(ciphertext.count - 16)
      let tag = ciphertext.suffix(16)

      let box = try AES.GCM.SealedBox(nonce: nonce, ciphertext: ctext, tag: tag)

      return try AES.GCM.open(box, using: key, authenticating: ad)
    }

    func rekey(k: Data) throws -> Data {
      return try self.encrypt(k: k, n: 0xffffffffffffffff, ad: Data(), plaintext: Data(repeating: 0, count: 32))
    }
  }

}
