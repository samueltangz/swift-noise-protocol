import Foundation
import Crypto

// https://noiseprotocol.org/noise.html#hash-functions
public protocol Hash {
  static var identifier: String { get }

  // Hashes some arbitrary-length data with a collision-resistant cryptographic hash function and
  // returns an output of HASHLEN bytes.
  func hash(data: Data) -> Data

  // Applies HMAC from [3] using the HASH() function. This function is only called as part of
  // HKDF().
  func hmac(key: Data, data: Data) throws -> Data

  // Takes a chaining_key byte sequence of length HASHLEN, and an input_key_material byte sequence
  // with length either zero bytes, 32 bytes, or DHLEN bytes. Returns a pair or triple of byte
  // sequences each of length HASHLEN, depending on whether num_outputs is two or three.
  func hkdf(chainingKey: Data, inputKeyMaterial: Data, numOutputs: UInt8) throws -> [Data]

  // = A constant specifying the size in bytes of the hash output. Must be 32 or 64.
  var hashlen: Int { get }

  // = A constant specifying the size in bytes that the hash function uses internally to divide its
  // input for iterative processing. This is needed to use the hash function with HMAC (BLOCKLEN is
  // B in [3]).
  var blocklen: Int { get }
}

public enum Hashes {
  public static let supported = [SHA256.identifier, SHA512.identifier]

  public static func hash(named name: String) -> Hash? {
    switch name {
    case SHA256.identifier:
      return Hashes.SHA256()
    case SHA512.identifier:
      return Hashes.SHA512()
    default:
      return nil
    }
  }
}

extension Hashes {
  struct SHA256: Hash {
    static let identifier: String = "SHA256"

    func hash(data: Data) -> Data {
      return Data(Crypto.SHA256.hash(data: data))
    }

    func hmac(key: Data, data: Data) throws -> Data {
      let key = SymmetricKey(data: key)
      let hmac = Crypto.HMAC<Crypto.SHA256>.authenticationCode(for: data, using: key)
      return Data(hmac)
    }

    func hkdf(chainingKey: Data, inputKeyMaterial: Data, numOutputs: UInt8) throws -> [Data] {
      if numOutputs < 2 {
        throw HashError.tooLittleOutputs
      }
      if numOutputs > 3 {
        throw HashError.tooManyOutputs
      }
      let tempKey = Data(try self.hmac(key: chainingKey, data: inputKeyMaterial))
      var lastOutput: Data = Data()
      var outputs: [Data] = []
      for index in 1...numOutputs {
        lastOutput = Data(try self.hmac(key: tempKey, data: lastOutput + [index]))
        outputs.append(lastOutput)
      }
      return outputs
    }

    let hashlen: Int = 32
    let blocklen: Int = 64
  }
}

extension Hashes {
  struct SHA512: Hash {
    static let identifier: String = "SHA512"

    func hash(data: Data) -> Data {
      return Data(Crypto.SHA512.hash(data: data))
    }

    func hmac(key: Data, data: Data) throws -> Data {
      let key = SymmetricKey(data: key)
      let hmac = Crypto.HMAC<Crypto.SHA512>.authenticationCode(for: data, using: key)
      return Data(hmac)
    }

    func hkdf(chainingKey: Data, inputKeyMaterial: Data, numOutputs: UInt8) throws -> [Data] {
      if numOutputs < 2 {
        throw HashError.tooLittleOutputs
      }
      if numOutputs > 3 {
        throw HashError.tooManyOutputs
      }
      let tempKey = Data(try self.hmac(key: chainingKey, data: inputKeyMaterial))
      var lastOutput: Data = Data()
      var outputs: [Data] = []
      for index in 1...numOutputs {
        lastOutput = Data(try self.hmac(key: tempKey, data: lastOutput + [index]))
        outputs.append(lastOutput)
      }
      return outputs
    }

    let hashlen: Int = 64
    let blocklen: Int = 128
  }
}
