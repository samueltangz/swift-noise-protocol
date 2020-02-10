import Foundation
import Crypto

// https://noiseprotocol.org/noise.html#hash-functions
protocol Hash {
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

// An extension on CryptoKit's SHA256.Digest to return Data
extension SHA256.Digest {
  var bytes: [UInt8] { Array(self.makeIterator()) }
  var data: Data { Data(self.bytes) }
}

// An extension on CryptoKit's SharedSecret to return Data
extension HashedAuthenticationCode {
  var bytes: [UInt8] { Array(self.makeIterator()) }
  var data: Data { Data(self.bytes) }
}


class S256: Hash {
  func hash(data: Data) -> Data {
    let digest = SHA256.hash(data: data)
    return digest.data
  }

  func hmac(key: Data, data: Data) -> Data {
    let h = HMAC<SHA256>.authenticationCode(for: data, using: SymmetricKey(data: key))
    return h.data
  }

  func hkdf(chainingKey: Data, inputKeyMaterial: Data, numOutputs: UInt8) throws -> [Data] {
    if numOutputs < 2 {
      throw HashError.tooLittleOutputs
    }
    if numOutputs > 3 {
      throw HashError.tooManyOutputs
    }
    let tempKey = self.hmac(key: chainingKey, data: inputKeyMaterial)
    var lastOutput: Data = Data()
    var outputs: [Data] = []
    for index in 1...numOutputs {
      lastOutput = self.hmac(key: tempKey, data: lastOutput + [index])
      outputs.append(lastOutput)
    }
    return outputs
  }

  var hashlen: Int = 32
  var blocklen: Int = 64
}
