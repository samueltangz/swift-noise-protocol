import Foundation
import CryptoSwift

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
  func hkdf2(chainingKey: Data, inputKeyMaterial: Data) throws -> (Data, Data)
  func hkdf3(chainingKey: Data, inputKeyMaterial: Data) throws -> (Data, Data, Data)

  // = A constant specifying the size in bytes of the hash output. Must be 32 or 64.
  var hashlen: Int { get }

  // = A constant specifying the size in bytes that the hash function uses internally to divide its
  // input for iterative processing. This is needed to use the hash function with HMAC (BLOCKLEN is
  // B in [3]).
  var blocklen: Int { get }
}

class SHA256: Hash {
  func hash(data: Data) -> Data {
    return Data(Digest.sha256(data.bytes))
  }

  func hmac(key: Data, data: Data) throws -> Data {
    return Data(try HMAC(key: key.bytes, variant: .sha256).authenticate(data.bytes))
  }

  func hkdf2(chainingKey: Data, inputKeyMaterial: Data) throws -> (Data, Data) {
    let tempKey = Data(try self.hmac(key: chainingKey, data: inputKeyMaterial))
    let output1 = Data(try self.hmac(key: tempKey, data: Data([1])))
    let output2 = Data(try self.hmac(key: tempKey, data: Data(output1 + [2])))
    return (output1, output2)
  }

  func hkdf3(chainingKey: Data, inputKeyMaterial: Data) throws -> (Data, Data, Data) {
    let tempKey = Data(try self.hmac(key: chainingKey, data: inputKeyMaterial))
    let output1 = Data(try self.hmac(key: tempKey, data: Data([1])))
    let output2 = Data(try self.hmac(key: tempKey, data: Data(output1 + [2])))
    let output3 = Data(try self.hmac(key: tempKey, data: Data(output2 + [3])))
    return (output1, output2, output3)
  }

  var hashlen: Int = 32
  var blocklen: Int = 64
}