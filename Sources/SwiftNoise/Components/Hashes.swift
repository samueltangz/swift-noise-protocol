import Foundation
import CryptoSwift

// https://noiseprotocol.org/noise.html#hash-functions
protocol Hash {
  // Hashes some arbitrary-length data with a collision-resistant cryptographic hash function and
  // returns an output of HASHLEN bytes.
  func hash(data: Data) -> Data

  // = A constant specifying the size in bytes of the hash output. Must be 32 or 64.
  var hashlen: Int { get }

  // = A constant specifying the size in bytes that the hash function uses internally to divide its
  // input for iterative processing. This is needed to use the hash function with HMAC (BLOCKLEN is
  // B in [3]).
  var blocklen: Int { get }

  // TODO: HMAC-HASH, HKDF
}

class SHA256: Hash {
  func hash(data: Data) -> Data {
    return Data(Digest.sha256(data.bytes))
  }
  var hashlen: Int = 32
  var blocklen: Int = 64
}