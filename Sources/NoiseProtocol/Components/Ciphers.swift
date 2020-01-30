// https://noiseprotocol.org/noise.html#cipher-functions
protocol Cipher {
  // Encrypts plaintext using the cipher key k of 32 bytes and an 8-byte unsigned integer nonce n
  // which must be unique for the key k. Returns the ciphertext. Encryption must be done with an
  // "AEAD" encryption mode with the associated data ad (using the terminology from [1]) and
  // returns a ciphertext that is the same size as the plaintext plus 16 bytes for authentication
  // data. The entire ciphertext must be indistinguishable from random if the key is secret (note
  // that this is an additional requirement that isn't necessarily met by all AEAD schemes).
  func Encrypt(k: [UInt8], n: [UInt8], ad: [UInt8], plaintext: [UInt8]) -> [UInt8]

  // Decrypts ciphertext using a cipher key k of 32 bytes, an 8-byte unsigned integer nonce n, and
  // associated data ad. Returns the plaintext, unless authentication fails, in which case an error
  // is signaled to the caller.
  func Decrypt(k: [UInt8], n: [UInt8], ad: [UInt8], ciphertext: [UInt8]) -> [UInt8]

  // Returns a new 32-byte cipher key as a pseudorandom function of k. If this function is not
  // specifically defined for some set of cipher functions, then it defaults to returning the first
  // 32 bytes from ENCRYPT(k, maxnonce, zerolen, zeros), where maxnonce equals 2^64-1, zerolen is a
  // zero-length byte sequence, and zeros is a sequence of 32 bytes filled with zeros.
  func Rekey(k: [UInt8]) -> [UInt8]
}