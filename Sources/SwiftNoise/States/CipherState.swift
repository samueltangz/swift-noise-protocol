import Foundation

// https://noiseprotocol.org/noise.html#the-cipherstate-object
public class CipherState {
  // k: A cipher key of 32 bytes (which may be empty). Empty is a special value which indicates k
  // has not yet been initialized.
  var k: Data?
  // n: An 8-byte (64-bit) unsigned integer nonce.
  var n: Nonce

  var cipherHelper: Cipher

  init(key: Data? = nil) throws {
    if key != nil && key!.count != 32 {
      throw CipherStateError.invalidKeySize
    }
    // Sets k = key.
    self.k = key
    // Sets n = 0.
    self.n = 0

    self.cipherHelper = AESGCM()
  }
  func hasKey() -> Bool {
    // Returns true if k is non-empty, false otherwise.
    return k != nil
  }
  func setNonce(nonce: Nonce) {
    // Sets n = nonce.
    self.n = nonce
  }
  public func encryptWithAd(ad: Data, plaintext: Data) throws -> Data {
    // If k is non-empty returns ENCRYPT(k, n++, ad, plaintext). Otherwise returns plaintext.
    if !self.hasKey() {
      return plaintext
    }
    let ciphertext = try self.cipherHelper.encrypt(k: self.k!, n: self.n, ad: ad, plaintext: plaintext)
    try self.n.increment()
    return ciphertext
  }
  public func decryptWithAd(ad: Data, ciphertext: Data) throws -> Data {
    // If k is non-empty returns DECRYPT(k, n++, ad, ciphertext). Otherwise returns ciphertext. If
    // an authentication failure occurs in DECRYPT() then n is not incremented and an error is
    // signaled to the caller.
    if !self.hasKey() {
      return ciphertext
    }
    let plaintext = try self.cipherHelper.decrypt(k: self.k!, n: self.n, ad: ad, ciphertext: ciphertext)
    try self.n.increment()
    return plaintext
  }
  func rekey() throws {
    // Sets k = REKEY(k).
    self.k = try self.cipherHelper.rekey(k: self.k!)
  }
}
