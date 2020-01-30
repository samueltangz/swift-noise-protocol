enum CipherStateError: Error {
  case invalidKeySize
}

// https://noiseprotocol.org/noise.html#the-cipherstate-object
public class CipherState {
  var k: [UInt8]? = nil
  var n: Nonce
  init(key: [UInt8]) throws {
    if key.count != 32 {
      throw CipherStateError.invalidKeySize
    }
    self.k = key
    self.n = 0
  }
  func hasKey() -> Bool {
    return k != nil
  }
  func getKey() -> [UInt8] {
    return self.k!
  }
  func setNonce(nonce: Nonce) {
    self.n = nonce
  }
  func encryptWithAd(ad: [UInt8], plaintext: [UInt8]) -> [UInt8] {
    if !self.hasKey() {
      return plaintext
    }
    // TODO: return ENCRYPT(k, n++, ad, plaintext)
    let ciphertext = try! encrypt(k: self.getKey(), n: self.n, ad: ad, plaintext: plaintext)
    try! self.n.increment()
    return ciphertext
  }
  func decryptWithAd(ad: [UInt8], ciphertext: [UInt8]) -> [UInt8] {
    if !self.hasKey() {
      return ciphertext
    }
    // TODO: return DECRYPT(k, n++, ad, ciphertext)
    let plaintext = try! decrypt(k: self.getKey(), n: self.n, ad: ad, ciphertextWithTag: ciphertext)
    try! self.n.increment()
    return plaintext
  }
  func rekey() {
    // TODO: self.k = REKEY(self.k)
  }
}