// https://noiseprotocol.org/noise.html#the-cipherstate-object
public class CipherState {
  var k: [UInt8] = []
  var n: [UInt8] = []
  init() {}
  func hasKey() -> Bool {
    return true
  }
  func setNonce(nonce: [UInt8]) {}
  func encryptWithAd(ad: [UInt8], plaintext: [UInt8]) -> [UInt8] {
    return []
  }
  func decryptWithAd(ad: [UInt8], ciphertext: [UInt8]) -> [UInt8] {
    return []
  }
  func rekey() {}
}