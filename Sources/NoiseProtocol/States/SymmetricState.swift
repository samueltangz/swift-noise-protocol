import CryptoSwift

// https://noiseprotocol.org/noise.html#the-symmetricstate-object
public class SymmetricState {
  // ck: A chaining key of HASHLEN bytes.
  var ck: [UInt8]
  // h: A hash output of HASHLEN bytes.
  var h: [UInt8]
  var cipherState: CipherState

  init(protocolName: String) {
    // TODO: this

    // If protocol_name is less than or equal to HASHLEN bytes in length,
    // sets h equal to protocol_name with zero bytes appended to make HASHLEN bytes.
    // Otherwise sets h = HASH(protocol_name).
    self.h = Digest.sha256(Array(protocolName.utf8))
    // Sets ck = h.
    self.ck = self.h
    // Calls InitializeKey(empty).
    self.cipherState = try! CipherState()
  }
  func mixKey(inputKeyMaterial: [UInt8]) {
    // Sets ck, temp_k = HKDF(ck, input_key_material, 2).
    let (ck, tempK) = try! hkdf2(chainingKey: self.ck, inputKeyMaterial: inputKeyMaterial)
    self.ck = ck

    // If HASHLEN is 64, then truncates temp_k to 32 bytes.

    // Calls InitializeKey(temp_k).
    self.cipherState = try! CipherState(key: tempK)
  }
  func mixHash(data: [UInt8]) {
    // Sets h = HASH(h || data)
    self.h = Digest.sha256(self.h + data)
  }
  func mixKeyAndHash(inputKeyMaterial: [UInt8]) {
    // Sets ck, temp_h, temp_k = HKDF(ck, input_key_material, 3).
    let (ck, tempH, tempK) = try! hkdf3(chainingKey: self.ck, inputKeyMaterial: inputKeyMaterial)

    // Calls MixHash(temp_h).
    mixHash(data: tempH)

    // If HASHLEN is 64, then truncates temp_k to 32 bytes.

    // Calls InitializeKey(temp_k).
    self.cipherState = try! CipherState(key: tempK)
  }
  func getHandshakeHash() -> [UInt8] {
    // Returns h.
    return self.h
  }
  func encryptAndHash(plaintext: [UInt8]) -> [UInt8] {
    // Sets ciphertext = EncryptWithAd(h, plaintext), calls MixHash(ciphertext), and returns ciphertext.
    // Note that if k is empty, the EncryptWithAd() call will set ciphertext equal to plaintext.
    return self.cipherState.encryptWithAd(ad: self.h, plaintext: plaintext)
  }
  func decryptAndHash(ciphertext: [UInt8]) -> [UInt8] {
    // Sets plaintext = DecryptWithAd(h, ciphertext), calls MixHash(ciphertext), and returns plaintext.
    // Note that if k is empty, the DecryptWithAd() call will set plaintext equal to ciphertext.
    return self.cipherState.decryptWithAd(ad: self.h, ciphertext: ciphertext)
  }
  func split() -> (CipherState, CipherState) {
    // Sets temp_k1, temp_k2 = HKDF(ck, zerolen, 2).
    let (tempK1, tempK2) = try! hkdf2(chainingKey: self.ck, inputKeyMaterial: [])

    // If HASHLEN is 64, then truncates temp_k1 and temp_k2 to 32 bytes.

    // Creates two new CipherState objects c1 and c2.
    // Calls c1.InitializeKey(temp_k1) and c2.InitializeKey(temp_k2).
    let c1 = try! CipherState(key: tempK1)
    let c2 = try! CipherState(key: tempK2)

    // Returns the pair (c1, c2).
    return (c1, c2)
  }
}