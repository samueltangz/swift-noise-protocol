import Foundation
import Crypto

// https://noiseprotocol.org/noise.html#the-symmetricstate-object
public class SymmetricState {
  // ck: A chaining key of HASHLEN bytes.
  private var ck: Data
  // h: A hash output of HASHLEN bytes.
  private var h: Data
  var cipherState: CipherState

  private let hashFunction: Hash
  private let cipher: Cipher

  init(protocolName: String) throws {
    let components = try protocolComponents(name: protocolName)

    self.cipher = components.cipher
    self.hashFunction = components.hash

    // If protocol_name is less than or equal to HASHLEN bytes in length,
    // sets h equal to protocol_name with zero bytes appended to make HASHLEN bytes.
    // Otherwise sets h = HASH(protocol_name).
    let h = Data(protocolName.utf8)
    if h.count <= components.hash.hashlen {
      self.h = h + Data(repeating: 0, count: components.hash.hashlen - h.count)
    } else {
      self.h = self.hashFunction.hash(data: h)
    }
    // Sets ck = h.
    self.ck = self.h

    // Calls InitializeKey(empty).
    self.cipherState = try CipherState(cipher: self.cipher)
  }

  func mixKey(inputKeyMaterial: Data) throws {
    // Sets ck, temp_k = HKDF(ck, input_key_material, 2).
    let hkdfOutput = try self.hashFunction.hkdf(chainingKey: self.ck, inputKeyMaterial: inputKeyMaterial, numOutputs: 2)
    self.ck = hkdfOutput[0]

    var tempK = hkdfOutput[1]

    // If HASHLEN is 64, then truncates temp_k to 32 bytes.
    if self.hashFunction.hashlen == 64 {
      tempK = tempK.prefix(32)
    }

    // Calls InitializeKey(temp_k).
    self.cipherState = try CipherState(key: tempK, cipher: self.cipher)
  }

  func mixHash(data: Data) {
    // Sets h = HASH(h || data)
    self.h = self.hashFunction.hash(data: self.h + data)
  }

  func mixKeyAndHash(inputKeyMaterial: Data) throws {
    // Sets ck, temp_h, temp_k = HKDF(ck, input_key_material, 3).
    let hkdfOutput = try self.hashFunction.hkdf(chainingKey: self.ck, inputKeyMaterial: inputKeyMaterial, numOutputs: 3)
    self.ck = hkdfOutput[0]
    let tempH = hkdfOutput[1]

    // Calls MixHash(temp_h).
    self.mixHash(data: tempH)

    var tempK = hkdfOutput[2]

    // If HASHLEN is 64, then truncates temp_k to 32 bytes.
    if self.hashFunction.hashlen == 64 {
      tempK = tempK.prefix(32)
    }

    // Calls InitializeKey(temp_k).
    self.cipherState = try CipherState(key: tempK, cipher: self.cipher)
  }

  func getHandshakeHash() -> Data {
    // Returns h.
    return self.h
  }

  func encryptAndHash(plaintext: Data) throws -> Data {
    // Sets ciphertext = EncryptWithAd(h, plaintext), calls MixHash(ciphertext), and returns ciphertext.
    // Note that if k is empty, the EncryptWithAd() call will set ciphertext equal to plaintext.
    let ciphertext = try self.cipherState.encrypt(plaintext: plaintext, with: self.h)
    self.mixHash(data: ciphertext)
    return ciphertext
  }

  func decryptAndHash(ciphertext: Data) throws -> Data {
    // Sets plaintext = DecryptWithAd(h, ciphertext), calls MixHash(ciphertext), and returns plaintext.
    // Note that if k is empty, the DecryptWithAd() call will set plaintext equal to ciphertext.
    let plaintext = try self.cipherState.decrypt(ciphertext: ciphertext, with: self.h)
    self.mixHash(data: ciphertext)
    return plaintext
  }

  func split() throws -> (CipherState, CipherState) {
    // Sets temp_k1, temp_k2 = HKDF(ck, zerolen, 2).
    let tempKs = try self.hashFunction.hkdf(chainingKey: self.ck, inputKeyMaterial: Data(), numOutputs: 2)

    var tempK1 = tempKs[0]
    var tempK2 = tempKs[1]

    // If HASHLEN is 64, then truncates temp_k1 and temp_k2 to 32 bytes.
    if self.hashFunction.hashlen == 64 {
      tempK1 = tempK1.prefix(32)
      tempK2 = tempK2.prefix(32)
    }

    // Creates two new CipherState objects c1 and c2.
    // Calls c1.InitializeKey(temp_k1) and c2.InitializeKey(temp_k2).
    let c1 = try CipherState(key: tempK1, cipher: self.cipher)
    let c2 = try CipherState(key: tempK2, cipher: self.cipher)

    // Returns the pair (c1, c2).
    return (c1, c2)
  }
}
