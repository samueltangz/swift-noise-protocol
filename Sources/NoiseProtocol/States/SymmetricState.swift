// https://noiseprotocol.org/noise.html#the-symmetricstate-object
public class SymmetricState {
  init(protocolName: String) {}
  func mixKey(inputKeyMaterial: [UInt8]) {}
  func mixHash(data: [UInt8]) {}
  func mixKeyAndHash(inputKeyMaterial: [UInt8]) {}
  func getHandshakeHash() -> [UInt8] {
    return []
  }
  func encryptAndHash(plaintext: [UInt8]) -> [UInt8] {
    return []
  }
  func DecryptAndHash(ciphertext: [UInt8]) -> [UInt8] {
    return []
  }
  func Split() -> CipherState {
    return CipherState()
  }
}