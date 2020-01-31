import Sodium

public func generateKeyPair() -> KeyPair {
  let sodium = Sodium()
  return sodium.box.keyPair()!
}

public func diffieHellman(keyPair: KeyPair, publicKey: PublicKey) -> [UInt8] {
  let sodium = Sodium()
  return sodium.box.beforenm(recipientPublicKey: publicKey, senderSecretKey: keyPair.secretKey)!
}

import CryptoSwift

func hkdf2(chainingKey: [UInt8], inputKeyMaterial: [UInt8]) throws -> ([UInt8], [UInt8]) {
  let tempKey = try HKDF(password: chainingKey, salt: inputKeyMaterial).calculate()
  let output1 = try HKDF(password: tempKey, salt: [1]).calculate()
  let output2 = try HKDF(password: tempKey, salt: output1 + [2]).calculate()
  return (output1, output2)
}

func hkdf3(chainingKey: [UInt8], inputKeyMaterial: [UInt8]) throws -> ([UInt8], [UInt8], [UInt8]) {
  let tempKey = try HKDF(password: chainingKey, salt: inputKeyMaterial).calculate()
  let output1 = try HKDF(password: tempKey, salt: [1]).calculate()
  let output2 = try HKDF(password: tempKey, salt: output1 + [2]).calculate()
  let output3 = try HKDF(password: tempKey, salt: output2 + [3]).calculate()
  return (output1, output2, output3)
}