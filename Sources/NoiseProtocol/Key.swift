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
  let tempKey = try HMAC(key: chainingKey, variant: .sha256).authenticate(inputKeyMaterial)
  let output1 = try HMAC(key: tempKey, variant: .sha256).authenticate([1])
  let output2 = try HMAC(key: tempKey, variant: .sha256).authenticate(output1 + [2])
  return (output1, output2)
}

func hkdf3(chainingKey: [UInt8], inputKeyMaterial: [UInt8]) throws -> ([UInt8], [UInt8], [UInt8]) {
  let tempKey = try HMAC(key: chainingKey, variant: .sha256).authenticate(inputKeyMaterial)
  let output1 = try HMAC(key: tempKey, variant: .sha256).authenticate([1])
  let output2 = try HMAC(key: tempKey, variant: .sha256).authenticate(output1 + [2])
  let output3 = try HMAC(key: tempKey, variant: .sha256).authenticate(output2 + [3])
  return (output1, output2, output3)
}