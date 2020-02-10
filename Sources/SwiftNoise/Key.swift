import Foundation
import CryptoKit25519

public func constructKeyPair(secretKey: SecretKey) throws -> KeyPair {
  let secretKeyObj = try Curve25519.KeyAgreement.PrivateKey(rawRepresentation: Data(normalize(secretKey: secretKey)))
  let publicKey = secretKeyObj.publicKey.rawRepresentation
  return KeyPair(publicKey: publicKey, secretKey: secretKey)
}

public func generateKeyPair() throws -> KeyPair {
  // using AES.randomIV as a reliable, secure source of random
  let secretKey = Data(AES.randomIV(32))
  return try constructKeyPair(secretKey: secretKey)
}

func normalize(secretKey: SecretKey) -> SecretKey {
  var newSecretKey = secretKey
  newSecretKey[0] &= 0xf8
  newSecretKey[31] &= 0x3f
  newSecretKey[31] |= 0x40
  return newSecretKey
}

public func diffieHellman(keyPair: KeyPair, publicKey: PublicKey) throws -> Data {
  let secretKeyObj = try Curve25519.KeyAgreement.PrivateKey(rawRepresentation: Data(normalize(secretKey: keyPair.secretKey)))
  let publicKeyObj = try Curve25519.KeyAgreement.PublicKey(rawRepresentation: Data(publicKey))
  let sharedKey = try secretKeyObj.sharedSecretFromKeyAgreement(with: publicKeyObj)
  return sharedKey.rawData
}

import CryptoSwift

func hkdf2(chainingKey: Data, inputKeyMaterial: Data) throws -> (Data, Data) {
  let tempKey = try HMAC(key: chainingKey.bytes, variant: .sha256).authenticate(inputKeyMaterial.bytes)
  let output1 = try HMAC(key: tempKey, variant: .sha256).authenticate([1])
  let output2 = try HMAC(key: tempKey, variant: .sha256).authenticate(output1 + [2])
  return (Data(output1), Data(output2))
}

func hkdf3(chainingKey: Data, inputKeyMaterial: Data) throws -> (Data, Data, Data) {
  let tempKey = try HMAC(key: chainingKey.bytes, variant: .sha256).authenticate(inputKeyMaterial.bytes)
  let output1 = try HMAC(key: tempKey, variant: .sha256).authenticate([1])
  let output2 = try HMAC(key: tempKey, variant: .sha256).authenticate(output1 + [2])
  let output3 = try HMAC(key: tempKey, variant: .sha256).authenticate(output2 + [3])
  return (Data(output1), Data(output2), Data(output3))
}