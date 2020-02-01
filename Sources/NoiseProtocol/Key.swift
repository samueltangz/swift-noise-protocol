import Sodium

public func constructKeyPair(secretKey: SecretKey) -> KeyPair {
  let secretKeyObj = try! Curve25519.KeyAgreement.PrivateKey(rawRepresentation: Data(normalize(secretKey: secretKey)))
  let publicKey = Array(secretKeyObj.publicKey.rawRepresentation)
  return KeyPair(publicKey: publicKey, secretKey: secretKey)
}

public func generateKeyPair() -> KeyPair {
  let sodium = Sodium()
  return sodium.box.keyPair()!
}

import CryptoKit25519
import Foundation

func normalize(secretKey: SecretKey) -> SecretKey {
  var newSecretKey = secretKey
  newSecretKey[0] &= 0xf8
  newSecretKey[31] &= 0x3f
  newSecretKey[31] |= 0x40
  return newSecretKey
}

public func diffieHellman(keyPair: KeyPair, publicKey: PublicKey) -> [UInt8] {
  let secretKeyObj = try! Curve25519.KeyAgreement.PrivateKey(rawRepresentation: Data(normalize(secretKey: keyPair.secretKey)))
  let publicKeyObj = try! Curve25519.KeyAgreement.PublicKey(rawRepresentation: Data(publicKey))
  let sharedKey = try! secretKeyObj.sharedSecretFromKeyAgreement(with: publicKeyObj)
  return Array(sharedKey.rawData)
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