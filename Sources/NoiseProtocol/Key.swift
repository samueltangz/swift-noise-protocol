import Sodium

public func generateKeyPair() -> KeyPair {
  let sodium = Sodium()
  return sodium.box.keyPair()!
}

import CryptoKit25519
import Foundation

public func diffieHellman(keyPair: KeyPair, publicKey: PublicKey) -> [UInt8] {
  let privateKey = try! Curve25519.KeyAgreement.PrivateKey(rawRepresentation: Data(keyPair.secretKey))
  let publicKeyObj = try! Curve25519.KeyAgreement.PublicKey(rawRepresentation: Data(publicKey))
  let sharedKey = try! privateKey.sharedSecretFromKeyAgreement(with: publicKeyObj)
  print(sharedKey)
  print(privateKey.publicKey)
  return Array(sharedKey.rawData)

  // let sodium = Sodium()
  // let sharedKey = sodium.box.beforenm(recipientPublicKey: publicKey, senderSecretKey: keyPair.secretKey)!
  // print("1. pk", publicKey)
  // print("2. sk", keyPair.secretKey)
  // print("sharedKey", sharedKey)
  // return sharedKey
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