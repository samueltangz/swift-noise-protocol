import CryptoSwift

enum CipherError: Error {
  case invalidTag
}

func nonceToUInt8Array(n: Nonce) -> Array<UInt8> {
  // TODO
  return [0, 0, 0, 0, 0, 0, 0, 0]
}

func encrypt(k: [UInt8], n: Nonce, ad: [UInt8], plaintext: [UInt8]) throws -> [UInt8] {
  let iv = nonceToUInt8Array(n: n)
  let (ciphertext, tag) = try AEADChaCha20Poly1305.encrypt(plaintext, key: k, iv: iv, authenticationHeader: ad)
  return ciphertext + tag
}

func decrypt(k: [UInt8], n: Nonce, ad: [UInt8], ciphertextWithTag: [UInt8]) throws -> [UInt8] {
  let iv = nonceToUInt8Array(n: n)
  let ciphertextLength = ciphertextWithTag.count
  if ciphertextLength < 16 {
    throw CipherError.invalidTag
  }
  let ciphertext = Array(ciphertextWithTag[0..<(ciphertextLength-16)])
  let tag = Array(ciphertextWithTag[(ciphertextLength-16)...])
  let (plaintext, success) = try AEADChaCha20Poly1305.decrypt(ciphertext, key: k, iv: iv, authenticationHeader: ad, authenticationTag: tag)
  if !success {
    throw CipherError.invalidTag
  }
  return plaintext
}
