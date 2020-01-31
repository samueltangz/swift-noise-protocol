import CryptoSwift

func nonceToUInt8Array(n: Nonce) -> Array<UInt8> {
  return [
    UInt8(truncatingIfNeeded: n),
    UInt8(truncatingIfNeeded: n>>8),
    UInt8(truncatingIfNeeded: n>>16),
    UInt8(truncatingIfNeeded: n>>24),
    UInt8(truncatingIfNeeded: n>>32),
    UInt8(truncatingIfNeeded: n>>40),
    UInt8(truncatingIfNeeded: n>>48),
    UInt8(truncatingIfNeeded: n>>56)
  ]
}

func encrypt(k: [UInt8], n: Nonce, ad: [UInt8], plaintext: [UInt8]) throws -> [UInt8] {
  let iv = nonceToUInt8Array(n: n)
  let gcm = GCM(iv: iv, additionalAuthenticatedData: ad, mode: .combined)
  let cipher = try AES(key: k, blockMode: gcm, padding: .noPadding)
  return try cipher.encrypt(plaintext)
}

func decrypt(k: [UInt8], n: Nonce, ad: [UInt8], ciphertext: [UInt8]) throws -> [UInt8] {
  let iv = nonceToUInt8Array(n: n)
  let gcm = GCM(iv: iv, additionalAuthenticatedData: ad, mode: .combined)
  let cipher = try AES(key: k, blockMode: gcm, padding: .noPadding)
  return try cipher.decrypt(ciphertext)
}
