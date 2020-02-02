import Foundation
import CryptoSwift

func nonceToUInt8Array(n: Nonce) -> Data {
  return Data([
    0, 0, 0, 0,
    UInt8(truncatingIfNeeded: n>>56),
    UInt8(truncatingIfNeeded: n>>48),
    UInt8(truncatingIfNeeded: n>>40),
    UInt8(truncatingIfNeeded: n>>32),
    UInt8(truncatingIfNeeded: n>>24),
    UInt8(truncatingIfNeeded: n>>16),
    UInt8(truncatingIfNeeded: n>>8),
    UInt8(truncatingIfNeeded: n>>0)
  ])
}

func encrypt(k: Data, n: Nonce, ad: Data, plaintext: Data) throws -> Data {
  let iv = nonceToUInt8Array(n: n)
  let gcm = GCM(iv: iv.bytes, additionalAuthenticatedData: ad.bytes, mode: .combined)
  let cipher = try AES(key: k.bytes, blockMode: gcm, padding: .noPadding)
  let ciphertext = try cipher.encrypt(plaintext.bytes)
  return Data(ciphertext)
}

func decrypt(k: Data, n: Nonce, ad: Data, ciphertext: Data) throws -> Data {
  let iv = nonceToUInt8Array(n: n)
  let gcm = GCM(iv: iv.bytes, additionalAuthenticatedData: ad.bytes, mode: .combined)
  let cipher = try AES(key: k.bytes, blockMode: gcm, padding: .noPadding)
  let plaintext = try cipher.decrypt(ciphertext.bytes)
  return Data(plaintext)
}
