import Foundation
import CryptoSwift
import Crypto

// https://noiseprotocol.org/noise.html#dh-functions
public protocol Curve {
  func constructKeyPair(secretKey: SecretKey) throws -> KeyPair

  // Generates a new Diffie-Hellman key pair. A DH key pair consists of public_key and private_key
  // elements. A public_key represents an encoding of a DH public key into a byte sequence of
  // length DHLEN. The public_key encoding details are specific to each set of DH functions.
  func generateKeyPair() throws -> KeyPair

  // Performs a Diffie-Hellman calculation between the private key in key_pair and the public_key
  // and returns an output sequence of bytes of length DHLEN. For security, the Gap-DH problem
  // based on this function must be unsolvable by any practical cryptanalytic adversary [2]. The
  // public_key either encodes some value which is a generator in a large prime-order group (which
  // value may have multiple equivalent encodings), or is an invalid value. Implementations must
  // handle invalid public keys either by returning some output which is purely a function of the
  // public key and does not depend on the private key, or by signaling an error to the caller. The
  // DH function may define more specific rules for handling invalid values.
  func dh(keyPair: KeyPair, publicKey: PublicKey) throws -> Data

  // = A constant specifying the size in bytes of public keys and DH outputs. For security reasons,
  // DHLEN must be 32 or greater.
  var dhlen: Int { get }
}

// An extension on CryptoKit's SharedSecret to return Data
extension SharedSecret {
  var data: Data { Data(self.withUnsafeBytes { $0 }) }
}

public class C25519: Curve {
  public init() {}

  func normalize(secretKey: SecretKey) -> SecretKey {
    var newSecretKey = secretKey
    newSecretKey[0] &= 0xf8
    newSecretKey[31] &= 0x3f
    newSecretKey[31] |= 0x40
    return newSecretKey
  }

  public func constructKeyPair(secretKey: SecretKey) throws -> KeyPair {
    let secretKeyObj = try Curve25519.KeyAgreement.PrivateKey(rawRepresentation: Data(normalize(secretKey: secretKey)))
    let publicKey = secretKeyObj.publicKey.rawRepresentation
    return KeyPair(publicKey: publicKey, secretKey: secretKey)
  }

  public func generateKeyPair() throws -> KeyPair {
    let secretKey = Data(AES.randomIV(32))
    return try constructKeyPair(secretKey: secretKey)
  }

  public func dh(keyPair: KeyPair, publicKey: PublicKey) throws -> Data {
    let secretKeyObj = try Curve25519.KeyAgreement.PrivateKey(
      rawRepresentation: Data(normalize(secretKey: keyPair.secretKey)))
    let publicKeyObj = try Curve25519.KeyAgreement.PublicKey(rawRepresentation: Data(publicKey))
    let sharedKey = try secretKeyObj.sharedSecretFromKeyAgreement(with: publicKeyObj)
    return sharedKey.data
  }

  public var dhlen: Int = 32
}
