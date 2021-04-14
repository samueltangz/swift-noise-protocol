import Foundation
import Crypto

// https://noiseprotocol.org/noise.html#dh-functions
public protocol DHFunction {
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

func randomKey(_ count: Int) -> SecretKey {
  let bytes = (0..<count).map({ _ in UInt8.random(in: 0...UInt8.max) })
  return Data(bytes)
}

public enum DHFunctions {
  public static func dhFunction(named name: String) -> DHFunction? {
    switch name {
    case "25519":
      return C25519()
    default:
      return nil
    }
  }
}

extension DHFunctions {
  public struct C25519: DHFunction {
    public init() {}

    public let dhlen: Int = 32

    public func constructKeyPair(secretKey: SecretKey) throws -> KeyPair {
      let secretKeyObj = try Curve25519.KeyAgreement.PrivateKey(rawRepresentation: secretKey)
      let publicKey = secretKeyObj.publicKey.rawRepresentation

      return KeyPair(publicKey: publicKey, secretKey: secretKey)
    }

    public func generateKeyPair() throws -> KeyPair {
      let secretKey = randomKey(self.dhlen)
      return try constructKeyPair(secretKey: secretKey)
    }

    public func dh(keyPair: KeyPair, publicKey: PublicKey) throws -> Data {
      let secretKeyObj = try Curve25519.KeyAgreement.PrivateKey(rawRepresentation: keyPair.secretKey)
      let publicKeyObj = try Curve25519.KeyAgreement.PublicKey(rawRepresentation: publicKey)
      let sharedKey = try secretKeyObj.sharedSecretFromKeyAgreement(with: publicKeyObj)

      return sharedKey.withUnsafeBytes { ptr in
        return Data(ptr)
      }
    }
  }

}
