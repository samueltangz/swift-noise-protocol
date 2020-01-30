import Sodium

public func generateKeyPair() -> KeyPair {
  let sodium = Sodium()
  return sodium.box.keyPair()!
}