import XCTest
import SwiftNoise

func getKeyPair(curveHelper: Curve, secretKey: Data?) -> KeyPair? {
  guard let secret = secretKey else {
    return nil
  }
  return try? curveHelper.constructKeyPair(secretKey: secret)
}

final class SwiftNoiseTests: XCTestCase {
  static var allTests = [
    ("testSnowVectors", testSnowVectors)
  ]

  let supportedCipherSuites = [
    "Noise_N_25519_AESGCM_SHA256",
    "Noise_K_25519_AESGCM_SHA256",
    "Noise_X_25519_AESGCM_SHA256",
    "Noise_NN_25519_AESGCM_SHA256",
    "Noise_NK_25519_AESGCM_SHA256",
    "Noise_NX_25519_AESGCM_SHA256",
    "Noise_KN_25519_AESGCM_SHA256",
    "Noise_KK_25519_AESGCM_SHA256",
    "Noise_KX_25519_AESGCM_SHA256",
    "Noise_XN_25519_AESGCM_SHA256",
    "Noise_XK_25519_AESGCM_SHA256",
    "Noise_XX_25519_AESGCM_SHA256",
    "Noise_IN_25519_AESGCM_SHA256",
    "Noise_IK_25519_AESGCM_SHA256",
    "Noise_IX_25519_AESGCM_SHA256",
  ]

  func loadTestVectors() throws -> [SnowTestVector]? {
    guard let url = Bundle.module.url(forResource: "SnowTestVectors", withExtension: "json") else {
      return nil
    }

    let data = try Data(contentsOf: url)
    let json = try JSONDecoder().decode(SnowTestVectors.self, from: data)

    return json.vectors
  }

  func testSnowVectors() throws {
    guard let testVectors = try self.loadTestVectors() else {
      return XCTFail("Unable to load resource 'SnowTestVectors.json'")
    }

    let curveHelper = Curves.C25519()

    for testVector in testVectors {
      if !supportedCipherSuites.contains(testVector.protocolName) {
        // print("unsupported cipher suite: \(testVector.protocolName)")
        continue
      }

      print("Running test vector for \(testVector.protocolName)")

      let handshakePattern = try getHandshakePatternFromProtocolName(protocolName: testVector.protocolName)

      let initiatorState = try HandshakeState(
        pattern: handshakePattern,
        initiator: true,
        prologue: testVector.initPrologue,
        s: getKeyPair(curveHelper: curveHelper, secretKey: testVector.initStatic),
        e: getKeyPair(curveHelper: curveHelper, secretKey: testVector.initEphemeral),
        rs: testVector.initRemoteStatic
      )

      let responderState = try HandshakeState(
        pattern: handshakePattern,
        initiator: false,
        prologue: testVector.respPrologue,
        s: getKeyPair(curveHelper: curveHelper, secretKey: testVector.respStatic),
        e: getKeyPair(curveHelper: curveHelper, secretKey: testVector.respEphemeral),
        rs: testVector.respRemoteStatic
      )

      let states: [HandshakeState] = [initiatorState, responderState]

      for index in 0..<testVector.messages.count {
        let message = testVector.messages[index]

        let senderState = states[index & 1]
        let receiverState = states[(index & 1) ^ 1]

        let ciphertext = try senderState.writeMessage(payload: message.payload)
        XCTAssertEqual(ciphertext, message.ciphertext)

        let payload = try receiverState.readMessage(message: ciphertext)
        XCTAssertEqual(payload, message.payload)
      }
    }
  }
}

enum TestError: Error {
  case invalidProtocolName
}

func protocolComponents(name: String) throws -> (handshake: HandshakePattern, dh: Curve, cipher: Cipher, hash: Hash) {
  let components = name.components(separatedBy: "_")

  guard components.count == 5 else {
    throw TestError.invalidProtocolName
  }

  guard let handshake = HandshakePattern(rawValue: components[1]) else {
    throw TestError.invalidProtocolName
  }

  guard let curve = Curves.curve(named: components[2]) else {
    throw TestError.invalidProtocolName
  }

  guard let cipher = Ciphers.cipher(named: components[3]) else {
    throw TestError.invalidProtocolName
  }

  guard let hash = Hashes.hash(named: components[4]) else {
    throw TestError.invalidProtocolName
  }

  return (handshake: handshake, dh: curve, cipher: cipher, hash: hash)
}

func getHandshakePatternFromProtocolName(protocolName: String) throws -> HandshakePattern {
  let components = try protocolComponents(name: protocolName)
  return components.handshake
}

struct SnowTestVectors: Codable {
  var vectors: [SnowTestVector]
}

struct SnowTestVector {
  var protocolName: String
  var initPrologue: Data
  var initPsks: [Data]
  var initStatic: Data?
  var initEphemeral: Data
  var initRemoteStatic: Data?
  var respPrologue: Data
  var respPsks: [Data]
  var respStatic: Data?
  var respEphemeral: Data
  var respRemoteStatic: Data?
  var messages: [Message]

  enum CodingKeys: String, CodingKey {
    case protocolName = "protocol_name"
    case initPrologue = "init_prologue"
    case initPsks = "init_psks"
    case initStatic = "init_static"
    case initEphemeral = "init_ephemeral"
    case initRemoteStatic = "init_remote_static"
    case respPrologue = "resp_prologue"
    case respPsks = "resp_psks"
    case respStatic = "resp_static"
    case respEphemeral = "resp_ephemeral"
    case respRemoteStatic = "resp_remote_static"
    case messages = "messages"
  }
}

extension SnowTestVector: Encodable {}

extension SnowTestVector: Decodable {
  init(from decoder: Decoder) throws {
    let values = try decoder.container(keyedBy: CodingKeys.self)
    self.protocolName = try values.decode(String.self, forKey: .protocolName)
    self.initPrologue = try values.decodeHex(forKey: .initPrologue)!
    self.initPsks = []
    self.initStatic = try values.decodeHex(forKey: .initStatic)
    self.initEphemeral = try values.decodeHex(forKey: .initEphemeral)!
    self.initRemoteStatic = try values.decodeHex(forKey: .initRemoteStatic)
    self.respPrologue = try values.decodeHex(forKey: .respPrologue)!
    self.respPsks = []
    self.respStatic = try values.decodeHex(forKey: .respStatic)
    self.respEphemeral = try values.decodeHex(forKey: .respEphemeral)!
    self.respRemoteStatic = try values.decodeHex(forKey: .respRemoteStatic)
    self.messages = try values.decode([Message].self, forKey: .messages)
  }
}

struct Message {
  var payload: Data
  var ciphertext: Data

  enum CodingKeys: String, CodingKey {
    case payload
    case ciphertext
  }
}

extension Message: Encodable {}
extension Message: Decodable {
  init(from decoder: Decoder) throws {
    let values = try decoder.container(keyedBy: CodingKeys.self)
    self.payload = try values.decodeHex(forKey: .payload)!
    self.ciphertext = try values.decodeHex(forKey: .ciphertext)!
  }
}

extension KeyedDecodingContainer {
  func decodeHex(forKey key: Key) throws -> Data? {
    if !self.contains(key) {
      return nil
    }
    let hexString = try self.decode(String.self, forKey: key)
    return Data(hex: hexString)
  }
}

extension Data {
  public init(hex: String) {
    self.init(Array<UInt8>(hex: hex))
  }

  public var bytes: Array<UInt8> {
    Array(self)
  }

  public func toHexString() -> String {
    self.bytes.toHexString()
  }
}

extension Array where Element == UInt8 {
  public init(hex: String) {
    self.init(reserveCapacity: hex.unicodeScalars.lazy.underestimatedCount)
    var buffer: UInt8?
    var skip = hex.hasPrefix("0x") ? 2 : 0
    for char in hex.unicodeScalars.lazy {
      guard skip == 0 else {
        skip -= 1
        continue
      }
      guard char.value >= 48 && char.value <= 102 else {
        removeAll()
        return
      }
      let v: UInt8
      let c: UInt8 = UInt8(char.value)
      switch c {
      case let c where c <= 57:
        v = c - 48
      case let c where c >= 65 && c <= 70:
        v = c - 55
      case let c where c >= 97:
        v = c - 87
      default:
        removeAll()
        return
      }
      if let b = buffer {
        append(b << 4 | v)
        buffer = nil
      } else {
        buffer = v
      }
    }
    if let b = buffer {
      append(b)
    }
  }

  public func toHexString() -> String {
    `lazy`.reduce(into: "") {
      var s = String($1, radix: 16)
      if s.count == 1 {
        s = "0" + s
      }
      $0 += s
    }
  }
}

extension Array {
  init(reserveCapacity: Int) {
    self = Array<Element>()
    self.reserveCapacity(reserveCapacity)
  }

  var slice: ArraySlice<Element> {
    self[self.startIndex..<self.endIndex]
  }
}
