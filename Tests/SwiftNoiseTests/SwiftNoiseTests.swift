import XCTest
import SwiftNoise

func getKeyPair(dhFunction: DHFunction, secretKey: Data?) throws -> KeyPair? {
  guard let secret = secretKey else {
    return nil
  }
  return try dhFunction.constructKeyPair(secretKey: secret)
}

final class SwiftNoiseTests: XCTestCase {
  static var allTests = [
    ("testSnowVectors", testSnowVectors)
  ]

  static let supportedCipherSuites = HandshakePattern.allCases.flatMap({ handshake -> [String] in
    DHFunctions.supported.flatMap({ dhFunction -> [String] in
      Ciphers.supported.flatMap({ cipher -> [String] in
        Hashes.supported.map({ hash -> String in
          return "Noise_\(handshake.rawValue)_\(dhFunction)_\(cipher)_\(hash)"
        })
      })
    })
  })

  func loadTestVectors() throws -> [SnowTestVector]? {
    guard let url = Bundle.module.url(forResource: "SnowTestVectors", withExtension: "json") else {
      return nil
    }

    let data = try Data(contentsOf: url)
    let json = try JSONDecoder().decode(SnowTestVectors.self, from: data)

    return json.vectors
  }

    func testDHCurve25519() throws {
        let privK = Data(hex: "4b9d66860c39de31492bdb3b090527bf66ef1ea75f105bb6f87328dfbb9fe337")
        let pubK = Data(hex: "1ede233080a9305f658aeced07ef04ced370b5f1bba099b3abc39ec7b4f5a83f")

        let kp1 = try DHFunctions.C25519().constructKeyPair(secretKey: privK)
        XCTAssertEqual(kp1.publicKey.toHexString(), pubK.toHexString())
    }

  func testSnowVectors() throws {
    guard let testVectors = try self.loadTestVectors() else {
      return XCTFail("Unable to load resource 'SnowTestVectors.json'")
    }

    for testVector in testVectors {
        guard SwiftNoiseTests.supportedCipherSuites.contains(testVector.protocolName) else {
        // print("unsupported cipher suite: \(testVector.protocolName)")
        continue
      }

      print("Running test vector for \(testVector.protocolName)")

      let protoComponents = try protocolComponents(name: testVector.protocolName)

      let initiatorState = try HandshakeState(
        pattern: protoComponents.handshake,
        dh: protoComponents.dh,
        cipher: protoComponents.cipher,
        hash: protoComponents.hash,
        initiator: true,
        prologue: testVector.initPrologue,
        s: try getKeyPair(dhFunction: protoComponents.dh, secretKey: testVector.initStatic),
        e: try getKeyPair(dhFunction: protoComponents.dh, secretKey: testVector.initEphemeral),
        rs: testVector.initRemoteStatic
      )

      let responderState = try HandshakeState(
        pattern: protoComponents.handshake,
        dh: protoComponents.dh,
        cipher: protoComponents.cipher,
        hash: protoComponents.hash,
        initiator: false,
        prologue: testVector.respPrologue,
        s: try getKeyPair(dhFunction: protoComponents.dh, secretKey: testVector.respStatic),
        e: try getKeyPair(dhFunction: protoComponents.dh, secretKey: testVector.respEphemeral),
        rs: testVector.respRemoteStatic
      )

      let states: [HandshakeState] = [initiatorState, responderState]

      for index in 0..<testVector.messages.count {
        let message = testVector.messages[index]

        let senderState = states[index & 1]
        let receiverState = states[(index & 1) ^ 1]

        var ciphertext = Data()
        var isComplete = false

        let writeResult = try senderState.writeMessage(payload: message.payload)
        switch writeResult {
        case .data(let data):
          XCTAssertEqual(data, message.ciphertext)
          ciphertext = data
        case .handshakeComplete(let data, _):
          XCTAssertEqual(data, message.ciphertext)
          ciphertext = data
          isComplete = true
        }

        let readResult = try receiverState.readMessage(message: ciphertext)
        switch readResult {
        case .data(let data):
          XCTAssertEqual(data, message.payload)
          XCTAssertFalse(isComplete)
        case .handshakeComplete(let data, _):
          XCTAssertEqual(data, message.payload)
          XCTAssertTrue(isComplete)
        }
      }
    }
  }
}

enum TestError: Error {
  case invalidProtocolName
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
