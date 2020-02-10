import XCTest

#if !canImport(ObjectiveC)
public func allTests() -> [XCTestCaseEntry] {
  return [
    testCase(SwiftNoiseTests.allTests)
  ]
}
#endif
