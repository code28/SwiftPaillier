import XCTest

import SwiftPaillierTests

var tests = [XCTestCaseEntry]()
tests += SwiftPaillierTests.allTests()
XCTMain(tests)