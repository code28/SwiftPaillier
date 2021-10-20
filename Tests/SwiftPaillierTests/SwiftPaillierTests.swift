import XCTest
import BigInt
@testable import SwiftPaillier

final class SwiftPaillierTests: XCTestCase {
    func testSimpleOperations() {
        let recipient = Paillier()
        
        let randomInt = BigUInt(12345678)
        let encryption = PaillierEncryption(randomInt, for: recipient.publicKey)
        
        encryption.add(BigUInt(2))
        encryption.add(ciphertext: PaillierEncryption(8, for: recipient.publicKey).ciphertext)
        
        encryption.subtract(BigUInt(8))
        encryption.subtract(ciphertext: PaillierEncryption(2, for: recipient.publicKey).ciphertext)
        
        encryption.multiply(BigUInt(2))
        
        let decrypted = recipient.decrypt(ciphertext: encryption.ciphertext, type: .bigNumFast)
        let expected = randomInt * 2
        
        XCTAssertEqual(decrypted, expected)
    }

    static var allTests = [
        ("testSimpleOperations", testSimpleOperations),
    ]
}
