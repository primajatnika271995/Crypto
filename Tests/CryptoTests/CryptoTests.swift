import XCTest
@testable import Crypto
import CommonCrypto
final class CryptoTests: XCTestCase {
    
    func testInBruteForce() throws {
        let texts = ["🐱🐱🐱", "Hello world", ""]
        do {
            for text in texts {
                for algorithm in SymmetryCipher.Algorithm.allCases {
                    for mode in SymmetryCipher.Mode.allCases {
                        for padding in SymmetryCipher.Padding.allCases {
                            let key = try algorithm.generateRandomKey()
                            let iv = mode.needesIV() ? algorithm.generateRandomIV() : Data()
                            let cipher = try SymmetryCipher(algorithm: algorithm, key: key, iv: iv, padding: padding, mode: mode)
                            if algorithm.isValid(mode: mode, padding: padding) {
                                let data = text.data(using: .utf8)!
                                let encrypted = try cipher.process(.encrypt, data)
                                let decrypted = try cipher.process(.decrypt, encrypted)
                                XCTAssert(data == decrypted)
                            }
                        }
                    }
                }
            }
        } catch let error {
            objc_exception_throw(error)
        }
    }
    
    func testSymmetryCipherWithHelloWorld() {
        do {
            let plainText = "Hello world"
            print("Plain text: \(plainText)")
            print("-----------------------------------------------------")
            for algorithm in SymmetryCipher.Algorithm.allCases {
                for mode in SymmetryCipher.Mode.allCases {
                    let key = try algorithm.generateRandomKey()
                    let iv = mode.needesIV() ? algorithm.generateRandomIV() : Data()
                    let cipher = try SymmetryCipher(algorithm: algorithm, key: key, iv: iv, mode: mode)
                    if cipher.isValid {
                        let data = plainText.data(using: .utf8)!
                        let encrypted = try cipher.process(.encrypt, data)
                        print("Algorithm: \(String(describing: algorithm).uppercased())")
                        print("Mode: \(String(describing: mode).uppercased())")
                        print("key: \(key.hex)")
                        if mode.needesIV() {
                            print("iv: \(iv.hex)")
                        }
                        print("Cipher text: \(encrypted.hex)")
                        let decrypted = try cipher.process(.decrypt, encrypted)
                        print("-----------------------------------------------------")
                        XCTAssert(decrypted == data)
                    }
                }
            }
        } catch let error {
            objc_exception_throw(error)
        }
        
    }
    
    func testRandomly() throws {
        do {
            for algorithm in SymmetryCipher.Algorithm.allCases {
                for mode in SymmetryCipher.Mode.allCases {
                    for padding in SymmetryCipher.Padding.allCases {
                       
                        let key = try algorithm.generateRandomKey()
                        let iv = mode.needesIV() ? algorithm.generateRandomIV() : Data()
                        let cipher = try SymmetryCipher(algorithm: algorithm, key: key, iv: iv, padding: padding, mode: mode)
                        if algorithm.isValid(mode: mode, padding: padding) {
                            let data = Data(random: Int(arc4random()) % 1000)
                            let encrypted = try cipher.process(.encrypt, data)
                            let decrypted = try cipher.process(.decrypt, encrypted)
                            XCTAssert(data == decrypted)
                        }
                    }
                }
            }
        } catch let error {
            objc_exception_throw(error)
        }
    }

    func testIsAlgorithmVaild() throws {
        XCTAssertTrue(SymmetryCipher.Algorithm.aes.isValid(mode: .ctr, padding: .pkcs7))
    }
    
    func testIsIVNeeded() {
        print(SymmetryCipher.Mode.cbc.needesIV())
        print(SymmetryCipher.Mode.ecb.needesIV())
    }
    
    func testDigests() {
        let plainText = "hello world"
        print("Plain text: \(plainText)")
        for digest in Digest.allCases {
            let digested = digest.process(plainText.data(using: .utf8)!)
            print("\(digest):\(digested.hex)")
            XCTAssert(digested.count == digest.length)
        }
    }
    
    func testAES128() {
        do {
            let algorithm = SymmetryCipher.Algorithm.aes
            let plainText = "Hello world"
            let data = try plainText.data(.utf8)
            let key = try String(repeating: "1", count: SymmetryCipher.Algorithm.KeySize.aes128).data(.ascii)
            let iv = try String(repeating: "1", count: algorithm.blockSize).data(.ascii)
            let aes = try SymmetryCipher(algorithm: .aes, key: key, iv: iv)
            let encrypted = try aes.encrypt(data)
            print("Cipher text: \(try encrypted.string(.hex))")
            let decrypted = try aes.decrypt(encrypted)
            XCTAssert(data == decrypted)
        } catch let error {
            objc_exception_throw(error)
        }
    }
    
    func testAES192() {
        do {
            let algorithm = SymmetryCipher.Algorithm.aes
            let plainText = "Hello world"
            let data = try plainText.data(.utf8)
            let key = try String(repeating: "1", count: SymmetryCipher.Algorithm.KeySize.aes192).data(.ascii)
            let iv = try String(repeating: "1", count: algorithm.blockSize).data(.ascii)
            let aes = try SymmetryCipher(algorithm: .aes, key: key, iv: iv)
            let encrypted = try aes.encrypt(data)
            print("Cipher text: \(try encrypted.string(.hex))")
            let decrypted = try aes.decrypt(encrypted)
            XCTAssert(data == decrypted)
        } catch let error {
            objc_exception_throw(error)
        }
    }
    
    func testAES256() {
        do {
            let plainText = "Hello world"
            let data = try plainText.data(.utf8)
            let key = try String(repeating: "1", count: 32).data(.ascii)
            let iv = try String(repeating: "1", count: 16).data(.ascii)
            let aes = try SymmetryCipher(algorithm: .aes, key: key, iv: iv)
            let encrypted = try aes.encrypt(data)
            print("Cipher text: \(try encrypted.string(.hex))")
            let decrypted = try aes.decrypt(encrypted)
            XCTAssert(data == decrypted)
        } catch let error {
            objc_exception_throw(error)
        }
    }
    
    func testSHA256() {
        do {
            let plainText = "Hello world"
            let data = try plainText.data(.utf8)
            let digest = try Digest.sha256.process(data).string(.hex)
            print("Plain text: \(plainText)")
            print("SHA256: \(digest)")
        } catch let error {
            objc_exception_throw(error)
        }
    }
    
    func testHMACSHA256() {
        do {
            let hmac = try HMAC(.sha256, key: "11111111111111111111".data(.hex))
            print("Result: \(try hmac.process(try "Hello world".data(.utf8)).string(.hex))")
        } catch let error {
            print(error)
        }
    }
    
    func testHMAC() {
        do {
            let plainText = "Hello world"
            print("Plain Text: \(plainText)")
            for algorithm in HMAC.Algorithm.allCases {
                let hmac = try HMAC(algorithm, key: "11111111111111111111".data(.hex))
                print("HMAC " + String(describing: algorithm).uppercased() + ":", try hmac.process(plainText.data(.ascii)).string(.hex))
            }
        } catch let error {
            print(error)
        }
    }

    static var allTests = [
        ("testInBruteForce", testInBruteForce),
        ("testRandomly", testRandomly),
        ("testAES", testAES128)
    ]
}
