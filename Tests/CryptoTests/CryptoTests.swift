import XCTest
@testable import Crypto
import CommonCrypto
final class CryptoTests: XCTestCase {
    
    func testBruteForce() throws {
        let texts = ["🐱🐱🐱", "Hello world", ""]
        do {
            for text in texts {
                for algorithm in SymmetricCipher.Algorithm.allCases {
                    for mode in SymmetricCipher.Mode.allCases {
                        for padding in SymmetricCipher.Padding.allCases {
                            let key = try algorithm.generateRandomKey()
                            let iv = mode.needesIV() ? algorithm.generateRandomIV() : Data()
                            let cipher = SymmetricCipher(algorithm, key: key, iv: iv, padding: padding, mode: mode)
                            if cipher.isValid {
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
    
    func testSymmetricCipherWithHelloWorld() {
        do {
            let plainText = "Hello world"
            print("Plain text: \(plainText)")
            print("-----------------------------------------------------")
            for algorithm in SymmetricCipher.Algorithm.allCases {
                for mode in SymmetricCipher.Mode.allCases {
                    let key = try algorithm.generateRandomKey()
                    let iv = mode.needesIV() ? algorithm.generateRandomIV() : Data()
                    let cipher = SymmetricCipher(algorithm, key: key, iv: iv, mode: mode)
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
    
    func testInRandom() throws {
        do {
            for algorithm in SymmetricCipher.Algorithm.allCases {
                for mode in SymmetricCipher.Mode.allCases {
                    for padding in SymmetricCipher.Padding.allCases {
                       
                        let key = try algorithm.generateRandomKey()
                        let iv = mode.needesIV() ? algorithm.generateRandomIV() : Data()
                        let cipher = SymmetricCipher(algorithm, key: key, iv: iv, padding: padding, mode: mode)
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
        XCTAssertTrue(SymmetricCipher.Algorithm.aes.isValid(mode: .ctr, padding: .pkcs7))
    }
    
    func testIsIVNeeded() {
        print(SymmetricCipher.Mode.cbc.needesIV())
        print(SymmetricCipher.Mode.ecb.needesIV())
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
            let algorithm = SymmetricCipher.Algorithm.aes
            let plainText = "Hello world"
            let data = try plainText.data(.utf8)
            let key = try String(repeating: "1", count: SymmetricCipher.Algorithm.KeySize.aes128).data(.ascii)
            let iv = try String(repeating: "1", count: algorithm.blockSize).data(.ascii)
            let aes = SymmetricCipher(.aes, key: key, iv: iv)
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
            let algorithm = SymmetricCipher.Algorithm.aes
            let plainText = "Hello world"
            let data = try plainText.data(.utf8)
            let key = try String(repeating: "1", count: SymmetricCipher.Algorithm.KeySize.aes192).data(.ascii)
            let iv = try String(repeating: "1", count: algorithm.blockSize).data(.ascii)
            let aes = SymmetricCipher(.aes, key: key, iv: iv)
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
            let aes = SymmetricCipher(.aes, key: key, iv: iv)
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
    
    func testStringProcessWithCipher() {
        let plainText = "I am fine"
        do {
            let key = "1111111111111111"
            let iv = "1111111111111111"
            let cipherText = try plainText.process(.init(.encrypt(.aes), [.key: key, .iv: iv]))
            let decryptedText = try cipherText.process(.init(.decrypt(.aes), [.key: key, .iv: iv]))
            XCTAssert(plainText == decryptedText)
        } catch let error {
            objc_exception_throw(error)
        }
    }
    
    func testStringProcessWithDigest() {
        let plainText = "I am fine"
        XCTAssertEqual(try plainText.process(.init(.digest(.md5))), "75dc9bbfa6b55441d6ea91dcb2e6e900")
        XCTAssertEqual(try plainText.process(.init(.digest(.sha1))), "a4b8d1d7b17bf814694770e6deec44b07ded3c98")
        XCTAssertEqual(try plainText.process(.init(.digest(.sha256))), "cf39f63b0188d40bb46686d2c0d092d9367650710ec5a869b41e5b1448c510f4")
    }
    
    func testIVSize() {
        XCTAssertEqual(SymmetricCipher.Algorithm.aes.keySizes(), [16, 24, 32])
        XCTAssertEqual(SymmetricCipher.Algorithm.aes.ivSize(mode: .cbc), 16)
        XCTAssertEqual(SymmetricCipher.Algorithm.aes.ivSize(mode: .ecb), 0)
        XCTAssertTrue(SymmetricCipher.Algorithm.aes.isValidKeySize(32))
        XCTAssertFalse(SymmetricCipher.Algorithm.aes.isValidKeySize(40))
    }
    
    func testStringProcessWithHMAC() {
        let plainText = "I am fine"
        let key = "11111111111111111111"
        XCTAssertEqual(try plainText.process(.init(.hmac(.sha1), [.key: key])), "f602de1d96b881613a7fed43b6fa6ec0bbb1857b")
    }
    
    func testChangeEncoding() {
        let text = "Hello world"
        do {
            let text1 = try text.process(.init(.changeEncoding, [.fromEncoding: Crypto.Encoding.utf8, .toEncoding: Crypto.Encoding.base64]))
            let text2 = try text1.process(.init(.changeEncoding, [.fromEncoding: Crypto.Encoding.base64, .toEncoding: Crypto.Encoding.utf8]))
            XCTAssert(text == text2)
        } catch let error {
            objc_exception_throw(error)
        }
    }

    static var allTests = [
        ("testInBruteForce", testBruteForce),
        ("testInRandom", testInRandom),
        ("testAES", testAES128)
    ]
}
