//
//  CryptoTests.swift
//  CryptoTests
//
//  Created by lonnie on 2020/8/14.
//  Copyright © 2020 lonnie. All rights reserved.
//

import XCTest
import CommonCrypto
@testable import Crypto

class CryptoTests: XCTestCase {

    func testInBruteForce() throws {
        var texts = ["🐱🐱🐱", "Hello world", ""]
        do {
            for text in texts {
                for algorithm in SymmetryCipher.Algorithm.allCases {
                    for mode in SymmetryCipher.Mode.allCases {
                        for padding in SymmetryCipher.Padding.allCases {
                            let key = try algorithm.generateRandomKey()
                            let iv = mode.needesIV() ? try algorithm.generateRandomIV() : Data()
                            let cipher = try SymmetryCipher(algorithm: algorithm, key: key, iv: iv, padding: padding, mode: mode)
                            if algorithm.isValid(mode: mode, padding: padding) {
                                let data = text.data(using: .utf8)!
                                let encrypted = try cipher.process(.encrypt, data: data)
                                let decrypted = try cipher.process(.decrypt, data: encrypted)
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
                            let encrypted = try cipher.process(.encrypt, data: data)
                            let decrypted = try cipher.process(.decrypt, data: encrypted)
                            XCTAssert(data == decrypted)
                        }
                    }
                }
            }
        } catch let error {
            objc_exception_throw(error)
        }
    }
    
}
