//
//  Data+Extension.swift
//  Crypto
//
//  Created by lonnie on 2020/8/14.
//  Copyright © 2020 lonnie. All rights reserved.
//

import Foundation

public extension Data {
    
    init(hex: String) throws {
        self.init()
        var buffer: UInt8?
        var skip = hex.hasPrefix("0x") ? 2 : 0
        for char in hex.unicodeScalars.lazy {
            guard skip == 0 else {
                skip -= 1
                continue
            }
            guard char.value >= 48 && char.value <= 102 else {
                throw CryptoError.codingError
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
                throw CryptoError.codingError
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
    
    var hex: String {
        return `lazy`.reduce("") {
            var s = String($1, radix: 16)
            if s.count == 1 {
                s = "0" + s
            }
            return $0 + s
        }
    }
    
    init(random count: Int) {
        var items = [UInt8](repeating: 0, count: count)
        arc4random_buf(&items, items.count)
        self.init(items)
    }
    

    
    func string(_ encoding: Encoding) throws -> String {
        var value: String?
        switch encoding {
        case .ascii:
            value = String(data: self, encoding: .ascii)
        case .utf8:
            value = String(data: self, encoding: .utf8)
        case .hex:
            value = hex
        case .base64:
            value = self.base64EncodedString()
        }
        guard let item = value else {
            throw CryptoError.codingError
        }
        return item
    }
    
    func process(_ options: ProcessOptions) throws -> Data {
        switch options.method {
        case .encrypt(let algorithm):
            return try symmetryCrypt(algorithm, .encrypt, options)
        case .decrypt(let algorithm):
            return try symmetryCrypt(algorithm, .decrypt, options)
        case .digest(let digest):
            return digest.process(self)
        case .hmac(let algorithm):
            guard let key: DataConvertable = options[.key]  else { throw CryptoError.invalidKey }
            return try HMAC(algorithm, key: key.toData()).process(self)
        case .changeEncoding:
            return self
        }
    }
    
    func symmetryCrypt(_ algorithm: SymmetricCipher.Algorithm, _ operation: SymmetricCipher.Operation, _ options: ProcessOptions) throws -> Data {
        let mode: SymmetricCipher.Mode = options[.mode] ?? .cbc
        let padding: SymmetricCipher.Padding = options[.padding] ?? .pkcs7
        guard let key: DataConvertable = options[.key] else { throw CryptoError.invalidKey }
        var iv: DataConvertable!
        if let theIV: DataConvertable = options[.iv] {
            iv = theIV
        } else {
            iv = Data()
        }
        let cipher = try SymmetricCipher(
            algorithm,
            key: key.toData(),
            iv: iv.toData(),
            padding: padding,
            mode: mode
        )
        return try cipher.process(operation, self)
    }

}
