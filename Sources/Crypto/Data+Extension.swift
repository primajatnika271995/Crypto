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
    
    init(ascii: String) throws {
        let data = ascii.data(using: .ascii)
        if let data = data {
            self = data
        } else {
            throw CryptoError.codingError
        }
    }
    
    init(utf8: String) throws {
        let data = utf8.data(using: .utf8)
        if let data = data {
            self = data
        } else {
            throw CryptoError.codingError
        }
    }
    
    init(random count: Int) {
        var items = [UInt8](repeating: 0, count: count)
        arc4random_buf(&items, items.count)
        self.init(items)
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
}
