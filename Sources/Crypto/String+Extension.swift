//
//  String+Extension.swift
//  
//
//  Created by lonnie on 2020/8/15.
//

import Foundation

public extension String {
    
    func data(_ encoding: Crypto.Encoding) throws -> Data {
        var d: Data?
        switch encoding {
        case .base64:
            d = Data(base64Encoded: self)
        case .ascii:
            d = data(using: .ascii)
        case .utf8:
            d = data(using: .utf8)
        case .hex:
            d = try Data(hex: self)
        }
        guard let value = d else { throw CryptoError.codingError }
        return value
    }
    
    func digest(_ algorithm: Digest) throws -> String {
        try algorithm.process(try data(.utf8)).string(.hex)
    }
    
    
    func process(_ options: StringProcessOptions) throws -> String {
        switch options.method {
        case .encrypt(let algorithm):
            return try symmetryCrypt(algorithm, .encrypt, options)
        case .decrypt(let algorithm):
            return try symmetryCrypt(algorithm, .decrypt, options)
        case .digest(let digest):
            let fromEncoding: Crypto.Encoding = options[.fromEncoding] ?? .utf8
            let toEncoding: Crypto.Encoding = options[.toEncoding] ?? .hex
            return try digest.process(self.data(fromEncoding)).string(toEncoding)
        case .hmac(let algorithm):
            let fromEncoding: Crypto.Encoding = options[.fromEncoding] ?? .utf8
            let toEncoding: Crypto.Encoding = options[.toEncoding] ?? .hex
            guard let key: DataConvertable = options[.key]  else { throw CryptoError.invalidKey }
            return try HMAC(algorithm, key: key.toData()).process(data(fromEncoding)).string(toEncoding)
        }
    }
    
    func symmetryCrypt(_ algorithm: SymmetryCipher.Algorithm, _ operation: SymmetryCipher.Operation, _ options: StringProcessOptions) throws -> String {
        let fromEncoding: Crypto.Encoding = options[.fromEncoding] ?? (operation == .encrypt ? .utf8 : .base64)
        let toEncoding: Crypto.Encoding = options[.toEncoding] ?? (operation == .encrypt ? .base64 : .utf8)
        let mode: SymmetryCipher.Mode = options[.mode] ?? .cbc
        let padding: SymmetryCipher.Padding = options[.padding] ?? .pkcs7
        guard let key: DataConvertable = options[.key] else { throw CryptoError.invalidKey }
        var iv: DataConvertable!
        if let theIV: DataConvertable = options[.iv] {
            iv = theIV
        } else {
            iv = Data()
        }
        let cipher = try SymmetryCipher(
            algorithm: algorithm,
            key: key.toData(),
            iv: iv.toData(),
            padding: padding,
            mode: mode
        )
        return try cipher.process(operation, data(fromEncoding)).string(toEncoding)
    }
}
