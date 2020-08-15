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
            d = Data(hex: self)
        }
        guard let value = d else { throw CryptoError.codingError }
        return value
    }
    
    func digest(_ algorithm: Digest) throws -> String {
        try algorithm.process(data: try data(.utf8)).string(.hex)
    }
    
}
