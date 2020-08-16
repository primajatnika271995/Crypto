//
//  HMAC.swift
//  
//
//  Created by lonnie on 2020/8/16.
//

import CommonCrypto
import Foundation

public struct HMAC  {
    
    public enum Algorithm: CCHmacAlgorithm, CaseIterable {
        
        case sha1
        
        case md5
        
        case sha256
        
        case sha384
        
        case sha512
        
        case sha224
        
        public var digestLength: Int {
            switch self {
            case .sha1:
                return Int(CC_SHA1_DIGEST_LENGTH)
            case .md5:
                return Int(CC_MD5_DIGEST_LENGTH)
            case .sha256:
                return Int(CC_SHA256_DIGEST_LENGTH)
            case .sha384:
                return Int(CC_SHA384_DIGEST_LENGTH)
            case .sha512:
                return Int(CC_SHA512_DIGEST_LENGTH)
            case .sha224:
                return Int(CC_SHA224_DIGEST_LENGTH)
            }
        }
    }
    
    public let key: Data
    
    public let algorithm: Algorithm
    
    public init(_ algorithm: Algorithm, key: Data) {
        self.key = key
        self.algorithm = algorithm
    }
    
    public func process(_ data: Data) -> Data {
        var context = CCHmacContext()
        var output = [UInt8](repeating: 0, count: algorithm.digestLength)
        key.withUnsafeBytes {
            CCHmacInit(&context, algorithm.rawValue, $0.baseAddress, key.count)
        }
        data.withUnsafeBytes {
            CCHmacUpdate(&context, $0.baseAddress, data.count)
        }
        CCHmacFinal(&context, &output)
        return Data(output)
    }
    
}
