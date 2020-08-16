//
//  File.swift
//  
//
//  Created by lonnie on 2020/8/15.
//

import CommonCrypto
import Foundation

public enum Digest: CaseIterable {
    
    case md2
    
    case md4
    
    case md5
    
    case sha1
    
    case sha224
    
    case sha256
    
    case sha384
    
    case sha512
    
    public var length: Int {
        switch self {
        case .md2:
            return Int(CC_MD2_DIGEST_LENGTH)
        case .md4:
            return Int(CC_MD4_DIGEST_LENGTH)
        case .md5:
            return Int(CC_MD5_DIGEST_LENGTH)
        case .sha1:
            return Int(CC_SHA1_DIGEST_LENGTH)
        case .sha224:
            return Int(CC_SHA224_DIGEST_LENGTH)
        case .sha256:
            return Int(CC_SHA256_DIGEST_LENGTH)
        case .sha384:
            return Int(CC_SHA384_DIGEST_LENGTH)
        case .sha512:
            return Int(CC_SHA512_DIGEST_LENGTH)
        }
    }
    
    public var function: ((_ data: UnsafeRawPointer?, _ len: CC_LONG, _ md: UnsafeMutablePointer<UInt8>?) -> UnsafeMutablePointer<UInt8>?) {
        switch self {
        case .md2:
            return CC_MD2
        case .md4:
            return CC_MD4
        case .md5:
            return CC_MD5
        case .sha1:
            return CC_SHA1
        case .sha224:
            return CC_SHA224
        case .sha256:
            return CC_SHA256
        case .sha384:
            return CC_SHA384
        case .sha512:
            return CC_SHA512
        }
    }
    
    public func process(_ data: Data) -> Data {
        var result = [UInt8](repeating: 0, count: length)
        _ = data.withUnsafeBytes {
            function($0.baseAddress, UInt32(data.count), &result)
        }
        return Data(result)
    }
    
}
