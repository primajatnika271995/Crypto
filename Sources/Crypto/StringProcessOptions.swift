//
//  StringProcessOptions.swift
//  
//
//  Created by lonnie on 2020/8/16.
//

import Foundation

public struct StringProcessOptions {
    
    public enum Option: String {
        
        case key
        
        case iv
        
        case method
        
        case mode
        
        case padding
        
        case fromEncoding
        
        case toEncoding
        
    }
    
    public enum Method {
        
        case encrypt(SymmetryCipher.Algorithm)
        
        case decrypt(SymmetryCipher.Algorithm)
        
        case digest(Digest)
        
        case hmac(HMAC.Algorithm)
        
    }
    
    public let method: Method
    
    public let parameters: [Option: Any]
    
    subscript<T>(option: Option) -> T? {
        return parameters[option] as? T
    }
    
    init(_ method: Method, _ parameters: [Option: Any] = [:]) {
        self.method = method
        self.parameters = parameters
    }
    
    
    public static let md5 = StringProcessOptions(.digest(.md5))
    
    public static let sha1 = StringProcessOptions(.digest(.sha1))
    
    public static let sha224 = StringProcessOptions(.digest(.sha224))
    
    public static let sha256 = StringProcessOptions(.digest(.sha256))
    
    public static let sha384 = StringProcessOptions(.digest(.sha384))
    
    public static func aesEncrypt(key: DataConvertable, iv: DataConvertable) -> StringProcessOptions {
        return StringProcessOptions(.encrypt(.aes), [.key: key, .iv: iv])
    }
    
    public static func aesDecrypt(key: DataConvertable, iv: DataConvertable) -> StringProcessOptions {
        return StringProcessOptions(.decrypt(.aes), [.key: key, .iv: iv])
    }
    
    public static func hmacmd5(key: DataConvertable) -> StringProcessOptions {
        return StringProcessOptions(.hmac(.md5), [.key: key])
    }
    
    public static func hmacsha1(key: DataConvertable) -> StringProcessOptions {
        StringProcessOptions(.hmac(.sha1), [.key: key])
    }
    
    public static func hmacsha224(key: DataConvertable) -> StringProcessOptions {
        StringProcessOptions(.hmac(.sha224), [.key: key])
    }
    
    public static func hmacsha256(key: DataConvertable) -> StringProcessOptions {
        StringProcessOptions(.hmac(.sha256), [.key: key])
    }
    
    public static func hmacsha384(key: DataConvertable) -> StringProcessOptions {
        StringProcessOptions(.hmac(.sha384), [.key: key])
    }
    
    public static func hmacsha512(key: DataConvertable) -> StringProcessOptions {
        StringProcessOptions(.hmac(.sha512), [.key: key])
    }
    
}
