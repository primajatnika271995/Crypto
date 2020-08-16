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
    
    public static func aes(_ operation: SymmetryCipher.Operation, key: DataConvertable, iv: DataConvertable, mode: SymmetryCipher.Mode = .cbc, padding: SymmetryCipher.Padding = .pkcs7) -> StringProcessOptions {
        symmetry(.aes, operation, key: key, iv: iv, mode: mode, padding: padding)
    }
    
    public static func des(_ operation: SymmetryCipher.Operation, key: DataConvertable, iv: DataConvertable, mode: SymmetryCipher.Mode = .cbc, padding: SymmetryCipher.Padding = .pkcs7) -> StringProcessOptions {
        symmetry(.des, operation, key: key, iv: iv, mode: mode, padding: padding)
    }
    
    public static func des3(_ operation: SymmetryCipher.Operation, key: DataConvertable, iv: DataConvertable, mode: SymmetryCipher.Mode = .cbc, padding: SymmetryCipher.Padding = .pkcs7) -> StringProcessOptions {
        symmetry(.des3, operation, key: key, iv: iv, mode: mode, padding: padding)
    }
    
    public static func cast(_ operation: SymmetryCipher.Operation, key: DataConvertable, iv: DataConvertable, mode: SymmetryCipher.Mode = .cbc, padding: SymmetryCipher.Padding = .pkcs7) -> StringProcessOptions {
        symmetry(.cast, operation, key: key, iv: iv, mode: mode, padding: padding)
    }
    
    public static func rc4(_ operation: SymmetryCipher.Operation, key: DataConvertable, iv: DataConvertable, padding: SymmetryCipher.Padding = .pkcs7) -> StringProcessOptions {
        symmetry(.rc4, operation, key: key, iv: iv, mode: .rc4, padding: padding)
    }
    
    public static func rc2(_ operation: SymmetryCipher.Operation, key: DataConvertable, iv: DataConvertable, mode: SymmetryCipher.Mode = .cbc, padding: SymmetryCipher.Padding = .pkcs7) -> StringProcessOptions {
        symmetry(.rc2, operation, key: key, iv: iv, mode: mode, padding: padding)
    }
    
    public static func blowfish(_ operation: SymmetryCipher.Operation, key: DataConvertable, iv: DataConvertable, mode: SymmetryCipher.Mode = .cbc, padding: SymmetryCipher.Padding = .pkcs7) -> StringProcessOptions {
        symmetry(.blowfish, operation, key: key, iv: iv, mode: mode, padding: padding)
    }
 
    public static func symmetry(_ algorithm: SymmetryCipher.Algorithm, _ operation: SymmetryCipher.Operation, key: DataConvertable, iv: DataConvertable, mode: SymmetryCipher.Mode = .cbc, padding: SymmetryCipher.Padding = .pkcs7) -> StringProcessOptions {
        let parameters: [StringProcessOptions.Option: Any] = [.key: key, .iv: iv, .mode: mode, .padding: padding]
        if operation == .encrypt {
            return StringProcessOptions(.encrypt(algorithm), parameters)
        } else {
            return StringProcessOptions(.decrypt(algorithm), parameters)
        }
    }
    
    public static func aesEncrypt(key: DataConvertable, iv: DataConvertable) -> StringProcessOptions {
        return StringProcessOptions(.encrypt(.aes), [.key: key, .iv: iv])
    }
    
    public static func aesDecrypt(key: DataConvertable, iv: DataConvertable) -> StringProcessOptions {
        return StringProcessOptions(.decrypt(.aes), [.key: key, .iv: iv])
    }
    
    public static func hmac(_ algorithm: HMAC.Algorithm, key: DataConvertable) -> StringProcessOptions {
        StringProcessOptions(.hmac(algorithm), [.key: key])
    }
    
    public static func hmacmd5(key: DataConvertable) -> StringProcessOptions {
        hmac(.md5, key: key)
    }
    
    public static func hmacsha1(key: DataConvertable) -> StringProcessOptions {
        hmac(.sha1, key: key)
    }
    
    public static func hmacsha224(key: DataConvertable) -> StringProcessOptions {
        hmac(.sha224, key: key)
    }
    
    public static func hmacsha256(key: DataConvertable) -> StringProcessOptions {
         hmac(.sha256, key: key)
    }
    
    public static func hmacsha384(key: DataConvertable) -> StringProcessOptions {
        hmac(.sha384, key: key)
    }
    
    public static func hmacsha512(key: DataConvertable) -> StringProcessOptions {
        hmac(.sha512, key: key)
    }
    
}
