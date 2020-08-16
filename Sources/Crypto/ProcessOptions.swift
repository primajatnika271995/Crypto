//
//  ProcessOptions.swift
//  
//
//  Created by lonnie on 2020/8/16.
//
import Compression
import Foundation
public struct ProcessOptions {
    
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
        
        case encrypt(SymmetricCipher.Algorithm)
        
        case decrypt(SymmetricCipher.Algorithm)
        
        case digest(Digest)
        
        case hmac(HMAC.Algorithm)
        
        case changeEncoding
        
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
    
    
    public static let md5 = ProcessOptions(.digest(.md5))
    
    public static let sha1 = ProcessOptions(.digest(.sha1))
    
    public static let sha224 = ProcessOptions(.digest(.sha224))
    
    public static let sha256 = ProcessOptions(.digest(.sha256))
    
    public static let sha384 = ProcessOptions(.digest(.sha384))
    
    public static func aes(_ operation: SymmetricCipher.Operation, key: DataConvertable, iv: DataConvertable, mode: SymmetricCipher.Mode = .cbc, padding: SymmetricCipher.Padding = .pkcs7) -> ProcessOptions {
        symmetry(.aes, operation, key: key, iv: iv, mode: mode, padding: padding)
    }
    
    public static func des(_ operation: SymmetricCipher.Operation, key: DataConvertable, iv: DataConvertable, mode: SymmetricCipher.Mode = .cbc, padding: SymmetricCipher.Padding = .pkcs7) -> ProcessOptions {
        symmetry(.des, operation, key: key, iv: iv, mode: mode, padding: padding)
    }
    
    public static func des3(_ operation: SymmetricCipher.Operation, key: DataConvertable, iv: DataConvertable, mode: SymmetricCipher.Mode = .cbc, padding: SymmetricCipher.Padding = .pkcs7) -> ProcessOptions {
        symmetry(.des3, operation, key: key, iv: iv, mode: mode, padding: padding)
    }
    
    public static func cast(_ operation: SymmetricCipher.Operation, key: DataConvertable, iv: DataConvertable, mode: SymmetricCipher.Mode = .cbc, padding: SymmetricCipher.Padding = .pkcs7) -> ProcessOptions {
        symmetry(.cast, operation, key: key, iv: iv, mode: mode, padding: padding)
    }
    
    public static func rc4(_ operation: SymmetricCipher.Operation, key: DataConvertable, iv: DataConvertable, padding: SymmetricCipher.Padding = .pkcs7) -> ProcessOptions {
        symmetry(.rc4, operation, key: key, iv: iv, mode: .rc4, padding: padding)
    }
    
    public static func rc2(_ operation: SymmetricCipher.Operation, key: DataConvertable, iv: DataConvertable, mode: SymmetricCipher.Mode = .cbc, padding: SymmetricCipher.Padding = .pkcs7) -> ProcessOptions {
        symmetry(.rc2, operation, key: key, iv: iv, mode: mode, padding: padding)
    }
    
    public static func blowfish(_ operation: SymmetricCipher.Operation, key: DataConvertable, iv: DataConvertable, mode: SymmetricCipher.Mode = .cbc, padding: SymmetricCipher.Padding = .pkcs7) -> ProcessOptions {
        symmetry(.blowfish, operation, key: key, iv: iv, mode: mode, padding: padding)
    }
 
    public static func symmetry(_ algorithm: SymmetricCipher.Algorithm, _ operation: SymmetricCipher.Operation, key: DataConvertable, iv: DataConvertable, mode: SymmetricCipher.Mode = .cbc, padding: SymmetricCipher.Padding = .pkcs7) -> ProcessOptions {
        let parameters: [ProcessOptions.Option: Any] = [.key: key, .iv: iv, .mode: mode, .padding: padding]
        if operation == .encrypt {
            return ProcessOptions(.encrypt(algorithm), parameters)
        } else {
            return ProcessOptions(.decrypt(algorithm), parameters)
        }
    }
    
    public static func hmac(_ algorithm: HMAC.Algorithm, key: DataConvertable) -> ProcessOptions {
        ProcessOptions(.hmac(algorithm), [.key: key])
    }
    
    public static func hmacmd5(key: DataConvertable) -> ProcessOptions {
        hmac(.md5, key: key)
    }
    
    public static func hmacsha1(key: DataConvertable) -> ProcessOptions {
        hmac(.sha1, key: key)
    }
    
    public static func hmacsha224(key: DataConvertable) -> ProcessOptions {
        hmac(.sha224, key: key)
    }
    
    public static func hmacsha256(key: DataConvertable) -> ProcessOptions {
        hmac(.sha256, key: key)
    }
    
    public static func hmacsha384(key: DataConvertable) -> ProcessOptions {
        hmac(.sha384, key: key)
    }
    
    public static func hmacsha512(key: DataConvertable) -> ProcessOptions {
        hmac(.sha512, key: key)
    }
    
}
