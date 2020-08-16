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
    
}
