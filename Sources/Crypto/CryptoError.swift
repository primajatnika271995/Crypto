//
//  CryptoError.swift
//  
//
//  Created by lonnie on 2020/8/16.
//

import Foundation

public enum CryptoError: Error {
    
    case invalidIV
    
    case invalidKey
    
    case codingError
    
    case invalidParams
    
    case invalidModeOrPadding
    
}
