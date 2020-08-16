//
//  CCError.swift
//  Crypto
//
//  Created by lonnie on 2020/8/14.
//  Copyright © 2020 lonnie. All rights reserved.
//

import CommonCrypto
import Foundation

public enum CCError: CCCryptorStatus, Error {
    
    case paramError         = -4300
    
    case bufferTooSmall     = -4301
    
    case memoryFailure      = -4302
    
    case alignmentError     = -4303
    
    case decodeError        = -4304
    
    case unimplemented      = -4305
    
    case overflow           = -4306
    
    case rngFailure         = -4307
    
    case unspecifiedError   = -4308
    
    case callSequenceError  = -4309
    
    case keySizeError       = -4310
    
    case invalidKey         = -4311
    
}
