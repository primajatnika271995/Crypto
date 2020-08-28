//
//  SymmetricCipher.swift
//  Crypto
//
//  Created by lonnie on 2020/8/14.
//  Copyright © 2020 lonnie. All rights reserved.
//

import CommonCrypto
import Foundation

public struct SymmetricCipher {
    
    public enum Algorithm: CCAlgorithm, CaseIterable {
        
        case aes
        
        case des
        
        case des3
        
        case cast
        
        case rc4
        
        case rc2
        
        case blowfish
        
    }
    
    public enum Operation: CCOperation {
        
        case encrypt = 0
        
        case decrypt = 1
        
    }
    
    public enum Padding: CCPadding, CaseIterable {
        
        case none = 0
        
        case pkcs7 = 1
        
    }
    
    public enum Mode: CCMode, CaseIterable {
        
        case ecb = 1
        
        case cbc = 2
        
        case cfb = 3
        
        case ctr = 4
        
        case ofb = 7
        
        case rc4 = 9
        
        case cfb8 = 10
        
        func needsIV() -> Bool {
            switch self {
            case .ecb:
                return false
            default:
                return true
            }
        }
    }

    public let algorithm: Algorithm
    
    public let key: Data
    
    public let iv: Data
    
    public let padding: Padding
    
    public let mode: Mode
    
    public init(_ algorithm: Algorithm, key: Data, iv: Data = Data(), padding: Padding = .pkcs7, mode: Mode = .cbc) {
        self.algorithm = algorithm
        self.key = key
        self.iv = iv
        self.padding = padding
        self.mode = mode
    }
    
    var isValid: Bool {
        if mode.needsIV() && iv.count != algorithm.blockSize { return false }
        if !algorithm.isValidKeySize(key.count) { return false }
        if !algorithm.isValid(mode: mode, padding: padding) { return false }
        return true
    }
    
    public func tryValidate() throws {
        if mode.needsIV() && iv.count != algorithm.blockSize { throw CryptoError.invalidIV }
        guard algorithm.isValidKeySize(key.count) else { throw CryptoError.invalidKey }
        if !algorithm.isValid(mode: mode, padding: padding) {
            throw CryptoError.invalidModeOrPadding
        }
    }
    
    public func encrypt(_ data:  Data) throws -> Data {
        try process(.encrypt, data)
    }
    
    public func decrypt(_ data: Data) throws -> Data {
        try process(.decrypt, data)
    }
    
    public func process(_ operation: Operation, _ data: Data) throws -> Data {
        try tryValidate()
        var cryptor: CCCryptorRef? = nil
        defer {
            CCCryptorRelease(cryptor)
        }
        var status: CCCryptorStatus = 0
        status = key.withUnsafeBytes { keyBytes in
            iv.withUnsafeBytes { ivBytes in
                CCCryptorCreateWithMode(
                    operation.rawValue,
                    mode.rawValue,
                    algorithm.rawValue,
                    padding.rawValue,
                    mode.needsIV() ? ivBytes.baseAddress: nil,
                    keyBytes.baseAddress,
                    key.count,
                    nil,
                    0,
                    0,
                    CCModeOptions(kCCModeOptionCTR_BE),
                    &cryptor
                )
            }
        }
        
        try verify(status)
        let outputLength = CCCryptorGetOutputLength(cryptor, data.count, true)
        var pointer = UnsafeMutableRawPointer.allocate(byteCount: outputLength, alignment: MemoryLayout<UInt8>.alignment)
        defer {
            pointer.deallocate()
        }
        var updateMovedLength = 0
        status = data.withUnsafeBytes {
            CCCryptorUpdate(
                cryptor,
                $0.baseAddress,
                data.count,
                pointer,
                outputLength,
                &updateMovedLength
            )
        }
        try verify(status)
        guard updateMovedLength <= outputLength else {
            throw CCError.decodeError
        }
        let available = outputLength - updateMovedLength
        let pointer2 = pointer.advanced(by: updateMovedLength)
        var finalMovedLength = 0
        status = CCCryptorFinal(cryptor, pointer2, available, &finalMovedLength)
        let finalLength = updateMovedLength + finalMovedLength
        if operation == .encrypt && finalLength != outputLength {
            throw CCError.decodeError
        }
        let typedPointer = pointer.bindMemory(to: UInt8.self, capacity: finalLength)
        let typedBuffer = UnsafeMutableBufferPointer(start: typedPointer, count: finalLength)
        return Data(typedBuffer)
    }
    
    private func verify(_ status: CCCryptorStatus) throws {
        guard status == kCCSuccess else {
            throw CCError(rawValue: status) ?? CCError(rawValue: CCCryptorStatus(kCCUnspecifiedError))!
        }
    }
 
}

public extension SymmetricCipher.Algorithm {
    
    struct KeySize {
        
        public static let aes128 = 16
        
        public static let aes192 = 24
        
        public static let aes256 = 32
        
        public static let aes = [aes128, aes192, aes256]
        
        public static let des = 8
        
        public static let des3 = 24
        
        public static let cast = 5...16
        
        public static let rc4 = 1...512
        
        public static let rc2 = 1...128
        
        public static let blowfish = 8...56
        
    }
    
    var blockSize: Int {
        switch self {
        case .aes:
            return 16
        default:
            return 8
        }
    }
    
    func keySizes() -> [Int] {
        switch self {
        case .aes:
            return KeySize.aes
        case .des:
            return [KeySize.des]
        case .des3:
            return [KeySize.des3]
        case .cast:
            return Array(KeySize.cast)
        case .rc4:
            return Array(KeySize.rc4)
        case .rc2:
            return Array(KeySize.rc2)
        case .blowfish:
            return Array(KeySize.blowfish)
        }
    }
    
    func ivSize(mode: SymmetricCipher.Mode) -> Int {
        return mode.needsIV() ? blockSize : 0
    }

    func isValidKeySize(_ size: Int) -> Bool {
        switch self {
        case .aes:
            return KeySize.aes.contains(size)
        case .des:
            return KeySize.des == size
        case .des3:
            return KeySize.des3 == size
        case .cast:
            return KeySize.cast.contains(size)
        case .rc4:
            return KeySize.rc4.contains(size)
        case .rc2:
            return KeySize.rc2.contains(size)
        case .blowfish:
            return KeySize.blowfish.contains(size)
        }
    }
    
    func isValid(mode: SymmetricCipher.Mode, padding: SymmetricCipher.Padding) -> Bool {
        switch self {
        case .rc4:
            return mode == .rc4
        default:
            if mode == .ecb || mode == .cbc {
                return padding != .none
            } else {
                return mode != .rc4
            }
        }
    }
    
    func generateRandomKey(size: Int? = nil) throws -> Data {
        var actualSize = 0
        if let size = size {
            guard isValidKeySize(size) else { throw CCError.keySizeError }
            actualSize = size
        } else {
            switch self {
            case .aes, .des3:
                actualSize = 24
            default:
                actualSize = 8
            }
        }
        return Data(random: actualSize)
    }
    
    func generateRandomIV() -> Data {
        return Data(random: blockSize)
    }
    
}
