//
//  SymmetryCipher.swift
//  Crypto
//
//  Created by lonnie on 2020/8/14.
//  Copyright © 2020 lonnie. All rights reserved.
//
import CommonCrypto
import Foundation
public struct SymmetryCipher {
    
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
        
        func needesIV() -> Bool {
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
    
    public init(algorithm: Algorithm, key: Data, iv: Data = Data(), padding: Padding = .pkcs7, mode: Mode = .cbc) throws {
        guard algorithm.isValidKeySize(key.count) else { throw CCError.keySizeError }
        if mode.needesIV() && iv.count != algorithm.blockSize { throw CryptoError.invalidIV }
        self.algorithm = algorithm
        self.key = key
        self.iv = iv
        self.padding = padding
        self.mode = mode
    }
    
    public func encrypt(data:  Data) throws -> Data {
        try process(.encrypt, data: data)
    }
    
    public func decrypt(data: Data) throws -> Data {
        try process(.decrypt, data: data)
    }
    
    public func process(_ operation: Operation, data: Data) throws -> Data {
        var cryptor: CCCryptorRef? = nil
        defer {
            CCCryptorRelease(cryptor)
        }
        var status: CCCryptorStatus = 0
        if mode.needesIV() {
            status = key.withUnsafeBytes { keyBytes in
                iv.withUnsafeBytes { ivBytes in
                    CCCryptorCreateWithMode(
                        operation.rawValue,
                        mode.rawValue,
                        algorithm.rawValue,
                        padding.rawValue,
                        ivBytes.baseAddress,
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
        } else {
            status = key.withUnsafeBytes { keyBytes in
                CCCryptorCreateWithMode(
                    operation.rawValue,
                    mode.rawValue,
                    algorithm.rawValue,
                    padding.rawValue,
                    nil,
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


extension SymmetryCipher.Algorithm {
    
    public enum KeySizes {
        public static let aes = [14, 24, 32]
        public static let des = [8]
        public static let des3 = [24]
        public static let cast = 5...16
        public static let rc4 = 1...512
        public static let rc2 = 1...128
        public static let blowfish = 8...56
    }
    
    public var blockSize: Int {
        switch self {
        case .aes:
            return 16
        default:
            return 8
        }
    }
    
    public func generateRandomKey(size: Int? = nil) throws -> Data {
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
    
    public func generateRandomIV() -> Data {
        return Data(random: blockSize)
    }

    public func isValidKeySize(_ size: Int) -> Bool {
        switch self {
        case .aes:
            return KeySizes.aes.contains(size)
        case .des:
            return KeySizes.des.contains(size)
        case .des3:
            return KeySizes.des3.contains(size)
        case .cast:
            return KeySizes.cast.contains(size)
        case .rc4:
            return KeySizes.rc4.contains(size)
        case .rc2:
            return KeySizes.rc2.contains(size)
        case .blowfish:
            return KeySizes.blowfish.contains(size)
        }
    }
    
    public func isValid(mode: SymmetryCipher.Mode, padding: SymmetryCipher.Padding) -> Bool {
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
    
}
