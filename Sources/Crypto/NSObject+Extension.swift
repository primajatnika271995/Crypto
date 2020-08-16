//
//  NSObject+Extension.swift
//  
//
//  Created by lonnie on 2020/8/16.
//

import Foundation

extension NSObject {
    
    public func `try`<T>(block: @escaping () throws ->T) -> Result<T, Error> {
        do {
            return try Result.success(block())
        } catch let error {
            return Result.failure(error)
        }
    }
    
}
