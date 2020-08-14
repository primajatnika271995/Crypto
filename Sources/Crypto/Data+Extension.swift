//
//  Data+Extension.swift
//  Crypto
//
//  Created by lonnie on 2020/8/14.
//  Copyright © 2020 lonnie. All rights reserved.
//

import Foundation
public extension Data {
    init(random count: Int) {
        var items = [UInt8](repeating: 0, count: count)
        arc4random_buf(&items, items.count)
        self.init(items)
    }
}
