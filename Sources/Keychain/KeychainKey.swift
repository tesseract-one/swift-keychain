//
//  KeyGenerator.swift
//  Keychain
//
//  Created by Yehor Popovych on 2/26/19.
//  Copyright © 2019 Tesseract Systems, Inc. All rights reserved.
//
//  Licensed under the Apache License, Version 2.0 (the "License");
//  you may not use this file except in compliance with the License.
//  You may obtain a copy of the License at
//
//  http://www.apache.org/licenses/LICENSE-2.0
//
//  Unless required by applicable law or agreed to in writing, software
//  distributed under the License is distributed on an "AS IS" BASIS,
//  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
//  See the License for the specific language governing permissions and
//  limitations under the License.
//

import Foundation

public protocol KeyPath {
    var purpose: UInt32 { get }
    var coin: UInt32 { get }
    var account: UInt32 { get }
    var change: UInt32 { get }
    var address: UInt32 { get }
}

public let BIP44_KEY_PATH_PURPOSE: UInt32 = 0x8000002C

public protocol KeychainKeyFactory {
    var network: Network { get }
    
    func keyDataFrom(seed: Data) throws -> Data
    func from(data: Data) throws -> KeychainKey
}

public protocol KeychainKey {
    func pubKey(path: KeyPath) throws -> Data
    func address(path: KeyPath) throws -> String
    func sign(data: Data, path: KeyPath) throws -> Data
    func verify(data: Data, signature: Data, path: KeyPath) throws -> Bool
}
