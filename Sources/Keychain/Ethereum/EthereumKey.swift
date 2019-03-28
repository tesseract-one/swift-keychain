//
//  Ethereum.swift
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

public extension Network {
    static let Ethereum = Network(rawValue: 0x8000003c)
}

// "44'/60'/index'/0/0"
public struct EthereumKeyPath: KeyPath {
    public let account: UInt32
    
    public var change: UInt32 { return 0 }
    public var address: UInt32 { return 0 }
    public var purpose: UInt32 { return BIP44_KEY_PATH_PURPOSE } // BIP44
    public var coin: UInt32 { return Network.Ethereum.rawValue } // ETH Coin Type
    
    public init(account: UInt32) {
        self.account = account
    }
}

// "44'/60'/0'/0/index"
public struct MetamaskKeyPath: KeyPath {
    public var address: UInt32
    
    public var account: UInt32 { return 0}
    public var change: UInt32 { return 0 }
    public var purpose: UInt32 { return BIP44_KEY_PATH_PURPOSE } // BIP44
    public var coin: UInt32 { return Network.Ethereum.rawValue } // ETH Coin Type
    
    public init(account: UInt32) {
        self.address = account
    }
}

public struct EthereumKeychainKeyFactory: KeychainKeyFactory {
    public let network: Network = .Ethereum
    
    public func keyDataFrom(seed: Data) throws -> Data {
        return EthereumHDNode(seed: seed)!.serialize()!
    }
    
    public func from(data: Data) throws -> KeychainKey {
        return try EthereumKeychainKey(data: data)
    }
}


struct EthereumKeychainKey: KeychainKey {
    private let pk: EthereumHDNode
    
    init(data: Data) throws {
        let key =  EthereumHDNode(data)?
            .derive(index: BIP44_KEY_PATH_PURPOSE, derivePrivateKey: true, hardened: true)?
            .derive(index: Network.Ethereum.rawValue, derivePrivateKey: true, hardened: true)
        guard let newkey = key else { throw Keychain.Error.dataError }
        pk = newkey
    }
    
    func pubKey(path: KeyPath) throws -> Data {
        return try _pKey(for: path).publicKey
    }
    
    func address(path: KeyPath) throws -> String {
        guard let address = try _pKey(for: path).hexAddress(eip55: false) else {
            throw Keychain.Error.internalError
        }
        return address
    }
    
    func sign(data: Data, path: KeyPath) throws -> Data {
        guard var signature = try _pKey(for: path).sign(data: data) else {
            throw Keychain.Error.internalError
        }
        
        signature[64] = signature[64] + 27
        
        return signature
    }
    
    func verify(data: Data, signature: Data, path: KeyPath) throws -> Bool {
        guard signature.count == 65 else {
            throw Keychain.Error.signatureError
        }
        var fixedSignature = signature
        fixedSignature[64] = fixedSignature[64] - 27
        
        guard let verified = try _pKey(for: path).verifySignature(message: data, signature: signature) else {
            throw Keychain.Error.internalError
        }
        
        return verified
    }
    
    private func _pKey(for path: KeyPath) throws -> EthereumHDNode {
        guard path.change == 0 && path.coin == Network.Ethereum.rawValue && path.purpose == BIP44_KEY_PATH_PURPOSE else {
            throw Keychain.Error.wrongKeyPath
        }
        let key = pk
            .derive(index: path.account, derivePrivateKey: true, hardened: true)?
            .derive(index: path.change, derivePrivateKey: true, hardened: false)?
            .derive(index: path.address, derivePrivateKey: true, hardened: false)
        guard let newkey = key else { throw Keychain.Error.keyGenerationError }
        return newkey
    }
}
