//
//  Wallet.swift
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
import MnemonicKit


public class Keychain {
    
    public enum Error: Swift.Error {
        case networkIsNotSupported(Network)
        case wrongKeyPath
        case dataError
        case keyGenerationError
        case signatureError
        case mnemonicError
        case internalError
        case wrongPassword
    }
    
    private let keys: Dictionary<Network, KeychainKey>
    
    public static let factories: Dictionary<Network, KeychainKeyFactory> = [
        .Ethereum: EthereumKeychainKeyFactory()
    ]
    
    public var networks: Set<Network> {
        return Set(Keychain.factories.keys).intersection(keys.keys)
    }
    
    public static func generateMnemonic() throws -> String {
        let optMnemonic = Mnemonic.generateMnemonic(strength: 128, language: .english)
        guard let mnemonic = optMnemonic else { throw Error.mnemonicError }
        return mnemonic
    }
    
    public convenience init(encrypted: Data, password: String) throws {
        let decrypted: Data
        do {
            decrypted = try decrypt(data: encrypted, password: password)
        } catch CryptError.decryptionFailed {
            throw Error.wrongPassword
        }
        try self.init(data: WalletVersionedData.from(data: decrypted).walletData())
    }
    
    private init(pkeys: Dictionary<Network, Data>) throws {
        let keysArr: Array<(Network, KeychainKey)> = try pkeys
            .compactMap {
                if let fact = Keychain.factories[$0.key] {
                    return ($0.key, try fact.from(data: $0.value))
                }
                return nil
        }
        self.keys = Dictionary(uniqueKeysWithValues: keysArr)
    }
    
    public func address(network: Network, path: KeyPath) throws -> String {
        return try _pk(net: network).address(path: path)
    }
    
    public func pubKey(network: Network, path: KeyPath) throws -> Data {
        return try _pk(net: network).pubKey(path: path)
    }
    
    public func sign(network: Network, data: Data, path: KeyPath) throws -> Data {
        return try _pk(net: network).sign(data: data, path: path)
    }
    
    public func verify(network: Network, data: Data, signature: Data, path: KeyPath) throws -> Bool {
        return try _pk(net: network).verify(data: data, signature: signature, path: path)
    }
    
    public static func fromSeed(seed: Data, password: String) throws -> (keychain: Keychain, encrypted: Data) {
        let keysTuple = try Keychain.factories.map { net, fact in
            return (net, try fact.keyDataFrom(seed: seed))
        }
        let keys = Dictionary(uniqueKeysWithValues: keysTuple)
        let keychain = try Keychain(pkeys: keys)
        let walletData = try WalletVersionedData(v1: WalletDataV1(keys: keys))
        let data = try encrypt(data: walletData.toData(), password: password)
        return (keychain, data)
    }
    
    public static func fromMnemonic(mnemonic: String, password: String) throws -> (keychain: Keychain, encrypted: Data) {
        let optSeedStr = Mnemonic.deterministicSeedString(from: mnemonic, passphrase: "", language: .english)
        guard let seedStr = optSeedStr, seedStr != "" else { throw Error.mnemonicError }
        return try fromSeed(seed: seedStr.mnemonicData(), password: password)
    }
    
    public static func changePassword(encrypted: Data, oldPassword: String, newPassword: String) throws -> Data {
        let data = try decrypt(data: encrypted, password: oldPassword)
        return try encrypt(data: data, password: newPassword)
    }
}

extension Keychain {
    private convenience init(data: WalletDataV1) throws {
        try self.init(pkeys: data.keys)
    }
    
    private func _pk(net: Network) throws -> KeychainKey {
        if let pk = keys[net] {
            return pk
        }
        throw Error.networkIsNotSupported(net)
    }
}
