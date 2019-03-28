//
//  Data.swift
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

enum DataVersion: UInt16, Codable {
    case v1 = 1
}

enum DataError: Error {
    case encodeError
    case decodeError
    case unknownDataVersion
}

struct WalletDataV1: Codable {
    let keys: Dictionary<Network, Data>
}

struct WalletVersionedData: Codable {
    private let version: DataVersion
    private let data: Data
    
    init(v1: WalletDataV1) throws {
        do {
            let data = try JSONEncoder().encode(v1)
            self.version = .v1
            self.data = data
        } catch {
            throw DataError.encodeError
        }
    }
    
    static func from(data: Data) throws -> WalletVersionedData {
        do {
            return try JSONDecoder().decode(WalletVersionedData.self, from: data)
        } catch {
            throw DataError.decodeError
        }
    }
    
    func toData() throws -> Data {
        return try JSONEncoder().encode(self)
    }
    
    func walletData() throws -> WalletDataV1 {
        switch version {
        case .v1:
            do {
                return try JSONDecoder().decode(WalletDataV1.self, from: data)
            } catch {
                throw DataError.decodeError
            }
        }
    }
}
