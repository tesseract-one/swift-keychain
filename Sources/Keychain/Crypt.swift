//
//  Crypt.swift
//  Keychain
//
//  Created by Yehor Popovych on 3/14/19.
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
import CryptoSwift

// DATA structure constants
private let ITER       : Int = 19_162
private let SALT_SIZE  : Int = 32
private let NONCE_SIZE : Int = 12
private let KEY_SIZE   : Int = 32
private let TAG_SIZE   : Int = 16

private let METADATA_SIZE : Int = SALT_SIZE + NONCE_SIZE + TAG_SIZE

private let SALT_START      : Int = 0
private let SALT_END        : Int = SALT_START + SALT_SIZE
private let NONCE_START     : Int = SALT_END
private let NONCE_END       : Int = NONCE_START + NONCE_SIZE
private let TAG_START       : Int = NONCE_END
private let TAG_END         : Int = TAG_START + TAG_SIZE
private let ENCRYPTED_START : Int = TAG_END

public enum CryptError: Error {
    case notEnoughData(Int)
    case decryptionFailed
    case randomFailed
    case wrongTagSize(Int)
}

func encrypt(data: Data, password: String) throws -> Data {
    var salt = Array<UInt8>(repeating: 0, count: SALT_SIZE)
    var nonce = Array<UInt8>(repeating: 0, count: NONCE_SIZE)
    
    guard SecRandomCopyBytes(kSecRandomDefault, salt.count, &salt) == 0 else {
        throw CryptError.randomFailed
    }
    guard SecRandomCopyBytes(kSecRandomDefault, nonce.count, &nonce) == 0 else {
        throw CryptError.randomFailed
    }
    
    let key = try PKCS5.PBKDF2(password: Array(password.utf8), salt: salt, iterations: ITER, keyLength: KEY_SIZE, variant: .sha512).calculate()
    
    let encypted = try AEADChaCha20Poly1305.encrypt(data.bytes, key: key, iv: nonce, authenticationHeader: [])
    
    guard encypted.authenticationTag.count == TAG_SIZE else {
        throw CryptError.wrongTagSize(encypted.authenticationTag.count)
    }
    
    var response = Data(capacity: encypted.cipherText.count + METADATA_SIZE)
    response.append(contentsOf: salt)
    response.append(contentsOf: nonce)
    response.append(contentsOf: encypted.authenticationTag)
    response.append(contentsOf: encypted.cipherText)
    return response
}

func decrypt(data: Data, password: String) throws -> Data {
    guard data.count > METADATA_SIZE else {
        throw CryptError.notEnoughData(data.count)
    }
    
    let salt = data[SALT_START..<SALT_END].bytes
    let nonce = data[NONCE_START..<NONCE_END].bytes
    let tag = data[TAG_START..<TAG_END].bytes
    let encrypted = data[ENCRYPTED_START...].bytes
    
    let key = try PKCS5.PBKDF2(password: Array(password.utf8), salt: salt, iterations: ITER, keyLength: KEY_SIZE, variant: .sha512).calculate()
    
    let decrypted = try AEADChaCha20Poly1305.decrypt(encrypted, key: key, iv: nonce, authenticationHeader: [], authenticationTag: tag)
    
    guard decrypted.success else {
        throw CryptError.decryptionFailed
    }
    return Data(decrypted.plainText)
}
