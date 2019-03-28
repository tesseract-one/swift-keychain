//  web3swift
//
//  Created by Alex Vlasov.
//  Copyright © 2018 Alex Vlasov. All rights reserved.
//

import Foundation
import BigInt
import CryptoSwift
import secp256k1

extension UInt32 {
    public func serialize32() -> Data {
        let uint32 = UInt32(self)
        var bigEndian = uint32.bigEndian
        let count = MemoryLayout<UInt32>.size
        let bytePtr = withUnsafePointer(to: &bigEndian) {
            $0.withMemoryRebound(to: UInt8.self, capacity: count) {
                UnsafeBufferPointer(start: $0, count: count)
            }
        }
        let byteArray = Array(bytePtr)
        return Data(byteArray)
    }
}

extension Data {
    func setLengthLeft(_ toBytes: UInt64, isNegative:Bool = false ) -> Data? {
        let existingLength = UInt64(self.count)
        if (existingLength == toBytes) {
            return Data(self)
        } else if (existingLength > toBytes) {
            return nil
        }
        var data:Data
        if (isNegative) {
            data = Data(repeating: UInt8(255), count: Int(toBytes - existingLength))
        } else {
            data = Data(repeating: UInt8(0), count: Int(toBytes - existingLength))
        }
        data.append(self)
        return data
    }
}

private struct SECP256K1 {
    static let context: OpaquePointer = {
        var seed = Array<UInt8>(repeating: 0, count: 32)
        guard SecRandomCopyBytes(kSecRandomDefault, seed.count, &seed) == 0 else {
            fatalError("Can't obtain 32 bytes of random data")
        }
        let context = secp256k1_context_create(UInt32(SECP256K1_CONTEXT_SIGN|SECP256K1_CONTEXT_VERIFY))
        let _ = secp256k1_context_randomize(context!, &seed)
        return context!
    }()

    public static func privateToPublic(privateKey: Data, compressed: Bool = false) -> Data? {
        if (privateKey.count != 32) {return nil}
        guard var publicKey = SECP256K1.privateKeyToPublicKey(privateKey: privateKey) else {return nil}
        guard let serializedKey = serializePublicKey(publicKey: &publicKey, compressed: compressed) else {return nil}
        return serializedKey
    }
    
    internal static func privateKeyToPublicKey(privateKey: Data) -> secp256k1_pubkey? {
        if (privateKey.count != 32) {return nil}
        var publicKey = secp256k1_pubkey()
        let result = privateKey.withUnsafeBytes { (privateKeyPointer:UnsafePointer<UInt8>) -> Int32 in
            let res = secp256k1_ec_pubkey_create(context, UnsafeMutablePointer<secp256k1_pubkey>(&publicKey), privateKeyPointer)
            return res
        }
        if result == 0 {
            return nil
        }
        return publicKey
    }
    
    public static func serializePublicKey(publicKey: inout secp256k1_pubkey, compressed: Bool = false) -> Data? {
        var keyLength = compressed ? 33 : 65
        var serializedPubkey = Data(repeating: 0x00, count: keyLength)
        let result = serializedPubkey.withUnsafeMutableBytes { (serializedPubkeyPointer:UnsafeMutablePointer<UInt8>) -> Int32 in
            withUnsafeMutablePointer(to: &keyLength, { (keyPtr:UnsafeMutablePointer<Int>) -> Int32 in
                withUnsafeMutablePointer(to: &publicKey, { (pubKeyPtr:UnsafeMutablePointer<secp256k1_pubkey>) -> Int32 in
                    let res = secp256k1_ec_pubkey_serialize(context,
                                                            serializedPubkeyPointer,
                                                            keyPtr,
                                                            pubKeyPtr,
                                                            UInt32(compressed ? SECP256K1_EC_COMPRESSED : SECP256K1_EC_UNCOMPRESSED))
                    return res
                })
            })
        }
        
        if result == 0 {
            return nil
        }
        return Data(serializedPubkey)
    }
    
    public static func verifyPrivateKey(privateKey: Data) -> Bool {
        if (privateKey.count != 32) {return false}
        let result = privateKey.withUnsafeBytes { (privateKeyPointer:UnsafePointer<UInt8>) -> Int32 in
            let res = secp256k1_ec_seckey_verify(context, privateKeyPointer)
            return res
        }
        return result == 1
    }
    
    public static func combineSerializedPublicKeys(keys: [Data], outputCompressed: Bool = false) -> Data? {
        let numToCombine = keys.count
        guard numToCombine >= 1 else { return nil}
        var storage = ContiguousArray<secp256k1_pubkey>()
        let arrayOfPointers = UnsafeMutablePointer< UnsafePointer<secp256k1_pubkey>? >.allocate(capacity: numToCombine)
        defer {
            arrayOfPointers.deinitialize(count: numToCombine)
            arrayOfPointers.deallocate()
        }
        for i in 0 ..< numToCombine {
            let key = keys[i]
            guard let pubkey = SECP256K1.parsePublicKey(serializedKey: key) else {return nil}
            storage.append(pubkey)
        }
        for i in 0 ..< numToCombine {
            withUnsafePointer(to: &storage[i]) { (ptr) -> Void in
                arrayOfPointers.advanced(by: i).pointee = ptr
            }
        }
        let immutablePointer = UnsafePointer(arrayOfPointers)
        var publicKey: secp256k1_pubkey = secp256k1_pubkey()
        let result = withUnsafeMutablePointer(to: &publicKey) { (pubKeyPtr: UnsafeMutablePointer<secp256k1_pubkey>) -> Int32 in
            let res = secp256k1_ec_pubkey_combine(context, pubKeyPtr, immutablePointer, numToCombine)
            return res
        }
        if result == 0 {
            return nil
        }
        let serializedKey = SECP256K1.serializePublicKey(publicKey: &publicKey, compressed: outputCompressed)
        return serializedKey
    }
    
    internal static func parsePublicKey(serializedKey: Data) -> secp256k1_pubkey? {
        guard serializedKey.count == 33 || serializedKey.count == 65 else {
            return nil
        }
        let keyLen: Int = Int(serializedKey.count)
        var publicKey = secp256k1_pubkey()
        let result = serializedKey.withUnsafeBytes { (serializedKeyPointer:UnsafePointer<UInt8>) -> Int32 in
            let res = secp256k1_ec_pubkey_parse(context, UnsafeMutablePointer<secp256k1_pubkey>(&publicKey), serializedKeyPointer, keyLen)
            return res
        }
        if result == 0 {
            return nil
        }
        return publicKey
    }
}

class EthereumHDNode {
    var path: String? = "m"
    var privateKey: Data? = nil
    var publicKey: Data
    var chaincode: Data
    var depth: UInt8
    var parentFingerprint: Data = Data(repeating: 0, count: 4)
    var childNumber: UInt32 = UInt32(0)
    
    var isHardened:Bool {
        get {
            return self.childNumber >= (UInt32(1) << 31)
        }
    }
    
    var index: UInt32 {
        get {
            if self.isHardened {
                return self.childNumber - (UInt32(1) << 31)
            } else {
                return self.childNumber
            }
        }
    }
    
    var hasPrivate:Bool {
        get {
            return privateKey != nil
        }
    }
    
    init() {
        publicKey = Data()
        chaincode = Data()
        depth = UInt8(0)
    }
    
    public init?(_ data: Data) {
        guard data.count == 77 else {return nil}
       
        depth = data[0..<1].bytes[0]
        parentFingerprint = data[1..<5]
        let cNum = data[5..<9].bytes
        childNumber = UnsafePointer(cNum).withMemoryRebound(to: UInt32.self, capacity: 1) {
            $0.pointee
        }
        chaincode = data[9..<41]
        privateKey = data[41..<73]
        
        guard let pubKey = SECP256K1.privateToPublic(privateKey: privateKey!, compressed: false) else {return nil}
        if pubKey[0] != 0x04 {return nil}
        publicKey = pubKey
        
        let hashedData = data[0..<73].sha256().sha256()
        let checksum = hashedData[0..<4]
        if checksum != data[73..<77] {return nil}
    }
    
    public init?(seed: Data) {
        guard seed.count >= 16 else {return nil}
        let hmacKey = "Bitcoin seed".data(using: .ascii)!
        let hmac:Authenticator = HMAC(key: hmacKey.bytes, variant: HMAC.Variant.sha512)
        guard let entropy = try? hmac.authenticate(seed.bytes) else {return nil}
        guard entropy.count == 64 else { return nil}
        let I_L = entropy[0..<32]
        let I_R = entropy[32..<64]
        chaincode = Data(I_R)
        let privKeyCandidate = Data(I_L)
        guard SECP256K1.verifyPrivateKey(privateKey: privKeyCandidate) else {return nil}
        guard let pubKeyCandidate = SECP256K1.privateToPublic(privateKey: privKeyCandidate, compressed: false) else {return nil}
        guard pubKeyCandidate.bytes[0] == 0x04 else {return nil}
        publicKey = pubKeyCandidate
        privateKey = privKeyCandidate
        depth = 0x00
        childNumber = UInt32(0)
    }
    
    private static var curveOrder = BigUInt("FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141", radix: 16)!
    public static var hardenedIndexPrefix: UInt32 = (UInt32(1) << 31)
    
    public static var hexadecimalNumbers: CharacterSet {
        return ["0", "1", "2", "3", "4", "5", "6", "7", "8", "9"]
    }
}

extension EthereumHDNode {
    private func derivePrivate(index: UInt32, hardened: Bool = false) -> EthereumHDNode? {
        guard hasPrivate else { return nil } // derive private key when is itself extended public key is impossible
        
        var entropy:Array<UInt8>
        var trueIndex: UInt32
        if index >= (UInt32(1) << 31) || hardened {
            trueIndex = index;
            if trueIndex < (UInt32(1) << 31) {
                trueIndex = trueIndex + (UInt32(1) << 31)
            }
            let hmac:Authenticator = HMAC(key: self.chaincode.bytes, variant: .sha512)
            var inputForHMAC = Data()
            inputForHMAC.append(Data([UInt8(0x00)]))
            inputForHMAC.append(self.privateKey!)
            inputForHMAC.append(trueIndex.serialize32())
            guard let ent = try? hmac.authenticate(inputForHMAC.bytes) else {return nil }
            guard ent.count == 64 else { return nil }
            entropy = ent
        } else {
            trueIndex = index
            let hmac:Authenticator = HMAC(key: self.chaincode.bytes, variant: .sha512)
            var inputForHMAC = Data()
            inputForHMAC.append(self.publicKey)
            inputForHMAC.append(trueIndex.serialize32())
            guard let ent = try? hmac.authenticate(inputForHMAC.bytes) else {return nil }
            guard ent.count == 64 else { return nil }
            entropy = ent
        }
        let I_L = entropy[0..<32]
        let I_R = entropy[32..<64]
        let cc = Data(I_R)
        let bn = BigUInt(Data(I_L))
        if bn > EthereumHDNode.curveOrder {
            if trueIndex < UInt32.max {
                return self.derivePrivate(index:index+1, hardened:hardened)
            }
            return nil
        }
        let newPK = (bn + BigUInt(self.privateKey!)) % EthereumHDNode.curveOrder
        if newPK == BigUInt(0) {
            if trueIndex < UInt32.max {
                return self.derivePrivate(index:index+1, hardened:hardened)
            }
            return nil
        }
        guard let privKeyCandidate = newPK.serialize().setLengthLeft(32) else {return nil}
        guard SECP256K1.verifyPrivateKey(privateKey: privKeyCandidate) else {return nil }
        guard let pubKeyCandidate = SECP256K1.privateToPublic(privateKey: privKeyCandidate, compressed: true) else {return nil}
        guard pubKeyCandidate[0] == 0x02 || pubKeyCandidate[0] == 0x03 else {return nil}
        guard self.depth < UInt8.max else {return nil}
        let newNode = EthereumHDNode()
        newNode.chaincode = cc
        newNode.depth = self.depth + 1
        newNode.publicKey = pubKeyCandidate
        newNode.privateKey = privKeyCandidate
        newNode.childNumber = trueIndex
        let fprint = RIPEMD160.hash(message: self.publicKey.sha256())[0..<4]
        newNode.parentFingerprint = fprint
        var newPath = String()
        if newNode.isHardened {
            newPath = self.path! + "/"
            newPath += String(newNode.index % EthereumHDNode.hardenedIndexPrefix) + "'"
        } else {
            newPath = self.path! + "/" + String(newNode.index)
        }
        newNode.path = newPath
        return newNode
    }
    
    private func derivePublic(index: UInt32, hardened: Bool = false) -> EthereumHDNode? {
        var entropy:Array<UInt8> // derive public key when is itself public key
        if index >= (UInt32(1) << 31) || hardened {
            return nil // no derivation of hardened public key from extended public key
        } else {
            let hmac:Authenticator = HMAC(key: self.chaincode.bytes, variant: .sha512)
            var inputForHMAC = Data()
            inputForHMAC.append(self.publicKey)
            inputForHMAC.append(index.serialize32())
            guard let ent = try? hmac.authenticate(inputForHMAC.bytes) else {return nil }
            guard ent.count == 64 else { return nil }
            entropy = ent
        }
        let I_L = entropy[0..<32]
        let I_R = entropy[32..<64]
        let cc = Data(I_R)
        let bn = BigUInt(Data(I_L))
        if bn > EthereumHDNode.curveOrder {
            if index < UInt32.max {
                return self.derivePublic(index:index+1, hardened:hardened)
            }
            return nil
        }
        guard let tempKey = bn.serialize().setLengthLeft(32) else {return nil}
        guard SECP256K1.verifyPrivateKey(privateKey: tempKey) else {return nil }
        guard let pubKeyCandidate = SECP256K1.privateToPublic(privateKey: tempKey, compressed: true) else {return nil}
        guard pubKeyCandidate.bytes[0] == 0x02 || pubKeyCandidate.bytes[0] == 0x03 else {return nil}
        guard let newPublicKey = SECP256K1.combineSerializedPublicKeys(keys: [self.publicKey, pubKeyCandidate], outputCompressed: true) else {return nil}
        guard newPublicKey.bytes[0] == 0x02 || newPublicKey.bytes[0] == 0x03 else {return nil}
        guard self.depth < UInt8.max else {return nil}
        let newNode = EthereumHDNode()
        newNode.chaincode = cc
        newNode.depth = self.depth + 1
        newNode.publicKey = pubKeyCandidate
        newNode.childNumber = index
        let fprint = RIPEMD160.hash(message: self.publicKey.sha256())[0..<4]
        newNode.parentFingerprint = fprint
        var newPath = String()
        if newNode.isHardened {
            newPath = self.path! + "/"
            newPath += String(newNode.index % EthereumHDNode.hardenedIndexPrefix) + "'"
        } else {
            newPath = self.path! + "/" + String(newNode.index)
        }
        newNode.path = newPath
        return newNode
    }
    
    public func derive(index: UInt32, derivePrivateKey:Bool, hardened: Bool = false) -> EthereumHDNode? {
        if derivePrivateKey {
            return derivePrivate(index: index, hardened: hardened)
        } else { // deriving only the public key
            return derivePublic(index: index, hardened: hardened)
        }
    }
    
    public func derive (path: String, derivePrivateKey: Bool = true) -> EthereumHDNode? {
        let components = path.components(separatedBy: "/")
        var currentNode:EthereumHDNode = self
        var firstComponent = 0
        if path.hasPrefix("m") {
            firstComponent = 1
        }
        for component in components[firstComponent ..< components.count] {
            var hardened = false
            if component.hasSuffix("'") {
                hardened = true
            }
            guard let index = UInt32(component.trimmingCharacters(in: CharacterSet(charactersIn: "'"))) else {return nil}
            guard let newNode = currentNode.derive(index: index, derivePrivateKey: derivePrivateKey, hardened: hardened) else {return nil}
            currentNode = newNode
        }
        return currentNode
    }
    
    public func serialize() -> Data? {
        guard hasPrivate else { return nil }
        var data = Data()
        
        data.append(contentsOf: [self.depth])
        data.append(self.parentFingerprint)
        data.append(self.childNumber.serialize32())
        data.append(self.chaincode)
        
        data.append(self.privateKey!)
        
        let hashedData = data.sha256().sha256()
        let checksum = hashedData[0..<4]
        data.append(checksum)
        return data
    }
    
    public func sign(data: Data) -> Data? {
        var hash = SHA3(variant: .keccak256).calculate(for: data.bytes)
        
        guard hash.count == 32 else {
            return nil
        }
        guard var pk = privateKey?.bytes else {
            return nil
        }
        guard let sig = malloc(MemoryLayout<secp256k1_ecdsa_recoverable_signature>.size)?.assumingMemoryBound(to: secp256k1_ecdsa_recoverable_signature.self) else {
            return nil
        }
        defer {
            free(sig)
        }
        
        guard secp256k1_ecdsa_sign_recoverable(SECP256K1.context, sig, &hash, &pk, nil, nil) == 1 else {
            return nil
        }
        
        var output64 = Array<UInt8>(repeating: 0, count: 64)
        var recid: Int32 = 0
        secp256k1_ecdsa_recoverable_signature_serialize_compact(SECP256K1.context, &output64, &recid, sig)
        
        guard recid == 0 || recid == 1 else {
            return nil
        }
        
        var response = Data(output64)
        response.append(UInt8(recid))
        return response
    }
    
    public func verifySignature(message: Data, signature: Data) -> Bool? {
        guard signature.count == 65 else {
            return nil
        }
        
        var rawpubKey = publicKey.bytes
   
        guard let pubkey = malloc(MemoryLayout<secp256k1_pubkey>.size)?.assumingMemoryBound(to: secp256k1_pubkey.self) else {
            return nil
        }
        defer {
            free(pubkey)
        }
        guard secp256k1_ec_pubkey_parse(SECP256K1.context, pubkey, &rawpubKey, rawpubKey.count) == 1 else {
            return nil
        }
        
        var rawSig = signature.bytes
        let v = Int32(rawSig.removeLast())
        
        // Parse recoverable signature
        guard let recsig = malloc(MemoryLayout<secp256k1_ecdsa_recoverable_signature>.size)?.assumingMemoryBound(to: secp256k1_ecdsa_recoverable_signature.self) else {
            return nil
        }
        defer {
            free(recsig)
        }
        guard secp256k1_ecdsa_recoverable_signature_parse_compact(SECP256K1.context, recsig, &rawSig, v) == 1 else {
            return nil
        }
        
        // Convert to normal signature
        guard let sig = malloc(MemoryLayout<secp256k1_ecdsa_signature>.size)?.assumingMemoryBound(to: secp256k1_ecdsa_signature.self) else {
            return nil
        }
        defer {
            free(sig)
        }
        guard secp256k1_ecdsa_recoverable_signature_convert(SECP256K1.context, sig, recsig) == 1 else {
            return nil
        }
        
        // Check validity with signature
        var hash = SHA3(variant: .keccak256).calculate(for: message.bytes)
        guard hash.count == 32 else {
            return nil
        }
        return secp256k1_ecdsa_verify(SECP256K1.context, sig, &hash, pubkey) == 1
    }
    
    public func address() -> Data? {
        guard var parsed = SECP256K1.parsePublicKey(serializedKey: publicKey) else { return nil }
        guard var mPubKey = SECP256K1.serializePublicKey(publicKey: &parsed, compressed: false)?.bytes else { return nil }
        mPubKey.remove(at: 0)
        var hash = SHA3(variant: .keccak256).calculate(for: mPubKey)
        guard hash.count == 32 else {
            return nil
        }
        return Data(hash[12...])
    }
    
    public func hexAddress(eip55: Bool) -> String? {
        guard let rawAddress = address()?.bytes else {
            return nil
        }
        var hex = "0x"
        if !eip55 {
            for b in rawAddress {
                hex += String(format: "%02x", b)
            }
        } else {
            var address = ""
            for b in rawAddress {
                address += String(format: "%02x", b)
            }
            let hash = SHA3(variant: .keccak256).calculate(for: Array(address.utf8))
            
            for i in 0..<address.count {
                let charString = String(address[address.index(address.startIndex, offsetBy: i)])
                
                if charString.rangeOfCharacter(from: EthereumHDNode.hexadecimalNumbers) != nil {
                    hex += charString
                    continue
                }
                
                let bytePos = (4 * i) / 8
                let bitPos = (4 * i) % 8
                let bit = (hash[bytePos] >> (7 - UInt8(bitPos))) & 0x01
                
                if bit == 1 {
                    hex += charString.uppercased()
                } else {
                    hex += charString.lowercased()
                }
            }
        }
        
        return hex
    }

}
