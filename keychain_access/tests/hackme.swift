#!/usr/bin/swift

import Foundation
import Security

sleep(1) // so Frida has time to attach

enum KeychainError : Error {
    case Open(message: String)
    case Unlock(message: String)
    case ItemNotFound
}

// Query password from keychain
let query: [String: Any] = [kSecClass as String: kSecClassGenericPassword,
                            kSecAttrLabel as String: "org.owlink.findme",
                            kSecReturnData as String: true]
var item: CFTypeRef?
let status = SecItemCopyMatching(query as CFDictionary, &item)
guard status == errSecSuccess else { throw KeychainError.ItemNotFound }
