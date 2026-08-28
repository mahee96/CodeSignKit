//
//  DEREncoder.swift
//  CodeSignKit
//
//  Created by Magesh K on 28/08/26.
//  Copyright © 2026 CodeSignKit. All rights reserved.
//

import Foundation

public enum DEREncoder {

    public static func encodeLength(_ length: Int) -> Data {
        if length < 128 {
            return Data([UInt8(length)])
        }
        var len = length
        var bytes: [UInt8] = []
        while len > 0 {
            bytes.insert(UInt8(len & 0xFF), at: 0)
            len >>= 8
        }
        return Data([UInt8(0x80 | bytes.count)] + bytes)
    }

    public static func encodeTLV(tag: UInt8, value: Data) -> Data {
        return Data([tag]) + encodeLength(value.count) + value
    }

    public static func encodeValue(_ value: Any) -> Data? {
        if let num = value as? NSNumber {

            if CFGetTypeID(num) == CFBooleanGetTypeID() {
                return encodeTLV(tag: 0x01, value: Data([num.boolValue ? 0xFF : 0x00]))
            }
            let intVal = num.int64Value
            var bigEndian = intVal.bigEndian
            var rawBytes = Array(Swift.withUnsafeBytes(of: &bigEndian) { $0 })
            while rawBytes.count > 1 && rawBytes[0] == 0 && (rawBytes[1] & 0x80) == 0 {
                rawBytes.removeFirst()
            }
            while rawBytes.count > 1 && rawBytes[0] == 0xFF && (rawBytes[1] & 0x80) != 0 {
                rawBytes.removeFirst()
            }
            return encodeTLV(tag: 0x02, value: Data(rawBytes))
        } else if let b = value as? Bool {
            return encodeTLV(tag: 0x01, value: Data([b ? 0xFF : 0x00]))

        } else if let str = value as? String {
            let utf8 = str.data(using: .utf8) ?? Data()
            return encodeTLV(tag: 0x0C, value: utf8)
        } else if let dataVal = value as? Data {
            return encodeTLV(tag: 0x04, value: dataVal)
        } else if let arr = value as? [Any] {
            var payload = Data()
            for item in arr {
                guard let encoded = encodeValue(item) else { return nil }
                payload.append(encoded)
            }
            return encodeTLV(tag: 0x30, value: payload)
        } else if let dict = value as? [String: Any] {
            var elements: [(key: String, itemData: Data)] = []
            for (k, v) in dict {
                let kData = encodeTLV(tag: 0x0C, value: k.data(using: .utf8) ?? Data())
                guard let vData = encodeValue(v) else { return nil }
                let pairData = encodeTLV(tag: 0x30, value: kData + vData)
                elements.append((k, pairData))
            }
            elements.sort { $0.key < $1.key }
            var dictPayload = Data()
            for el in elements {
                dictPayload.append(el.itemData)
            }
            return encodeTLV(tag: 0xB0, value: dictPayload)
        }

        return nil
    }

    public static func encodePlistXML(_ xml: String) -> Data? {
        guard let data = xml.data(using: .utf8) else { return nil }
        guard let plist = try? PropertyListSerialization.propertyList(from: data, options: [], format: nil) as? [String: Any] else {
            return nil
        }
        guard let dictData = encodeValue(plist) else { return nil }
        let versionData = Data([0x02, 0x01, 0x01]) // INTEGER 1
        return encodeTLV(tag: 0x70, value: versionData + dictData)
    }
}

