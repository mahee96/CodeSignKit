//
//  DEREncoderTests.swift
//  CodeSignKitTests
//
//  Created by Magesh K on 28/08/26.
//  Copyright © 2026 CodeSignKit. All rights reserved.
//

import Testing
import Foundation
@testable import CodeSignKit

@Suite
struct DEREncoderTests {

    @Test
    func encodeString() throws {
        let str = "com.example.app"
        let der = try #require(DEREncoder.encodeValue(str))
        #expect(!der.isEmpty)
        // Check ASN.1 UTF8String tag 0x0C
        #expect(der[0] == 0x0C)
        #expect(der[1] == UInt8(str.utf8.count))
    }

    @Test
    func encodeBoolean() throws {
        let trueDER = try #require(DEREncoder.encodeValue(true))
        let falseDER = try #require(DEREncoder.encodeValue(false))
        #expect(trueDER == Data([0x01, 0x01, 0xFF]))
        #expect(falseDER == Data([0x01, 0x01, 0x00]))
    }

    @Test
    func encodeInteger() throws {
        let smallInt = NSNumber(value: 42)
        let smallDER = try #require(DEREncoder.encodeValue(smallInt))
        #expect(smallDER == Data([0x02, 0x01, 0x2A]))

        // Positive integer with high bit set requiring 0x00 padding byte
        let highInt = NSNumber(value: 128)
        let highDER = try #require(DEREncoder.encodeValue(highInt))
        #expect(highDER == Data([0x02, 0x02, 0x00, 0x80]))
    }

    @Test
    func encodeArray() throws {
        let array = ["item1", "item2"]
        let der = try #require(DEREncoder.encodeValue(array))
        #expect(!der.isEmpty)
        // Check Sequence tag 0x30
        #expect(der[0] == 0x30)
    }

    @Test
    func encodeDictionary() throws {
        let dict: [String: Any] = [
            "application-identifier": "TEAM12345.com.example.app",
            "get-task-allow": true,
            "custom-count": NSNumber(value: 10)
        ]
        let der = try #require(DEREncoder.encodeValue(dict))
        #expect(!der.isEmpty)
        // Check Dictionary tag 0xB0
        #expect(der[0] == 0xB0)
    }

    @Test
    func encodeNestedDictionary() throws {
        let dict: [String: Any] = [
            "key1": "value1",
            "nested": [
                "sub-key": NSNumber(value: 100),
                "bool-sub": false
            ]
        ]
        let der = try #require(DEREncoder.encodeValue(dict))
        #expect(!der.isEmpty)
        #expect(der[0] == 0xB0)
    }

    @Test
    func encodePlistXML() throws {
        let xml = """
        <?xml version="1.0" encoding="UTF-8"?>
        <!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
        <plist version="1.0">
        <dict>
            <key>application-identifier</key>
            <string>TEAM123.com.example.app</string>
            <key>get-task-allow</key>
            <true/>
        </dict>
        </plist>
        """
        let der = try #require(DEREncoder.encodePlistXML(xml))
        #expect(!der.isEmpty)
        // Check Outer tag 0x70
        #expect(der[0] == 0x70)
    }
}


