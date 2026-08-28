//
//  CodeDirectoryBuilderTests.swift
//  CodeSignKitTests
//
//  Created by Magesh K on 28/08/26.
//  Copyright © 2026 CodeSignKit. All rights reserved.
//

import Testing
import Foundation
import Crypto
@testable import CodeSignKit

@Suite
struct CodeDirectoryBuilderTests {

    @Test
    func codeDirectoryStructure() throws {
        let dummyCode = Data(repeating: 0x90, count: 16384) // 16KB dummy binary

        let builder = CodeDirectoryBuilder(
            binaryData: dummyCode,
            codeLimit: dummyCode.count,
            bundleIdentifier: "com.example.test",
            teamIdentifier: "TEAM123456",
            hashType: CodeSigningConstants.CS_HASHTYPE_SHA256,
            pageSizeShift: 12 // 4096 bytes per page
        )

        builder.setSpecialSlot(CodeSigningConstants.CSSLOT_INFOSLOT, data: Data("<plist></plist>".utf8))
        builder.setSpecialSlot(CodeSigningConstants.CSSLOT_ENTITLEMENTS, data: Data("<plist></plist>".utf8))

        let cdData = builder.build()
        #expect(cdData.count >= 88)

        // Magic 0xfade0c02
        let magic = cdData.withUnsafeBytes { $0.loadUnaligned(as: UInt32.self).bigEndian }
        #expect(magic == CodeSigningConstants.CSMAGIC_CODEDIRECTORY)

        // Version 0x20400
        let version = cdData.withUnsafeBytes { $0.loadUnaligned(fromByteOffset: 8, as: UInt32.self).bigEndian }
        #expect(version == CodeSigningConstants.CS_SUPPORTED_CD_VERSION)

        // Hash offset
        let hashOffset = Int(cdData.withUnsafeBytes { $0.loadUnaligned(fromByteOffset: 16, as: UInt32.self).bigEndian })
        #expect(hashOffset > 88)

        // Ident offset
        let identOffset = Int(cdData.withUnsafeBytes { $0.loadUnaligned(fromByteOffset: 20, as: UInt32.self).bigEndian })
        #expect(identOffset == 88)

        // Num special slots (at least 5 because CSSLOT_ENTITLEMENTS = 5)
        let numSpecialSlots = Int(cdData.withUnsafeBytes { $0.loadUnaligned(fromByteOffset: 24, as: UInt32.self).bigEndian })
        #expect(numSpecialSlots >= 5)

        // Num pages (16384 / 4096 = 4 pages)
        let numPages = Int(cdData.withUnsafeBytes { $0.loadUnaligned(fromByteOffset: 28, as: UInt32.self).bigEndian })
        #expect(numPages == 4)

        // Code limit (16384)
        let codeLimit = Int(cdData.withUnsafeBytes { $0.loadUnaligned(fromByteOffset: 32, as: UInt32.self).bigEndian })
        #expect(codeLimit == 16384)

        // Hash type & size
        #expect(cdData[36] == 32) // SHA256 size
        #expect(cdData[37] == CodeSigningConstants.CS_HASHTYPE_SHA256)
        #expect(cdData[39] == 12) // pageSizeShift
    }
}

