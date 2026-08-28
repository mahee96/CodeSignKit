//
//  RequirementsBuilderTests.swift
//  CodeSignKitTests
//
//  Created by Magesh K on 28/08/26.
//  Copyright © 2026 CodeSignKit. All rights reserved.
//

import Testing
import Foundation
@testable import CodeSignKit

@Suite
struct RequirementsBuilderTests {

    @Test
    func designatedRequirementGeneration() throws {
        let bundleID = "com.example.sampleapp"

        let reqData = RequirementsBuilder.buildDesignatedRequirement(bundleIdentifier: bundleID)
        #expect(reqData.count > 12)

        // SuperBlob magic for requirements set: 0xfade0c01
        let setMagic = reqData.withUnsafeBytes { $0.loadUnaligned(as: UInt32.self).bigEndian }
        #expect(setMagic == CodeSigningConstants.CSMAGIC_REQUIREMENTS)

        // Count of requirement elements in set (1 element: Designated Requirement)
        let count = reqData.withUnsafeBytes { $0.loadUnaligned(fromByteOffset: 8, as: UInt32.self).bigEndian }
        #expect(count == 1)

        // Inner Requirement magic: 0xfade0c00
        let reqBlobOffset = 12 + 8 // 12 header + 8 directory entry
        let reqMagic = reqData.withUnsafeBytes { $0.loadUnaligned(fromByteOffset: reqBlobOffset, as: UInt32.self).bigEndian }
        #expect(reqMagic == CodeSigningConstants.CSMAGIC_REQUIREMENT)
    }
}

