//
//  RequirementsBuilder.swift
//  CodeSignKit
//
//  Created by Magesh K on 28/08/26.
//  Copyright © 2026 CodeSignKit. All rights reserved.
//

import Foundation
import Crypto

public struct RequirementsBuilder {
    private static let opAnd: UInt32 = 6
    private static let opIdent: UInt32 = 2
    private static let opCertField: UInt32 = 4
    private static let matchEqual: UInt32 = 0
    private static let certLeaf: UInt32 = 0xFFFFFFFF // -1 = leaf certificate


    public static func buildDesignatedRequirement(bundleIdentifier: String, certSHA1: Data? = nil) -> Data {
        var exprData = Data()

        var identBytes = bundleIdentifier.data(using: .utf8) ?? Data()
        let identLen = UInt32(identBytes.count)
        let pad = (4 - (identBytes.count % 4)) % 4
        if pad > 0 {
            identBytes.append(Data(repeating: 0, count: pad))
        }

        if let certSHA1, certSHA1.count == 20 {
            // opAnd
            exprData.writeUInt32BigEndian(opAnd)
            // opIdent <len> <identBytes>
            exprData.writeUInt32BigEndian(opIdent)
            exprData.writeUInt32BigEndian(identLen)
            exprData.append(identBytes)
            // opCertField <certSlot: -1> <matchEqual> <20-byte SHA-1>
            exprData.writeUInt32BigEndian(opCertField)
            exprData.writeUInt32BigEndian(certLeaf)
            exprData.writeUInt32BigEndian(UInt32(certSHA1.count))
            exprData.append(certSHA1)
        } else {
            // opIdent <len> <identBytes>
            exprData.writeUInt32BigEndian(opIdent)
            exprData.writeUInt32BigEndian(identLen)
            exprData.append(identBytes)
        }

        // Single requirement expr blob: header (12 bytes) + exprData
        let exprBlobSize = 12 + exprData.count
        var exprBlob = Data(count: exprBlobSize)
        exprBlob.writeUInt32BigEndian(CodeSigningConstants.CSMAGIC_REQUIREMENT, at: 0)
        exprBlob.writeUInt32BigEndian(UInt32(exprBlobSize), at: 4)
        exprBlob.writeUInt32BigEndian(1 /* exprForm = 1 */, at: 8)
        exprBlob.replaceSubrange(12..<exprBlobSize, with: exprData)

        // Requirements superblob: header (12 bytes) + 1 entry (8 bytes) + exprBlob
        let totalSize = 12 + 8 + exprBlob.count
        var reqSuperBlob = Data(count: totalSize)
        reqSuperBlob.writeUInt32BigEndian(CodeSigningConstants.CSMAGIC_REQUIREMENTS, at: 0)
        reqSuperBlob.writeUInt32BigEndian(UInt32(totalSize), at: 4)
        reqSuperBlob.writeUInt32BigEndian(1 /* count = 1 */, at: 8)

        // Entry 0: type = 3 (kSecDesignatedRequirementType), offset = 20
        reqSuperBlob.writeUInt32BigEndian(3, at: 12)
        reqSuperBlob.writeUInt32BigEndian(20, at: 16)
        reqSuperBlob.replaceSubrange(20..<totalSize, with: exprBlob)

        return reqSuperBlob
    }

    public static func buildEmpty() -> Data {
        var reqBlob = Data(count: 12)
        reqBlob.writeUInt32BigEndian(CodeSigningConstants.CSMAGIC_REQUIREMENTS, at: 0)
        reqBlob.writeUInt32BigEndian(12, at: 4)
        reqBlob.writeUInt32BigEndian(0, at: 8)
        return reqBlob
    }
}

fileprivate extension Data {
    mutating func writeUInt32BigEndian(_ value: UInt32) {
        var bigEndian = value.bigEndian
        Swift.withUnsafeBytes(of: &bigEndian) { bytes in
            self.append(contentsOf: bytes)
        }
    }

    mutating func writeUInt32BigEndian(_ value: UInt32, at offset: Int) {
        var bigEndian = value.bigEndian
        Swift.withUnsafeBytes(of: &bigEndian) { bytes in
            self.replaceSubrange(offset..<offset + 4, with: bytes)
        }
    }
}
