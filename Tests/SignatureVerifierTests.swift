//
//  SignatureVerifierTests.swift
//  CodeSignKitTests
//
//  Created by Magesh K on 28/08/26.
//  Copyright © 2026 CodeSignKit. All rights reserved.
//

import Testing
import Foundation
@testable import CodeSignKit

@Suite
struct SignatureVerifierTests {

    private func createSignedMachOBinary() throws -> Data {
        var data = Data(count: 8192)
        var magic = CodeSigningConstants.MH_MAGIC_64
        data.replaceSubrange(0..<4, with: Swift.withUnsafeBytes(of: &magic) { Data($0) })
        var cputype: UInt32 = 0x0100000C
        data.replaceSubrange(4..<8, with: Swift.withUnsafeBytes(of: &cputype) { Data($0) })
        var filetype: UInt32 = 2
        data.replaceSubrange(12..<16, with: Swift.withUnsafeBytes(of: &filetype) { Data($0) })
        var ncmds: UInt32 = 1
        data.replaceSubrange(16..<20, with: Swift.withUnsafeBytes(of: &ncmds) { Data($0) })
        var sizeofcmds: UInt32 = 72
        data.replaceSubrange(20..<24, with: Swift.withUnsafeBytes(of: &sizeofcmds) { Data($0) })
        var cmd: UInt32 = CodeSigningConstants.LC_SEGMENT_64
        data.replaceSubrange(32..<36, with: Swift.withUnsafeBytes(of: &cmd) { Data($0) })
        var cmdsize: UInt32 = 72
        data.replaceSubrange(36..<40, with: Swift.withUnsafeBytes(of: &cmdsize) { Data($0) })
        let segName = "__TEXT".data(using: .utf8)!
        data.replaceSubrange(40..<40 + segName.count, with: segName)
        var vmsize: UInt64 = 8192
        data.replaceSubrange(56..<64, with: Swift.withUnsafeBytes(of: &vmsize) { Data($0) })
        var filesize: UInt64 = 8192
        data.replaceSubrange(72..<80, with: Swift.withUnsafeBytes(of: &filesize) { Data($0) })

        let signer = MachOSigner(
            binaryData: data,
            bundleIdentifier: "com.example.verifier.test",
            teamIdentifier: "TEAM123456",
            entitlementsXML: "<plist><dict><key>get-task-allow</key><true/></dict></plist>",
            infoPlistData: nil,
            codeResourcesData: nil,
            cmsSigner: nil
        )
        return try signer.sign()
    }

    @Test
    func verifyTamperedCodePage() throws {
        var signedData = try createSignedMachOBinary()

        // Verify initial page hashes are correct
        let initialResult = SignatureVerifier.verify(binaryData: signedData)
        #expect(initialResult.bundleIdentifier == "com.example.verifier.test")
        #expect(initialResult.teamIdentifier == "TEAM123456")
        #expect(initialResult.cdHash != nil)

        // Tamper 1 byte in the executable code segment (page 0)
        signedData[100] ^= 0xFF

        // Verify after tampering
        let tamperedResult = SignatureVerifier.verify(binaryData: signedData)
        #expect(!tamperedResult.isValid)
        #expect(tamperedResult.errors.contains { $0.contains("tampered binary content") })
    }

    @Test
    func verifyUnsignedBinary() throws {
        let unsigned = Data(repeating: 0, count: 4096)
        let result = SignatureVerifier.verify(binaryData: unsigned)
        #expect(!result.isValid)
    }

    @Test(.enabled(if: TestFixtures.isClangAvailable))
    func verifyRealCompiledBinaryAndTamperDetection() throws {

        let realBinary = try TestFixtures.compileRealMachOBinary(fat: false)

        let (p12Data, _, _) = try TestFixtures.createSelfSignedP12(password: "test")
        let cms = CMSSigner(p12Data: p12Data, password: "test")

        let signer = MachOSigner(
            binaryData: realBinary,
            bundleIdentifier: "com.example.realtamper",
            teamIdentifier: "TEAM123456",
            entitlementsXML: "<plist><dict><key>get-task-allow</key><true/></dict></plist>",
            infoPlistData: nil,
            codeResourcesData: nil,
            cmsSigner: cms,
            isMainExecutable: true
        )

        var signedData = try signer.sign()

        // 1. Native verification on untampered real binary
        let validResult = SignatureVerifier.verify(binaryData: signedData)
        #expect(validResult.isValid)
        #expect(validResult.bundleIdentifier == "com.example.realtamper")
        #expect(validResult.teamIdentifier == "TEAM123456")
        #expect(validResult.cdHash != nil)

        // 2. Tamper real machine code in the __TEXT segment (page 0)
        signedData[0x1000] ^= 0xFF

        // 3. Verify that native engine detects real code page tampering
        let tamperedResult = SignatureVerifier.verify(binaryData: signedData)
        #expect(!tamperedResult.isValid)
        #expect(tamperedResult.errors.contains { $0.contains("tampered binary content") })
    }
}


