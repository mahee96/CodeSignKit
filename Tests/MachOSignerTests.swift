//
//  MachOSignerTests.swift
//  CodeSignKitTests
//
//  Created by Magesh K on 28/08/26.
//  Copyright © 2026 CodeSignKit. All rights reserved.
//

import Testing
import Foundation
@testable import CodeSignKit

@Suite
struct MachOSignerTests {

    // Helper to generate a minimal valid 64-bit Mach-O executable header
    private func createDummyMachOBinary() -> Data {
        var data = Data(count: 16384)
        // MH_MAGIC_64 (0xfeedfacf)
        var magic = CodeSigningConstants.MH_MAGIC_64
        data.replaceSubrange(0..<4, with: Swift.withUnsafeBytes(of: &magic) { Data($0) })

        // cputype = CPU_TYPE_ARM64 (0x0100000C)
        var cputype: UInt32 = 0x0100000C
        data.replaceSubrange(4..<8, with: Swift.withUnsafeBytes(of: &cputype) { Data($0) })

        // filetype = MH_EXECUTE (2)
        var ft: UInt32 = 2
        data.replaceSubrange(12..<16, with: Swift.withUnsafeBytes(of: &ft) { Data($0) })

        // ncmds = 7 (__PAGEZERO, __TEXT, __LINKEDIT, LC_LOAD_DYLINKER, LC_MAIN, LC_BUILD_VERSION, LC_LOAD_DYLIB)
        var ncmds: UInt32 = 7
        data.replaceSubrange(16..<20, with: Swift.withUnsafeBytes(of: &ncmds) { Data($0) })

        // sizeofcmds = 72 + 152 + 72 + 32 + 24 + 24 + 56 = 432
        var sizeofcmds: UInt32 = 432
        data.replaceSubrange(20..<24, with: Swift.withUnsafeBytes(of: &sizeofcmds) { Data($0) })

        // flags = MH_NOUNDEFS | MH_DYLDLINK | MH_TWOLEVEL | MH_PIE (0x00200085)
        var flags: UInt32 = 0x00200085
        data.replaceSubrange(24..<28, with: Swift.withUnsafeBytes(of: &flags) { Data($0) })

        // 1. LC_SEGMENT_64 (__PAGEZERO) at offset 32 (size 72)
        var cmd1: UInt32 = CodeSigningConstants.LC_SEGMENT_64
        data.replaceSubrange(32..<36, with: Swift.withUnsafeBytes(of: &cmd1) { Data($0) })
        var cmdsize1: UInt32 = 72
        data.replaceSubrange(36..<40, with: Swift.withUnsafeBytes(of: &cmdsize1) { Data($0) })
        let pageZeroName = "__PAGEZERO".data(using: .utf8)!
        data.replaceSubrange(40..<40 + pageZeroName.count, with: pageZeroName)
        var pzVmSize: UInt64 = 0x100000000
        data.replaceSubrange(56..<64, with: Swift.withUnsafeBytes(of: &pzVmSize) { Data($0) })

        // 2. LC_SEGMENT_64 (__TEXT) at offset 104 (size 152 = 72 + 80)
        var cmd2: UInt32 = CodeSigningConstants.LC_SEGMENT_64
        data.replaceSubrange(104..<108, with: Swift.withUnsafeBytes(of: &cmd2) { Data($0) })
        var cmdsize2: UInt32 = 152
        data.replaceSubrange(108..<112, with: Swift.withUnsafeBytes(of: &cmdsize2) { Data($0) })
        let textSegName = "__TEXT".data(using: .utf8)!
        data.replaceSubrange(112..<112 + textSegName.count, with: textSegName)
        var textVmAddr: UInt64 = 0x100000000
        data.replaceSubrange(120..<128, with: Swift.withUnsafeBytes(of: &textVmAddr) { Data($0) })
        var textVmSize: UInt64 = 16384
        data.replaceSubrange(128..<136, with: Swift.withUnsafeBytes(of: &textVmSize) { Data($0) })
        var textFileOff: UInt64 = 0
        data.replaceSubrange(136..<144, with: Swift.withUnsafeBytes(of: &textFileOff) { Data($0) })
        var textFileSize: UInt64 = 16384
        data.replaceSubrange(144..<152, with: Swift.withUnsafeBytes(of: &textFileSize) { Data($0) })
        var textMaxProt: UInt32 = 7
        data.replaceSubrange(152..<156, with: Swift.withUnsafeBytes(of: &textMaxProt) { Data($0) })
        var textInitProt: UInt32 = 5
        data.replaceSubrange(156..<160, with: Swift.withUnsafeBytes(of: &textInitProt) { Data($0) })
        var textNsects: UInt32 = 1
        data.replaceSubrange(160..<164, with: Swift.withUnsafeBytes(of: &textNsects) { Data($0) })

        // Section 1 (__text) at offset 176 (size 80)
        let textSectName = "__text".data(using: .utf8)!
        data.replaceSubrange(176..<176 + textSectName.count, with: textSectName)
        data.replaceSubrange(192..<192 + textSegName.count, with: textSegName)
        var sectAddr: UInt64 = 0x100003f00
        data.replaceSubrange(208..<216, with: Swift.withUnsafeBytes(of: &sectAddr) { Data($0) })
        var sectSize: UInt64 = 4
        data.replaceSubrange(216..<224, with: Swift.withUnsafeBytes(of: &sectSize) { Data($0) })
        var sectOff: UInt32 = 0x3f00
        data.replaceSubrange(224..<228, with: Swift.withUnsafeBytes(of: &sectOff) { Data($0) })
        var sectAlign: UInt32 = 2
        data.replaceSubrange(228..<232, with: Swift.withUnsafeBytes(of: &sectAlign) { Data($0) })
        var sectFlags: UInt32 = 0x80000400 // S_ATTR_SOME_INSTRUCTIONS | S_ATTR_PURE_INSTRUCTIONS
        data.replaceSubrange(240..<244, with: Swift.withUnsafeBytes(of: &sectFlags) { Data($0) })

        // 3. LC_SEGMENT_64 (__LINKEDIT) at offset 256 (size 72)
        var cmd3: UInt32 = CodeSigningConstants.LC_SEGMENT_64
        data.replaceSubrange(256..<260, with: Swift.withUnsafeBytes(of: &cmd3) { Data($0) })
        var cmdsize3: UInt32 = 72
        data.replaceSubrange(260..<264, with: Swift.withUnsafeBytes(of: &cmdsize3) { Data($0) })
        let linkSegName = "__LINKEDIT".data(using: .utf8)!
        data.replaceSubrange(264..<264 + linkSegName.count, with: linkSegName)
        var linkVmAddr: UInt64 = 0x100004000
        data.replaceSubrange(272..<280, with: Swift.withUnsafeBytes(of: &linkVmAddr) { Data($0) })
        var linkVmSize: UInt64 = 4096
        data.replaceSubrange(280..<288, with: Swift.withUnsafeBytes(of: &linkVmSize) { Data($0) })
        var linkFileOff: UInt64 = 16384
        data.replaceSubrange(288..<296, with: Swift.withUnsafeBytes(of: &linkFileOff) { Data($0) })
        var linkFileSize: UInt64 = 0
        data.replaceSubrange(296..<304, with: Swift.withUnsafeBytes(of: &linkFileSize) { Data($0) })
        var linkMaxProt: UInt32 = 7
        data.replaceSubrange(304..<308, with: Swift.withUnsafeBytes(of: &linkMaxProt) { Data($0) })
        var linkInitProt: UInt32 = 1
        data.replaceSubrange(308..<312, with: Swift.withUnsafeBytes(of: &linkInitProt) { Data($0) })

        // 4. LC_LOAD_DYLINKER (0x0e) at offset 328 (size 32)
        var cmd4: UInt32 = 0x0e
        data.replaceSubrange(328..<332, with: Swift.withUnsafeBytes(of: &cmd4) { Data($0) })
        var cmdsize4: UInt32 = 32
        data.replaceSubrange(332..<336, with: Swift.withUnsafeBytes(of: &cmdsize4) { Data($0) })
        var dyldNameOff: UInt32 = 12
        data.replaceSubrange(336..<340, with: Swift.withUnsafeBytes(of: &dyldNameOff) { Data($0) })
        let dyldPath = "/usr/lib/dyld\0\0\0".data(using: .utf8)!
        data.replaceSubrange(340..<340 + dyldPath.count, with: dyldPath)

        // 5. LC_MAIN (0x80000028) at offset 360 (size 24)
        var cmd5: UInt32 = 0x80000028
        data.replaceSubrange(360..<364, with: Swift.withUnsafeBytes(of: &cmd5) { Data($0) })
        var cmdsize5: UInt32 = 24
        data.replaceSubrange(364..<368, with: Swift.withUnsafeBytes(of: &cmdsize5) { Data($0) })
        var entryOff: UInt64 = 0x3f00
        data.replaceSubrange(368..<376, with: Swift.withUnsafeBytes(of: &entryOff) { Data($0) })

        // 6. LC_BUILD_VERSION (0x32) at offset 384 (size 24)
        var cmd6: UInt32 = 0x32
        data.replaceSubrange(384..<388, with: Swift.withUnsafeBytes(of: &cmd6) { Data($0) })
        var cmdsize6: UInt32 = 24
        data.replaceSubrange(388..<392, with: Swift.withUnsafeBytes(of: &cmdsize6) { Data($0) })
        var platform: UInt32 = 1 // macOS
        data.replaceSubrange(392..<396, with: Swift.withUnsafeBytes(of: &platform) { Data($0) })
        var minos: UInt32 = 0x000e0000 // 14.0.0
        data.replaceSubrange(396..<400, with: Swift.withUnsafeBytes(of: &minos) { Data($0) })
        var sdk: UInt32 = 0x000e0000
        data.replaceSubrange(400..<404, with: Swift.withUnsafeBytes(of: &sdk) { Data($0) })

        // 7. LC_LOAD_DYLIB (0x0c) at offset 408 (size 56)
        var cmd7: UInt32 = 0x0c
        data.replaceSubrange(408..<412, with: Swift.withUnsafeBytes(of: &cmd7) { Data($0) })
        var cmdsize7: UInt32 = 56
        data.replaceSubrange(412..<416, with: Swift.withUnsafeBytes(of: &cmdsize7) { Data($0) })
        var dylibNameOff: UInt32 = 24
        data.replaceSubrange(416..<420, with: Swift.withUnsafeBytes(of: &dylibNameOff) { Data($0) })
        var dylibTimestamp: UInt32 = 2
        data.replaceSubrange(420..<424, with: Swift.withUnsafeBytes(of: &dylibTimestamp) { Data($0) })
        var dylibCurrentVersion: UInt32 = 0x054c0000
        data.replaceSubrange(424..<428, with: Swift.withUnsafeBytes(of: &dylibCurrentVersion) { Data($0) })
        var dylibCompatVersion: UInt32 = 0x00010000
        data.replaceSubrange(428..<432, with: Swift.withUnsafeBytes(of: &dylibCompatVersion) { Data($0) })
        let libSystemPath = "/usr/lib/libSystem.B.dylib\0\0\0\0\0\0".data(using: .utf8)!
        data.replaceSubrange(432..<432 + libSystemPath.count, with: libSystemPath)

        // Valid ARM64 instruction (ret = 0xd65f03c0) at offset 0x3f00
        var retOpcode: UInt32 = 0xd65f03c0
        data.replaceSubrange(0x3f00..<0x3f04, with: Swift.withUnsafeBytes(of: &retOpcode) { Data($0) })

        return data
    }

    @Test
    func signAndStripThinBinary() throws {
        let originalBinary = createDummyMachOBinary()
        let signer = MachOSigner(
            binaryData: originalBinary,
            bundleIdentifier: "com.example.unitest",
            teamIdentifier: "TEAM123456",
            entitlementsXML: "<plist><dict><key>get-task-allow</key><true/></dict></plist>",
            infoPlistData: nil,
            codeResourcesData: nil,
            cmsSigner: nil,
            isMainExecutable: true
        )

        let signedBinary = try signer.sign()
        #expect(signedBinary.count > originalBinary.count)

        // Verify that signed binary has LC_CODE_SIGNATURE command
        let parser = MachOParser(data: signedBinary)
        #expect(parser.bundleIdentifier() == "com.example.unitest")
        #expect(parser.teamID() == "TEAM123456")
        #expect(!parser.getCDHashes().isEmpty)

        // Remove signature
        let strippedBinary = try MachOSigner.removeSignature(binaryData: signedBinary)
        #expect(strippedBinary.count == originalBinary.count)

        // Verify that signature is completely removed
        let strippedParser = MachOParser(data: strippedBinary)
        #expect(strippedParser.bundleIdentifier() == nil)
        #expect(strippedParser.getCDHashes().isEmpty)
    }

    @Test
    func reSignBinary() throws {

        let originalBinary = createDummyMachOBinary()
        let signer1 = MachOSigner(
            binaryData: originalBinary,
            bundleIdentifier: "com.example.first",
            teamIdentifier: "TEAM1",
            entitlementsXML: nil,
            infoPlistData: nil,
            codeResourcesData: nil,
            cmsSigner: nil
        )
        let signed1 = try signer1.sign()

        let signer2 = MachOSigner(
            binaryData: signed1,
            bundleIdentifier: "com.example.second",
            teamIdentifier: "TEAM2",
            entitlementsXML: nil,
            infoPlistData: nil,
            codeResourcesData: nil,
            cmsSigner: nil
        )
        let signed2 = try signer2.sign()

        let parser = MachOParser(data: signed2)
        #expect(parser.bundleIdentifier() == "com.example.second")
        #expect(parser.teamID() == "TEAM2")
    }

    @Test(.enabled(if: TestFixtures.isClangAvailable), arguments: [false, true])
    func appleCodeSignOnSyntheticGeneratedBinary(isFat: Bool) throws {
        let binary = try TestFixtures.compileRealMachOBinary(fat: isFat)
        let (p12Data, _, _) = try TestFixtures.createSelfSignedP12(password: "test")
        let cms = CMSSigner(p12Data: p12Data, password: "test")

        let signer = MachOSigner(
            binaryData: binary,
            bundleIdentifier: isFat ? "com.example.synthetic.fat" : "com.example.synthetic.thin",
            teamIdentifier: "TEAM123456",
            entitlementsXML: "<plist><dict><key>get-task-allow</key><true/></dict></plist>",
            infoPlistData: nil,
            codeResourcesData: nil,
            cmsSigner: cms,
            isMainExecutable: true
        )

        let signedData = try signer.sign()

        // Write to temporary file
        let prefix = isFat ? "fat" : "thin"
        let synthBinPath = TestFixtures.tempDir.appendingPathComponent("synthetic_signed_\(prefix)_bin").path
        try signedData.write(to: URL(fileURLWithPath: synthBinPath))
        defer { try? FileManager.default.removeItem(atPath: synthBinPath) }

        // Validate using Apple's official codesign tool
        let (appleOk, appleOutput) = TestFixtures.verifyWithAppleCodeSign(binaryPath: synthBinPath, strict: true)
        #expect(appleOk, "Apple codesign tool should validate \(prefix) generated binary: \(appleOutput)")
    }

    @Test(.enabled(if: TestFixtures.isClangAvailable))
    func signRealCompiledMachOBinary() throws {
        let realBinary = try TestFixtures.compileRealMachOBinary(fat: false)
        let (p12Data, _, _) = try TestFixtures.createSelfSignedP12(password: "test")
        let cms = CMSSigner(p12Data: p12Data, password: "test")

        let signer = MachOSigner(
            binaryData: realBinary,
            bundleIdentifier: "com.example.realapp",
            teamIdentifier: "TEAM123456",
            entitlementsXML: "<plist><dict><key>get-task-allow</key><true/></dict></plist>",
            infoPlistData: nil,
            codeResourcesData: nil,
            cmsSigner: cms,
            isMainExecutable: true
        )

        let signedData = try signer.sign()
        #expect(signedData.count > realBinary.count)

        // Verify with MachOParser
        let parser = MachOParser(data: signedData)
        #expect(parser.bundleIdentifier() == "com.example.realapp")
        #expect(parser.teamID() == "TEAM123456")
        #expect(!parser.getCDHashes().isEmpty)

        // Write to disk and verify with Apple's official codesign tool
        let tempBinPath = TestFixtures.tempDir.appendingPathComponent("real_signed_bin").path
        try signedData.write(to: URL(fileURLWithPath: tempBinPath))
        defer { try? FileManager.default.removeItem(atPath: tempBinPath) }

        let (appleOk, _) = TestFixtures.verifyWithAppleCodeSign(binaryPath: tempBinPath)
        #expect(appleOk, "Apple codesign tool should accept real signed binary")

        // Test stripping real signed binary
        let strippedData = try MachOSigner.removeSignature(binaryData: signedData)
        let strippedParser = MachOParser(data: strippedData)
        #expect(strippedParser.bundleIdentifier() == nil)
        #expect(strippedParser.getCDHashes().isEmpty)
    }

    @Test(.enabled(if: TestFixtures.isClangAvailable))
    func signRealFatMachOBinary() throws {
        let fatBinary = try TestFixtures.compileRealMachOBinary(fat: true)
        let (p12Data, _, _) = try TestFixtures.createSelfSignedP12(password: "test")
        let cms = CMSSigner(p12Data: p12Data, password: "test")

        let signer = MachOSigner(
            binaryData: fatBinary,
            bundleIdentifier: "com.example.realfat",
            teamIdentifier: "TEAM123456",
            entitlementsXML: "<plist><dict><key>get-task-allow</key><true/></dict></plist>",
            infoPlistData: nil,
            codeResourcesData: nil,
            cmsSigner: cms,
            isMainExecutable: true
        )

        let signedData = try signer.sign()
        #expect(signedData.count > fatBinary.count)

        let parser = MachOParser(data: signedData)
        #expect(parser.bundleIdentifier() == "com.example.realfat")
        #expect(parser.teamID() == "TEAM123456")

        let tempFatPath = TestFixtures.tempDir.appendingPathComponent("real_signed_fat").path
        try signedData.write(to: URL(fileURLWithPath: tempFatPath))
        defer { try? FileManager.default.removeItem(atPath: tempFatPath) }

        let (appleOk, _) = TestFixtures.verifyWithAppleCodeSign(binaryPath: tempFatPath)
        #expect(appleOk, "Apple codesign tool should accept real signed FAT binary")
    }
}


