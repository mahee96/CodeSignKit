//
//  AppBundleSigningTests.swift
//  CodeSignKitTests
//
//  Created by Magesh K on 28/08/26.
//  Copyright © 2026 CodeSignKit. All rights reserved.
//

import Testing
import Foundation
@testable import CodeSignKit

@Suite
struct AppBundleSigningTests {

    private func createDummyMachOBinary() -> Data {
        var data = Data(count: 4096)
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
        var vmsize: UInt64 = 4096
        data.replaceSubrange(56..<64, with: Swift.withUnsafeBytes(of: &vmsize) { Data($0) })
        var filesize: UInt64 = 4096
        data.replaceSubrange(72..<80, with: Swift.withUnsafeBytes(of: &filesize) { Data($0) })
        return data
    }

    @Test
    func appBundleSigningAndVerification() throws {
        let tempDir = FileManager.default.temporaryDirectory.appendingPathComponent(UUID().uuidString)

        let appDir = tempDir.appendingPathComponent("TestApp.app")
        try FileManager.default.createDirectory(at: appDir, withIntermediateDirectories: true)
        defer { try? FileManager.default.removeItem(at: tempDir) }

        // Info.plist
        let infoPlist = """
        <?xml version="1.0" encoding="UTF-8"?>
        <!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
        <plist version="1.0">
        <dict>
            <key>CFBundleIdentifier</key>
            <string>com.example.testapp</string>
            <key>CFBundleExecutable</key>
            <string>TestApp</string>
        </dict>
        </plist>
        """
        try infoPlist.write(to: appDir.appendingPathComponent("Info.plist"), atomically: true, encoding: .utf8)

        // Main Executable
        let binaryData = createDummyMachOBinary()
        try binaryData.write(to: appDir.appendingPathComponent("TestApp"))

        // Resource file
        try "Resource Content".write(to: appDir.appendingPathComponent("data.txt"), atomically: true, encoding: .utf8)

        // Generate test cert P12 dynamically
        let (p12Data, _, _) = try TestFixtures.createSelfSignedP12(password: "test")

        // 1. Sign App Bundle
        try CodeSigner.sign(
            appPath: appDir.path,
            keyData: p12Data,
            password: "test",
            teamID: "TEAM123456",
            entitlementProvider: { _ in "<plist><dict><key>get-task-allow</key><true/></dict></plist>" },
            progress: {}
        )

        // 2. Verify App Bundle
        let verResult = SignatureVerifier.verify(url: appDir, deep: true, strict: false)
        #expect(verResult.isValid)
        #expect(verResult.bundleIdentifier == "com.example.testapp")
        #expect(verResult.teamIdentifier == "TEAM123456")
        #expect(verResult.cdHash != nil)

        // 3. Remove signature
        try CodeSigner.removeSignature(at: appDir, deep: true)
        let strippedResult = SignatureVerifier.verify(url: appDir, deep: true, strict: false)
        #expect(!strippedResult.isValid)
    }

    @Test(.enabled(if: TestFixtures.isClangAvailable))
    func realCompiledAppBundleSigningWithAppleVerification() throws {
        let tempDir = FileManager.default.temporaryDirectory.appendingPathComponent("RealAppTest_\(UUID().uuidString)")

        let appDir = tempDir.appendingPathComponent("SampleReal.app")
        try FileManager.default.createDirectory(at: appDir, withIntermediateDirectories: true)
        defer { try? FileManager.default.removeItem(at: tempDir) }

        // Info.plist
        let infoPlist = """
        <?xml version="1.0" encoding="UTF-8"?>
        <!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
        <plist version="1.0">
        <dict>
            <key>CFBundleIdentifier</key>
            <string>com.example.samplereal</string>
            <key>CFBundleExecutable</key>
            <string>SampleReal</string>
            <key>CFBundlePackageType</key>
            <string>APPL</string>
        </dict>
        </plist>
        """
        try infoPlist.write(to: appDir.appendingPathComponent("Info.plist"), atomically: true, encoding: .utf8)

        // Real compiled Mach-O binary
        let realBinData = try TestFixtures.compileRealMachOBinary(fat: false)
        try realBinData.write(to: appDir.appendingPathComponent("SampleReal"))

        // Resource files
        try "Resource content".write(to: appDir.appendingPathComponent("assets.txt"), atomically: true, encoding: .utf8)

        // Generate P12
        let (p12Data, _, _) = try TestFixtures.createSelfSignedP12(password: "test")

        // 1. Sign entire real App Bundle
        try CodeSigner.sign(
            appPath: appDir.path,
            keyData: p12Data,
            password: "test",
            teamID: "TEAM123456",
            entitlementProvider: { _ in "<plist><dict><key>get-task-allow</key><true/></dict></plist>" },
            progress: {}
        )

        // 2. Native verification
        let verResult = SignatureVerifier.verify(url: appDir, deep: true, strict: false)
        #expect(verResult.isValid)
        #expect(verResult.bundleIdentifier == "com.example.samplereal")
        #expect(verResult.teamIdentifier == "TEAM123456")

        // 3. Apple codesign official verification
        let (appleOk, appleOutput) = TestFixtures.verifyWithAppleCodeSign(binaryPath: appDir.path)
        #expect(appleOk, "Apple codesign should verify real App Bundle successfully: \(appleOutput)")

        // 4. Remove signature & re-verify with Apple codesign
        try CodeSigner.removeSignature(at: appDir, deep: true)
        let (appleStrippedOk, _) = TestFixtures.verifyWithAppleCodeSign(binaryPath: appDir.path)
        #expect(!appleStrippedOk, "Apple codesign should report unsigned after signature removal")
    }
}


