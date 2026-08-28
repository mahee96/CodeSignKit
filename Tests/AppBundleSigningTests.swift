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

    @Test(.enabled(if: TestFixtures.isClangAvailable))
    func realComplexMultiTargetAppBundleSigningWithAppleVerification() throws {
        let tempDir = FileManager.default.temporaryDirectory.appendingPathComponent("ComplexAppTest_\(UUID().uuidString)")
        let appDir = tempDir.appendingPathComponent("ComplexEnterprise.app")
        try FileManager.default.createDirectory(at: appDir, withIntermediateDirectories: true)
        defer { try? FileManager.default.removeItem(at: tempDir) }

        // 1. Main App Info.plist & Executable
        let mainPlist = """
        <?xml version="1.0" encoding="UTF-8"?>
        <!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
        <plist version="1.0">
        <dict>
            <key>CFBundleIdentifier</key>
            <string>com.enterprise.complexapp</string>
            <key>CFBundleExecutable</key>
            <string>ComplexEnterprise</string>
            <key>CFBundlePackageType</key>
            <string>APPL</string>
        </dict>
        </plist>
        """
        try mainPlist.write(to: appDir.appendingPathComponent("Info.plist"), atomically: true, encoding: .utf8)
        let mainBinData = try TestFixtures.compileRealMachOBinary(fat: false)
        try mainBinData.write(to: appDir.appendingPathComponent("ComplexEnterprise"))

        // 2. Root Loose Dylibs (e.g. Threads96.debug.dylib and __preview.dylib)
        let dylibData = try TestFixtures.compileRealDylib(fat: false)
        try dylibData.write(to: appDir.appendingPathComponent("ComplexEnterprise.debug.dylib"))
        try dylibData.write(to: appDir.appendingPathComponent("__preview.dylib"))

        // 3. Embedded Framework (Frameworks/CoreEngine.framework)
        let fwDir = appDir.appendingPathComponent("Frameworks/CoreEngine.framework")
        try FileManager.default.createDirectory(at: fwDir, withIntermediateDirectories: true)
        let fwPlist = """
        <?xml version="1.0" encoding="UTF-8"?>
        <!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
        <plist version="1.0">
        <dict>
            <key>CFBundleIdentifier</key>
            <string>com.enterprise.coreengine</string>
            <key>CFBundleExecutable</key>
            <string>CoreEngine</string>
            <key>CFBundlePackageType</key>
            <string>FMWK</string>
        </dict>
        </plist>
        """
        try fwPlist.write(to: fwDir.appendingPathComponent("Info.plist"), atomically: true, encoding: .utf8)
        try dylibData.write(to: fwDir.appendingPathComponent("CoreEngine"))

        // 4. Embedded Dylib (Frameworks/libnetwork.dylib)
        try dylibData.write(to: appDir.appendingPathComponent("Frameworks/libnetwork.dylib"))

        // 5. Embedded App Extension (PlugIns/ShareWidget.appex)
        let appexDir = appDir.appendingPathComponent("PlugIns/ShareWidget.appex")
        try FileManager.default.createDirectory(at: appexDir, withIntermediateDirectories: true)
        let appexPlist = """
        <?xml version="1.0" encoding="UTF-8"?>
        <!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
        <plist version="1.0">
        <dict>
            <key>CFBundleIdentifier</key>
            <string>com.enterprise.complexapp.sharewidget</string>
            <key>CFBundleExecutable</key>
            <string>ShareWidget</string>
            <key>CFBundlePackageType</key>
            <string>XPC!</string>
        </dict>
        </plist>
        """
        try appexPlist.write(to: appexDir.appendingPathComponent("Info.plist"), atomically: true, encoding: .utf8)
        try mainBinData.write(to: appexDir.appendingPathComponent("ShareWidget"))

        // 6. Embedded XCTest Bundle (PlugIns/UnitTests.xctest)
        let xctestDir = appDir.appendingPathComponent("PlugIns/UnitTests.xctest")
        try FileManager.default.createDirectory(at: xctestDir, withIntermediateDirectories: true)
        let xctestPlist = """
        <?xml version="1.0" encoding="UTF-8"?>
        <!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
        <plist version="1.0">
        <dict>
            <key>CFBundleIdentifier</key>
            <string>com.enterprise.complexapp.unittests</string>
            <key>CFBundleExecutable</key>
            <string>UnitTests</string>
            <key>CFBundlePackageType</key>
            <string>BNDL</string>
        </dict>
        </plist>
        """
        try xctestPlist.write(to: xctestDir.appendingPathComponent("Info.plist"), atomically: true, encoding: .utf8)
        try dylibData.write(to: xctestDir.appendingPathComponent("UnitTests"))

        // 7. Embedded XPC Service (XPCServices/BackgroundWorker.xpc)
        let xpcDir = appDir.appendingPathComponent("XPCServices/BackgroundWorker.xpc")
        try FileManager.default.createDirectory(at: xpcDir, withIntermediateDirectories: true)
        let xpcPlist = """
        <?xml version="1.0" encoding="UTF-8"?>
        <!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
        <plist version="1.0">
        <dict>
            <key>CFBundleIdentifier</key>
            <string>com.enterprise.complexapp.worker</string>
            <key>CFBundleExecutable</key>
            <string>BackgroundWorker</string>
            <key>CFBundlePackageType</key>
            <string>XPC!</string>
        </dict>
        </plist>
        """
        try xpcPlist.write(to: xpcDir.appendingPathComponent("Info.plist"), atomically: true, encoding: .utf8)
        try mainBinData.write(to: xpcDir.appendingPathComponent("BackgroundWorker"))

        // 8. Embedded Resource Bundle (Assets.bundle - pure resources, no binary)
        let resBundleDir = appDir.appendingPathComponent("Assets.bundle")
        try FileManager.default.createDirectory(at: resBundleDir, withIntermediateDirectories: true)
        try "Resource Icon".write(to: resBundleDir.appendingPathComponent("icon.png"), atomically: true, encoding: .utf8)
        try "Colors".write(to: resBundleDir.appendingPathComponent("colors.plist"), atomically: true, encoding: .utf8)

        // 9. Generate Certificate P12
        let (p12Data, _, _) = try TestFixtures.createSelfSignedP12(password: "test")

        // 10. Sign Entire Multi-Target App Bundle
        var signedCount = 0
        try CodeSigner.sign(
            appPath: appDir.path,
            keyData: p12Data,
            password: "test",
            teamID: "TEAM123456",
            entitlementProvider: { relPath in
                if relPath.contains("ShareWidget") {
                    return "<plist><dict><key>com.apple.security.application-groups</key><array><string>group.com.enterprise</string></array></dict></plist>"
                }
                return "<plist><dict><key>get-task-allow</key><true/></dict></plist>"
            },
            progress: {
                signedCount += 1
            }
        )
        #expect(signedCount >= 6, "Should sign main app, 2 loose dylibs, framework, libnetwork, appex, xctest, xpc")

        // 11. Verify Each Component Individually with Apple codesign
        let itemsToVerify = [
            appDir.appendingPathComponent("ComplexEnterprise.debug.dylib").path,
            appDir.appendingPathComponent("__preview.dylib").path,
            fwDir.path,
            appDir.appendingPathComponent("Frameworks/libnetwork.dylib").path,
            appexDir.path,
            xctestDir.path,
            xpcDir.path,
            appDir.path
        ]

        for itemPath in itemsToVerify {
            let (appleOk, appleOutput) = TestFixtures.verifyWithAppleCodeSign(binaryPath: itemPath)
            #expect(appleOk, "Apple codesign should verify \(itemPath): \(appleOutput)")
        }

        // 12. Strict Deep Verification on Root App Bundle
        let (deepAppleOk, deepOutput) = TestFixtures.verifyWithAppleCodeSign(binaryPath: appDir.path, strict: true)
        #expect(deepAppleOk, "Apple codesign strict deep verification must pass for complex bundle: \(deepOutput)")

        // 13. Test Signature Removal on Entire Tree
        try CodeSigner.removeSignature(at: appDir, deep: true)
        for itemPath in itemsToVerify {
            let (appleStrippedOk, _) = TestFixtures.verifyWithAppleCodeSign(binaryPath: itemPath)
            #expect(!appleStrippedOk, "Item should be unsigned after deep strip: \(itemPath)")
        }
    }
}
