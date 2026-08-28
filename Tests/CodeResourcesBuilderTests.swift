//
//  CodeResourcesBuilderTests.swift
//  CodeSignKitTests
//
//  Created by Magesh K on 28/08/26.
//  Copyright © 2026 CodeSignKit. All rights reserved.
//

import Testing
import Foundation
@testable import CodeSignKit

@Suite
struct CodeResourcesBuilderTests {

    @Test
    func codeResourcesBuilding() throws {
        let tempDir = FileManager.default.temporaryDirectory.appendingPathComponent(UUID().uuidString)

        try FileManager.default.createDirectory(at: tempDir, withIntermediateDirectories: true)
        defer { try? FileManager.default.removeItem(at: tempDir) }

        // Create sample files
        try "Test File 1".write(to: tempDir.appendingPathComponent("file1.txt"), atomically: true, encoding: .utf8)
        try "Info Plist Data".write(to: tempDir.appendingPathComponent("Info.plist"), atomically: true, encoding: .utf8)
        try "Executable Binary".write(to: tempDir.appendingPathComponent("MyApp"), atomically: true, encoding: .utf8)

        // Create _CodeSignature directory that should be ignored
        let codeSigDir = tempDir.appendingPathComponent("_CodeSignature")
        try FileManager.default.createDirectory(at: codeSigDir, withIntermediateDirectories: true)
        try "Old Sign Data".write(to: codeSigDir.appendingPathComponent("CodeResources"), atomically: true, encoding: .utf8)

        let builder = CodeResourcesBuilder(bundleURL: tempDir, executableName: "MyApp")
        let resData = try builder.build()

        #expect(!resData.isEmpty)

        let plist = try #require(PropertyListSerialization.propertyList(from: resData, options: [], format: nil) as? [String: Any])

        let files = plist["files"] as? [String: Any]
        let files2 = plist["files2"] as? [String: Any]
        let rules2 = plist["rules2"] as? [String: Any]

        #expect(files != nil)
        #expect(files2 != nil)
        #expect(rules2 != nil)

        // file1.txt should be present in files and files2
        #expect(files?["file1.txt"] != nil)
        #expect(files2?["file1.txt"] != nil)

        // Info.plist is omitted from files2 by default rule but present in files
        #expect(files?["Info.plist"] != nil)
        #expect(files2?["Info.plist"] == nil)

        // Executable and _CodeSignature should NOT be in files
        #expect(files?["MyApp"] == nil)
        #expect(files?["_CodeSignature/CodeResources"] == nil)
    }
}

