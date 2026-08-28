//
//  TestFixtures.swift
//  CodeSignKitTests
//
//  Created by Magesh K on 28/08/26.
//  Copyright © 2026 CodeSignKit. All rights reserved.
//

import Foundation

enum TestFixtures {
    static let tempDir: URL = {
        let dir = FileManager.default.temporaryDirectory.appendingPathComponent("CodeSignKitUnitTests_\(UUID().uuidString)")
        try? FileManager.default.createDirectory(at: dir, withIntermediateDirectories: true)
        return dir
    }()

    private static func findExecutable(_ name: String) -> String? {
        let candidates = [
            "/usr/bin/" + name,
            "/usr/local/bin/" + name,
            "/opt/homebrew/bin/" + name,
            "/bin/" + name
        ]
        for path in candidates {
            if FileManager.default.fileExists(atPath: path) {
                return path
            }
        }
        return nil
    }

    static var isClangAvailable: Bool {
        #if os(macOS)
        return findExecutable("clang") != nil
        #else
        return false
        #endif
    }

    static var isAppleCodeSignAvailable: Bool {
        #if os(macOS)
        return findExecutable("codesign") != nil
        #else
        return false
        #endif
    }

    static func compileRealMachOBinary(fat: Bool = false) throws -> Data {
        #if os(macOS)
        guard let clangPath = findExecutable("clang") else {
            throw NSError(domain: "TestFixtures", code: 2, userInfo: [NSLocalizedDescriptionKey: "clang not found on system"])
        }

        let srcFile = tempDir.appendingPathComponent("test_\(UUID().uuidString).c")
        let binFile = tempDir.appendingPathComponent("bin_\(UUID().uuidString)")
        let cSource = """
        #include <stdio.h>
        int main() {
            printf("Genuine Mach-O Binary\\n");
            return 0;
        }
        """
        try cSource.write(to: srcFile, atomically: true, encoding: .utf8)
        defer { try? FileManager.default.removeItem(at: srcFile) }

        let process = Process()
        process.executableURL = URL(fileURLWithPath: clangPath)
        if fat {
            process.arguments = ["-arch", "arm64", "-arch", "x86_64", "-o", binFile.path, srcFile.path]
        } else {
            #if arch(arm64)
            process.arguments = ["-arch", "arm64", "-o", binFile.path, srcFile.path]
            #else
            process.arguments = ["-arch", "x86_64", "-o", binFile.path, srcFile.path]
            #endif
        }
        try process.run()
        process.waitUntilExit()

        guard process.terminationStatus == 0, FileManager.default.fileExists(atPath: binFile.path) else {
            throw NSError(domain: "TestFixtures", code: 1, userInfo: [NSLocalizedDescriptionKey: "Failed to compile test Mach-O binary"])
        }

        let data = try Data(contentsOf: binFile)
        try? FileManager.default.removeItem(at: binFile)
        return data
        #else
        throw NSError(domain: "TestFixtures", code: 2, userInfo: [NSLocalizedDescriptionKey: "Real Mach-O compilation via clang is only supported on macOS"])
        #endif
    }

    static func createSelfSignedP12(password: String = "test") throws -> (p12Data: Data, certPEM: Data, keyPEM: Data) {
        guard let opensslPath = findExecutable("openssl") else {
            throw NSError(domain: "TestFixtures", code: 3, userInfo: [NSLocalizedDescriptionKey: "openssl CLI not found on system"])
        }

        let keyPath = tempDir.appendingPathComponent("key_\(UUID().uuidString).pem").path
        let certPath = tempDir.appendingPathComponent("cert_\(UUID().uuidString).pem").path
        let p12Path = tempDir.appendingPathComponent("cert_\(UUID().uuidString).p12").path
        let cnfPath = tempDir.appendingPathComponent("cnf_\(UUID().uuidString).cnf").path

        let cnfContent = """
        [ req ]
        default_bits        = 2048
        distinguished_name  = req_distinguished_name
        x509_extensions     = v3_req
        prompt              = no

        [ req_distinguished_name ]
        CN = Test Developer
        OU = TEAM123456
        O  = Test
        C  = US

        [ v3_req ]
        basicConstraints = critical, CA:FALSE
        keyUsage = critical, digitalSignature, nonRepudiation
        extendedKeyUsage = critical, codeSigning, 1.2.840.113635.100.6.1.5
        """
        try cnfContent.write(toFile: cnfPath, atomically: true, encoding: .utf8)
        defer { try? FileManager.default.removeItem(atPath: cnfPath) }

        // Generate cert and key
        let p1 = Process()
        p1.executableURL = URL(fileURLWithPath: opensslPath)
        p1.arguments = ["req", "-x509", "-newkey", "rsa:2048", "-keyout", keyPath, "-out", certPath, "-days", "365", "-nodes", "-config", cnfPath]
        try p1.run()
        p1.waitUntilExit()

        // Generate p12
        let p2 = Process()
        p2.executableURL = URL(fileURLWithPath: opensslPath)
        p2.arguments = ["pkcs12", "-export", "-out", p12Path, "-inkey", keyPath, "-in", certPath, "-passout", "pass:\(password)", "-name", "Test Developer"]
        try p2.run()
        p2.waitUntilExit()

        let keyData = try Data(contentsOf: URL(fileURLWithPath: keyPath))
        let certData = try Data(contentsOf: URL(fileURLWithPath: certPath))
        let p12Data = try Data(contentsOf: URL(fileURLWithPath: p12Path))

        try? FileManager.default.removeItem(atPath: keyPath)
        try? FileManager.default.removeItem(atPath: certPath)
        try? FileManager.default.removeItem(atPath: p12Path)

        return (p12Data, certData, keyData)
    }

    static func verifyWithAppleCodeSign(binaryPath: String, strict: Bool = true) -> (success: Bool, output: String) {
        #if os(macOS)
        guard let codesignPath = findExecutable("codesign") else {
            return (true, "Skipped: Apple codesign tool not available on this system")
        }

        let process = Process()
        process.executableURL = URL(fileURLWithPath: codesignPath)
        if strict {
            process.arguments = ["-v", "--strict", "--deep", "--verbose=4", binaryPath]
        } else {
            process.arguments = ["-v", "--verbose=4", binaryPath]
        }
        let pipe = Pipe()
        process.standardOutput = pipe
        process.standardError = pipe
        try? process.run()
        process.waitUntilExit()

        let data = pipe.fileHandleForReading.readDataToEndOfFile()
        let output = String(data: data, encoding: .utf8) ?? ""
        return (process.terminationStatus == 0, output)
        #else
        return (true, "Skipped: Apple codesign tool only available on macOS")
        #endif
    }
}


