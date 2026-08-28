//
//  main.swift
//  CodeSignKit
//
//  Created by Magesh K on 28/08/26.
//  Copyright © 2026 CodeSignKit. All rights reserved.
//

import Foundation
import CodeSignKit

let args = CommandLine.arguments

func printUsage() {
    print("""
    codesigntoolkit - Code Signing, Verification, and Inspection Tool
    
    Usage:
      # Signing
      codesigntoolkit -s <p12Path> [--password <pwd>] [-f] [--deep] [-i <id>] [--team <team>] [--entitlements <file>] <path>
      codesigntoolkit sign <path> --p12 <p12Path> [--password <pwd>] [-i <id>] [--team <team>] [--entitlements <file>]

      # Verification
      codesigntoolkit -v <path> [--deep] [--strict]
      codesigntoolkit verify <path> [--deep] [--strict]

      # Display / Extraction
      codesigntoolkit -d <path>
      codesigntoolkit -dvvvv <path>
      codesigntoolkit -d --entitlements [-] <path>
      codesigntoolkit -d -r- <path>
      codesigntoolkit display <path> [--entitlements] [--requirements]

      # Signature Removal
      codesigntoolkit --remove-signature <path> [--deep]
      codesigntoolkit remove-signature <path> [--deep]
    """)
}

if args.count <= 1 || args.contains("-h") || args.contains("--help") || args.contains("help") {
    printUsage()
    exit(0)
}


// Parse Command Line Arguments
var targetPath: String?
var p12Path: String?
var password = ""
var entitlementsPath: String?
var bundleID: String?
var teamID: String?
var isDeep = false
var isStrict = false
var isForce = false
var verboseLevel = 0

var mode: String? = nil // "sign", "verify", "display", "remove"
var dumpEntitlements = false
var dumpRequirements = false

var i = 1
while i < args.count {
    let arg = args[i]

    if arg == "sign" {
        mode = "sign"
    } else if arg == "verify" {
        mode = "verify"
    } else if arg == "display" {
        mode = "display"
    } else if arg == "remove-signature" || arg == "--remove-signature" {
        mode = "remove"
    } else if arg == "-s" || arg == "--sign" {
        mode = "sign"
        if i + 1 < args.count { p12Path = args[i + 1]; i += 1 }
    } else if arg == "--p12" {
        if i + 1 < args.count { p12Path = args[i + 1]; i += 1 }
    } else if arg == "--password" {
        if i + 1 < args.count { password = args[i + 1]; i += 1 }
    } else if arg == "-i" || arg == "--identifier" || arg == "--id" {
        if i + 1 < args.count { bundleID = args[i + 1]; i += 1 }
    } else if arg == "--team" {
        if i + 1 < args.count { teamID = args[i + 1]; i += 1 }
    } else if arg == "--entitlements" {
        if i + 1 < args.count {
            let next = args[i + 1]
            if next == "-" {
                dumpEntitlements = true
                i += 1
            } else if !next.hasPrefix("-") && FileManager.default.fileExists(atPath: next) {
                entitlementsPath = next
                i += 1
            } else {
                dumpEntitlements = true
            }
        } else {
            dumpEntitlements = true
        }
    } else if arg == "-r-" || arg == "--requirements" {
        dumpRequirements = true
    } else if arg == "-f" || arg == "--force" {
        isForce = true
    } else if arg == "--deep" {
        isDeep = true
    } else if arg == "--strict" {
        isStrict = true
    } else if arg.hasPrefix("-dv") || arg == "-d" || arg == "--display" {
        mode = "display"
        if arg.contains("v") {
            verboseLevel = arg.filter { $0 == "v" }.count
        }
    } else if arg.hasPrefix("-v") || arg == "--verify" {
        if mode == nil { mode = "verify" }
        verboseLevel = arg.filter { $0 == "v" }.count
    } else if !arg.hasPrefix("-") {
        targetPath = arg
    }

    i += 1
}

guard let target = targetPath else {
    print("Error: No target file or bundle specified.")
    printUsage()
    exit(1)
}

let targetURL = URL(fileURLWithPath: target)
let fileManager = FileManager.default
var isDir: ObjCBool = false

guard fileManager.fileExists(atPath: targetURL.path, isDirectory: &isDir) else {
    print("Error: Target path does not exist: \(target)")
    exit(1)
}

// Default mode detection
if mode == nil {
    if p12Path != nil {
        mode = "sign"
    } else if dumpEntitlements || dumpRequirements {
        mode = "display"
    } else {
        mode = "verify"
    }
}

switch mode {
case "sign":
    guard let p12 = p12Path else {
        print("Error: Missing certificate path (-s /path/to/cert.p12)")
        exit(1)
    }

    guard let p12Data = try? Data(contentsOf: URL(fileURLWithPath: p12)) else {
        print("Error: Could not read PKCS#12 file at \(p12)")
        exit(1)
    }

    var entitlementsXML: String? = nil
    if let entPath = entitlementsPath {
        guard let xml = try? String(contentsOfFile: entPath, encoding: .utf8) else {
            print("Error: Could not read entitlements file at \(entPath)")
            exit(1)
        }
        entitlementsXML = xml
    }

    do {
        if isDir.boolValue {
            try CodeSigner.sign(
                appPath: targetURL.path,
                keyData: p12Data,
                password: password,
                teamID: teamID,
                entitlementProvider: { _ in entitlementsXML ?? "" },
                progress: {}
            )
            print("\(target): replacing existing signature")
            print("\(target): signed bundle successfully")
        } else {
            let binaryData = try Data(contentsOf: targetURL)
            let cmsSigner = CMSSigner(p12Data: p12Data, password: password)
            let finalBundleID = bundleID ?? targetURL.lastPathComponent

            let signer = MachOSigner(
                binaryData: binaryData,
                bundleIdentifier: finalBundleID,
                teamIdentifier: teamID,
                entitlementsXML: entitlementsXML,
                infoPlistData: nil,
                codeResourcesData: nil,
                cmsSigner: cmsSigner,
                isMainExecutable: true
            )
            let signed = try signer.sign()
            try signed.write(to: targetURL, options: .atomic)
            print("\(target): signed Mach-O binary successfully")
        }
    } catch {
        print("Signing failed: \(error.localizedDescription)")
        exit(1)
    }

case "verify":
    let result = SignatureVerifier.verify(url: targetURL, deep: isDeep, strict: isStrict)
    if result.isValid {
        print("\(target): valid on disk")
        print("\(target): satisfies its Designated Requirement")
        if verboseLevel > 0 {
            if let ident = result.bundleIdentifier { print("Identifier=\(ident)") }
            if let team = result.teamIdentifier { print("TeamIdentifier=\(team)") }
            if let cdHash = result.cdHash { print("CDHash=\(cdHash)") }
            if let subject = result.signerCertificateSubject { print("Signer=\(subject)") }
        }
    } else {
        print("\(target): verification failed:")
        for err in result.errors {
            print("  - \(err)")
        }
        exit(1)
    }

case "display":
    let execURL: URL
    if isDir.boolValue {
        guard let exec = MachOParser.findExecutable(at: targetURL) else {
            print("Error: Could not find executable inside bundle \(target)")
            exit(1)
        }
        execURL = exec
    } else {
        execURL = targetURL
    }

    guard let parser = try? MachOParser(url: execURL) else {
        print("Error: Failed to parse Mach-O binary at \(execURL.path)")
        exit(1)
    }

    if dumpEntitlements {
        if let xml = try? parser.entitlements() {
            print(xml)
        } else {
            print("No XML entitlements found in binary.")
        }
    } else if dumpRequirements {
        if let req = try? parser.requirements() {
            print(req)
        } else {
            print("No Designated Requirements found in binary.")
        }
    } else {
        print("Executable=\(execURL.path)")
        if let ident = parser.bundleIdentifier() {
            print("Identifier=\(ident)")
        }
        if let team = parser.teamID() {
            print("TeamIdentifier=\(team)")
        }
        let cdHashes = parser.getCDHashes()
        if !cdHashes.isEmpty {
            print("CDHash=\(cdHashes[0])")
        }
        let archs = parser.architectures()
        if !archs.isEmpty {
            print("Architectures=\(archs.joined(separator: " "))")
        }
        if verboseLevel >= 3 {
            let certs = parser.certificates()
            print("Authority=\(certs.count) certificate(s) embedded")
            if let minOS = parser.minimumOSVersion() {
                print("MinimumOSVersion=\(minOS)")
            }
        }
    }

case "remove":
    do {
        try CodeSigner.removeSignature(at: targetURL, deep: isDeep)
        print("\(target): removed signature successfully")
    } catch {
        print("Failed to remove signature: \(error.localizedDescription)")
        exit(1)
    }

default:
    printUsage()
    exit(1)
}
