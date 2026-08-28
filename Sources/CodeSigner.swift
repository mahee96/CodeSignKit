//
//  CodeSigner.swift
//  CodeSignKit
//
//  Created by Magesh K on 28/08/26.
//  Copyright © 2026 CodeSignKit. All rights reserved.
//


import Foundation

public final class CodeSigner {

    public static func sign(
        appPath: String,
        keyData: Data,
        password: String = "",
        teamID: String? = nil,
        entitlementProvider: @escaping (String) -> String,
        progress: @escaping () -> Void
    ) throws {
        let appURL = URL(fileURLWithPath: appPath).standardizedFileURL
        guard FileManager.default.fileExists(atPath: appURL.path) else {
            throw CodeSignerError.invalidPath("App path does not exist: \(appPath)")
        }

        let cmsSigner = CMSSigner(p12Data: keyData, password: password)

        // 1. Collect all embedded frameworks, dylibs, and app extensions
        let embeddedItems = collectEmbeddedItems(in: appURL)

        // 2. Sign embedded frameworks and dylibs first
        for itemURL in embeddedItems.frameworksAndDylibs {
            try signItem(
                at: itemURL,
                relativeTo: appURL,
                customTeamID: teamID,
                cmsSigner: cmsSigner,
                entitlementProvider: entitlementProvider
            )
            progress()
        }

        // 3. Sign app extensions (PlugIns)
        for appexURL in embeddedItems.appExtensions {
            try signItem(
                at: appexURL,
                relativeTo: appURL,
                customTeamID: teamID,
                cmsSigner: cmsSigner,
                entitlementProvider: entitlementProvider
            )
            progress()
        }

        // 4. Sign main application bundle
        try signItem(
            at: appURL,
            relativeTo: appURL,
            customTeamID: teamID,
            cmsSigner: cmsSigner,
            entitlementProvider: entitlementProvider
        )
        progress()
    }

    public static func removeSignature(at url: URL, deep: Bool = true) throws {
        let fileManager = FileManager.default
        var isDir: ObjCBool = false
        guard fileManager.fileExists(atPath: url.path, isDirectory: &isDir) else {
            throw CodeSignerError.invalidPath("Path does not exist: \(url.path)")
        }

        if isDir.boolValue {
            // 1. Remove _CodeSignature directory from bundle
            let codeSigDir = url.appendingPathComponent("_CodeSignature")
            if fileManager.fileExists(atPath: codeSigDir.path) {
                try? fileManager.removeItem(at: codeSigDir)
            }

            // 2. Strip signature from main executable
            if let execURL = MachOParser.findExecutable(at: url) {
                let execData = try Data(contentsOf: execURL)
                let unsignedData = try MachOSigner.removeSignature(binaryData: execData)
                try unsignedData.write(to: execURL, options: .atomic)
            }

            // 3. Deep remove from embedded items if requested
            if deep {
                let embedded = collectEmbeddedItems(in: url)
                for fwURL in embedded.frameworksAndDylibs {
                    try removeSignature(at: fwURL, deep: true)
                }
                for appexURL in embedded.appExtensions {
                    try removeSignature(at: appexURL, deep: true)
                }
            }
        } else {
            let data = try Data(contentsOf: url)
            let unsignedData = try MachOSigner.removeSignature(binaryData: data)
            try unsignedData.write(to: url, options: .atomic)
        }
    }

    private static func signItem(

        at url: URL,
        relativeTo rootURL: URL,
        customTeamID: String? = nil,
        cmsSigner: CMSSigner,
        entitlementProvider: (String) -> String
    ) throws {
        let fileManager = FileManager.default
        var isDir: ObjCBool = false
        guard fileManager.fileExists(atPath: url.path, isDirectory: &isDir) else {
            return
        }

        let isBundle = isDir.boolValue
        let executableURL: URL
        let bundleURL: URL?

        if isBundle {
            bundleURL = url
            guard let exec = MachOParser.findExecutable(at: url) else {
                throw CodeSignerError.invalidMachO("Could not find executable for bundle at \(url.path)")
            }
            executableURL = exec
        } else {
            bundleURL = nil
            executableURL = url
        }

        // Compute relative path from root
        let rootPath = rootURL.path.hasSuffix("/") ? rootURL.path : rootURL.path + "/"
        let relPath: String
        if url.path == rootURL.path {
            relPath = ""
        } else if url.path.hasPrefix(rootPath) {
            relPath = String(url.path.dropFirst(rootPath.count))
        } else {
            relPath = url.lastPathComponent
        }

        // Read or build bundle resources
        var infoPlistData: Data? = nil
        var codeResourcesData: Data? = nil
        var bundleID = executableURL.lastPathComponent
        var teamID: String? = customTeamID

        if let bundleURL = bundleURL {
            let infoPlistURL = bundleURL.appendingPathComponent("Info.plist")
            if let data = try? Data(contentsOf: infoPlistURL) {
                infoPlistData = data
                if let plist = try? PropertyListSerialization.propertyList(from: data, options: [], format: nil) as? [String: Any] {
                    if let id = plist["CFBundleIdentifier"] as? String {
                        bundleID = id
                    }
                }
            }

            // Generate _CodeSignature/CodeResources
            let resourcesBuilder = CodeResourcesBuilder(
                bundleURL: bundleURL,
                executableName: executableURL.lastPathComponent
            )
            let resData = try resourcesBuilder.build()
            codeResourcesData = resData

            // Write _CodeSignature/CodeResources to disk
            let codeSigDir = bundleURL.appendingPathComponent("_CodeSignature")
            try? fileManager.createDirectory(at: codeSigDir, withIntermediateDirectories: true)
            let codeResURL = codeSigDir.appendingPathComponent("CodeResources")
            try resData.write(to: codeResURL, options: .atomic)
        }

        // Query entitlements from provider
        let rawEntitlements = entitlementProvider(relPath)
        let entitlementsXML: String? = rawEntitlements.isEmpty ? nil : rawEntitlements

        // Extract Team ID from existing binary or entitlements if present
        if teamID == nil, let parser = try? MachOParser(url: executableURL) {
            teamID = parser.teamID()
        }


        // Read executable data
        let binaryData = try Data(contentsOf: executableURL)

        let isMain = (url.path == rootURL.path)

        // Sign Mach-O binary
        let machOSigner = MachOSigner(
            binaryData: binaryData,
            bundleIdentifier: bundleID,
            teamIdentifier: teamID,
            entitlementsXML: entitlementsXML,
            infoPlistData: infoPlistData,
            codeResourcesData: codeResourcesData,
            cmsSigner: cmsSigner,
            isMainExecutable: isMain
        )


        let signedBinary = try machOSigner.sign()

        // Write signed binary back to disk
        try signedBinary.write(to: executableURL, options: .atomic)

        // Ensure executable permissions (0755)
        try? fileManager.setAttributes([.posixPermissions: 0o755], ofItemAtPath: executableURL.path)
    }

    private struct EmbeddedItems {
        var frameworksAndDylibs: [URL] = []
        var appExtensions: [URL] = []
    }

    private static func collectEmbeddedItems(in appURL: URL) -> EmbeddedItems {
        var items = EmbeddedItems()
        let fileManager = FileManager.default

        // Frameworks
        let frameworksURL = appURL.appendingPathComponent("Frameworks")
        if let contents = try? fileManager.contentsOfDirectory(at: frameworksURL, includingPropertiesForKeys: nil) {
            for item in contents {
                if item.pathExtension == "framework" || item.pathExtension == "dylib" {
                    items.frameworksAndDylibs.append(item)
                }
            }
        }

        // PlugIns (App Extensions)
        let pluginsURL = appURL.appendingPathComponent("PlugIns")
        if let contents = try? fileManager.contentsOfDirectory(at: pluginsURL, includingPropertiesForKeys: nil) {
            for item in contents {
                if item.pathExtension == "appex" {
                    items.appExtensions.append(item)
                }
            }
        }

        // Extensions
        let extensionsURL = appURL.appendingPathComponent("Extensions")
        if let contents = try? fileManager.contentsOfDirectory(at: extensionsURL, includingPropertiesForKeys: nil) {
            for item in contents {
                if item.pathExtension == "appex" {
                    items.appExtensions.append(item)
                }
            }
        }

        return items
    }
}
