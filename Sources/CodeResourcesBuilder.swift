//
//  CodeResourcesBuilder.swift
//  CodeSignKit
//
//  Created by Magesh K on 28/08/26.
//  Copyright © 2026 CodeSignKit. All rights reserved.
//


import Foundation
import Crypto

public final class CodeResourcesBuilder {


    private let bundleURL: URL
    private let executableName: String?

    public init(bundleURL: URL, executableName: String?) {
        self.bundleURL = bundleURL
        self.executableName = executableName
    }

    public func build() throws -> Data {
        var files: [String: Data] = [:]
        var files2: [String: [String: any Sendable]] = [:]

        let fileManager = FileManager.default
        guard let enumerator = fileManager.enumerator(
            at: bundleURL,
            includingPropertiesForKeys: [.isRegularFileKey, .isSymbolicLinkKey, .isDirectoryKey],
            options: []
        ) else {
            throw CodeSignerError.ioError("Failed to enumerate bundle at \(bundleURL.path)")
        }

        let bundlePath = bundleURL.standardizedFileURL.path
        let bundlePathPrefix = bundlePath.hasSuffix("/") ? bundlePath : bundlePath + "/"

        for case let fileURL as URL in enumerator {
            let standardized = fileURL.standardizedFileURL.path
            guard standardized.hasPrefix(bundlePathPrefix) else { continue }
            let relativePath = String(standardized.dropFirst(bundlePathPrefix.count))

            // Ignore the current bundle's own _CodeSignature directory
            if relativePath == "_CodeSignature" || relativePath.hasPrefix("_CodeSignature/") {
                continue
            }

            // Check if directory


            let resourceValues = try? fileURL.resourceValues(forKeys: [.isRegularFileKey, .isSymbolicLinkKey, .isDirectoryKey])
            if resourceValues?.isDirectory == true {
                continue
            }

            // Check if executable itself
            if let executableName = executableName, relativePath == executableName {
                continue
            }

            // Read file data
            guard let fileData = try? Data(contentsOf: fileURL) else {
                continue
            }

            // SHA-1
            let sha1Digest = Insecure.SHA1.hash(data: fileData)
            let sha1Data = Data(sha1Digest)

            // SHA-256
            let sha256Digest = SHA256.hash(data: fileData)
            let sha256Data = Data(sha256Digest)

            files[relativePath] = sha1Data
            if relativePath != "Info.plist" && relativePath != "PkgInfo" {
                files2[relativePath] = [
                    "hash2": sha256Data
                ]
            }
        }

        let rules: [String: any Sendable] = [
            "^.*": true,
            "^.*\\.lproj/": [
                "optional": true,
                "weight": 1000.0
            ],
            "^.*\\.lproj/locversion.plist$": [
                "omit": true,
                "weight": 1100.0
            ],
            "^Base\\.lproj/": [
                "weight": 1010.0
            ],
            "^version.plist$": true
        ]

        let rules2: [String: any Sendable] = [
            ".*\\.dSYM($|/)": [
                "weight": 11.0
            ],
            "^(.*/)?\\.DS_Store$": [
                "omit": true,
                "weight": 2000.0
            ],
            "^.*": true,
            "^.*\\.lproj/": [
                "optional": true,
                "weight": 1000.0
            ],
            "^.*\\.lproj/locversion.plist$": [
                "omit": true,
                "weight": 1100.0
            ],
            "^Base\\.lproj/": [
                "weight": 1010.0
            ],
            "^Info\\.plist$": [
                "omit": true,
                "weight": 20.0
            ],
            "^PkgInfo$": [
                "omit": true,
                "weight": 20.0
            ],
            "^embedded\\.provisionprofile$": [
                "weight": 20.0
            ],
            "^version\\.plist$": [
                "weight": 20.0
            ]
        ]


        let plistDict: [String: any Sendable] = [
            "files" : files,
            "files2": files2,
            "rules" : rules,
            "rules2": rules2
        ]

        return try PropertyListSerialization.data(fromPropertyList: plistDict, format: .xml, options: 0)
    }
}

