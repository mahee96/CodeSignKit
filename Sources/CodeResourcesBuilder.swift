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

        struct FileEntry {
            let relativePath: String
            let url: URL
        }

        var candidateFiles: [FileEntry] = []

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

            candidateFiles.append(FileEntry(relativePath: relativePath, url: fileURL))
        }

        struct HashResult {
            let relativePath: String
            let sha1: Data
            let sha256: Data
        }

        var hashResults = [HashResult?](repeating: nil, count: candidateFiles.count)

        DispatchQueue.concurrentPerform(iterations: candidateFiles.count) { i in
            let item = candidateFiles[i]
            let fileData = (try? Data(contentsOf: item.url, options: .alwaysMapped)) ?? (try? Data(contentsOf: item.url)) ?? Data()
            let sha1 = Data(Insecure.SHA1.hash(data: fileData))
            let sha256 = Data(SHA256.hash(data: fileData))
            hashResults[i] = HashResult(relativePath: item.relativePath, sha1: sha1, sha256: sha256)
        }

        for result in hashResults.compactMap({ $0 }) {
            files[result.relativePath] = result.sha1
            if result.relativePath != "Info.plist" && result.relativePath != "PkgInfo" {
                files2[result.relativePath] = [
                    "hash2": result.sha256
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

