//
//  SignatureVerifier.swift
//  CodeSignKit
//
//  Created by Magesh K on 28/08/26.
//  Copyright © 2026 CodeSignKit. All rights reserved.
//

import Foundation
import CryptoKit
import OpenSSL

public struct VerificationResult {
    public let isValid: Bool
    public let path: String
    public let bundleIdentifier: String?
    public let teamIdentifier: String?
    public let cdHash: String?
    public let signerCertificateSubject: String?
    public let errors: [String]
    public let warnings: [String]

    public init(
        isValid: Bool,
        path: String,
        bundleIdentifier: String? = nil,
        teamIdentifier: String? = nil,
        cdHash: String? = nil,
        signerCertificateSubject: String? = nil,
        errors: [String] = [],
        warnings: [String] = []
    ) {
        self.isValid = isValid
        self.path = path
        self.bundleIdentifier = bundleIdentifier
        self.teamIdentifier = teamIdentifier
        self.cdHash = cdHash
        self.signerCertificateSubject = signerCertificateSubject
        self.errors = errors
        self.warnings = warnings
    }
}

public final class SignatureVerifier {

    public static func verify(url: URL, deep: Bool = true, strict: Bool = false) -> VerificationResult {
        let fileManager = FileManager.default
        var isDir: ObjCBool = false
        guard fileManager.fileExists(atPath: url.path, isDirectory: &isDir) else {
            return VerificationResult(
                isValid: false,
                path: url.path,
                errors: ["Path does not exist: \(url.path)"]
            )
        }

        if isDir.boolValue {
            return verifyBundle(at: url, deep: deep, strict: strict)
        } else {
            do {
                let data = try Data(contentsOf: url)
                return verify(binaryData: data, path: url.path)
            } catch {
                return VerificationResult(
                    isValid: false,
                    path: url.path,
                    errors: ["Failed to read binary file: \(error.localizedDescription)"]
                )
            }
        }
    }

    public static func verify(binaryData: Data, path: String = "") -> VerificationResult {
        guard binaryData.count >= 4 else {
            return VerificationResult(
                isValid: false,
                path: path,
                errors: ["Binary too short to be Mach-O"]
            )
        }

        let magic = binaryData.readUInt32(at: 0)

        // FAT binary
        if magic == CodeSigningConstants.FAT_MAGIC || magic == CodeSigningConstants.FAT_CIGAM ||
           magic == CodeSigningConstants.FAT_MAGIC_64 || magic == CodeSigningConstants.FAT_CIGAM_64 {
            return verifyFatBinary(binaryData: binaryData, path: path)
        } else if magic == CodeSigningConstants.MH_MAGIC_64 || magic == CodeSigningConstants.MH_CIGAM_64 ||
                  magic == CodeSigningConstants.MH_MAGIC || magic == CodeSigningConstants.MH_CIGAM {
            return verifyThinBinary(sliceData: binaryData, path: path)
        } else {
            return VerificationResult(
                isValid: false,
                path: path,
                errors: ["Unrecognized Mach-O magic: \(String(format: "0x%08X", magic))"]
            )
        }
    }
    private static func verifyThinBinary(sliceData: Data, path: String) -> VerificationResult {
        let parser = MachOParser(data: sliceData)

        var errors: [String] = []
        let warnings: [String] = []

        let bundleID = parser.bundleIdentifier()
        let teamID = parser.teamID()
        let cdHashes = parser.getCDHashes()
        let primaryCDHash = cdHashes.first

        // Verify page digests against CodeDirectory
        let thinData = (try? parser.getThinBinaryData()) ?? sliceData
        guard let cdBlob = try? parser.extractCodeDirectoryBlob() else {
            return VerificationResult(
                isValid: false,
                path: path,
                bundleIdentifier: bundleID,
                teamIdentifier: teamID,
                cdHash: primaryCDHash,
                errors: ["No CodeDirectory found in signature"]
            )
        }

        let pageVerification = verifyCodeDirectoryPages(cdBlob: cdBlob, thinData: thinData)
        if !pageVerification.isValid {
            errors.append(contentsOf: pageVerification.errors)
        }

        // Verify CMS Signature
        var signerSubject: String? = nil
        if let sigBlob = try? parser.extractSignatureBlob() {
            let cmsResult = verifyCMSSignatureBlob(sigBlob: sigBlob, codeDirectoryBlob: cdBlob)
            signerSubject = cmsResult.signerSubject
            if !cmsResult.isValid {
                if let err = cmsResult.error {
                    errors.append(err)
                }
            }
        } else {
            errors.append("No CMS signature blob found")
        }

        let isValid = errors.isEmpty
        return VerificationResult(
            isValid: isValid,
            path: path,
            bundleIdentifier: bundleID,
            teamIdentifier: teamID,
            cdHash: primaryCDHash,
            signerCertificateSubject: signerSubject,
            errors: errors,
            warnings: warnings
        )
    }

    private static func verifyFatBinary(binaryData: Data, path: String) -> VerificationResult {

        let is64 = (binaryData.readUInt32(at: 0) == CodeSigningConstants.FAT_MAGIC_64 ||
                    binaryData.readUInt32(at: 0) == CodeSigningConstants.FAT_CIGAM_64)
        let swap = (binaryData.readUInt32(at: 0) == CodeSigningConstants.FAT_CIGAM ||
                    binaryData.readUInt32(at: 0) == CodeSigningConstants.FAT_CIGAM_64)

        let nfatArch = Int(swap ? binaryData.readUInt32(at: 4).byteSwapped : binaryData.readUInt32(at: 4))
        let archHeaderSize = is64 ? 32 : 20
        var headerOffset = 8

        var allErrors: [String] = []
        var allWarnings: [String] = []
        var primaryID: String? = nil
        var primaryTeam: String? = nil
        var primaryHash: String? = nil
        var primarySubject: String? = nil

        for archIndex in 0..<nfatArch {
            guard headerOffset + archHeaderSize <= binaryData.count else {
                return VerificationResult(isValid: false, path: path, errors: ["Truncated FAT header"])
            }

            let offset = Int(swap ? binaryData.readUInt32(at: headerOffset + 8).byteSwapped : binaryData.readUInt32(at: headerOffset + 8))
            let size = Int(swap ? binaryData.readUInt32(at: headerOffset + 12).byteSwapped : binaryData.readUInt32(at: headerOffset + 12))

            guard offset + size <= binaryData.count else {
                return VerificationResult(isValid: false, path: path, errors: ["Invalid FAT slice offset/size"])
            }

            let sliceData = binaryData.subdata(in: offset..<offset + size)
            let result = verifyThinBinary(sliceData: sliceData, path: "\(path) (slice \(archIndex))")

            if primaryID == nil { primaryID = result.bundleIdentifier }
            if primaryTeam == nil { primaryTeam = result.teamIdentifier }
            if primaryHash == nil { primaryHash = result.cdHash }
            if primarySubject == nil { primarySubject = result.signerCertificateSubject }

            if !result.isValid {
                allErrors.append(contentsOf: result.errors)
            }
            allWarnings.append(contentsOf: result.warnings)

            headerOffset += archHeaderSize
        }

        return VerificationResult(
            isValid: allErrors.isEmpty,
            path: path,
            bundleIdentifier: primaryID,
            teamIdentifier: primaryTeam,
            cdHash: primaryHash,
            signerCertificateSubject: primarySubject,
            errors: allErrors,
            warnings: allWarnings
        )
    }

    private static func verifyBundle(at bundleURL: URL, deep: Bool, strict: Bool) -> VerificationResult {
        var errors: [String] = []
        let warnings: [String] = []


        guard let executableURL = MachOParser.findExecutable(at: bundleURL) else {
            return VerificationResult(
                isValid: false,
                path: bundleURL.path,
                errors: ["Could not find executable for bundle at \(bundleURL.path)"]
            )
        }

        // 1. Verify CodeResources sealing
        let codeSigURL = bundleURL.appendingPathComponent("_CodeSignature").appendingPathComponent("CodeResources")
        if !FileManager.default.fileExists(atPath: codeSigURL.path) {
            errors.append("Missing CodeResources file at \(codeSigURL.path)")
        } else if let resData = try? Data(contentsOf: codeSigURL),
                  let plist = try? PropertyListSerialization.propertyList(from: resData, options: [], format: nil) as? [String: Any] {

            // Check files2 (SHA-256)
            if let files2 = plist["files2"] as? [String: Any] {
                for (relPath, info) in files2 {
                    let fileURL = bundleURL.appendingPathComponent(relPath)
                    guard FileManager.default.fileExists(atPath: fileURL.path) else {
                        errors.append("Sealed resource missing: \(relPath)")
                        continue
                    }

                    if let fileDict = info as? [String: Any], let expectedHash = fileDict["hash2"] as? Data {
                        if let fileData = try? Data(contentsOf: fileURL) {
                            let actualHash = Data(SHA256.hash(data: fileData))
                            if actualHash != expectedHash {
                                errors.append("Resource modified: \(relPath)")
                            }
                        }
                    }
                }
            }
        }

        // 2. Verify main executable
        let mainResult = verify(url: executableURL, deep: false, strict: strict)
        if !mainResult.isValid {
            errors.append(contentsOf: mainResult.errors)
        }

        // 3. Deep verification of embedded frameworks and extensions if requested
        if deep {
            let frameworksDir = bundleURL.appendingPathComponent("Frameworks")
            if FileManager.default.fileExists(atPath: frameworksDir.path),
               let items = try? FileManager.default.contentsOfDirectory(at: frameworksDir, includingPropertiesForKeys: nil) {
                for item in items {
                    if item.pathExtension == "framework" || item.pathExtension == "dylib" {
                        let subResult = verify(url: item, deep: true, strict: strict)
                        if !subResult.isValid {
                            errors.append(contentsOf: subResult.errors)
                        }
                    }
                }
            }

            let pluginsDir = bundleURL.appendingPathComponent("PlugIns")
            if FileManager.default.fileExists(atPath: pluginsDir.path),
               let items = try? FileManager.default.contentsOfDirectory(at: pluginsDir, includingPropertiesForKeys: nil) {
                for item in items {
                    if item.pathExtension == "appex" {
                        let subResult = verify(url: item, deep: true, strict: strict)
                        if !subResult.isValid {
                            errors.append(contentsOf: subResult.errors)
                        }
                    }
                }
            }
        }

        return VerificationResult(
            isValid: errors.isEmpty,
            path: bundleURL.path,
            bundleIdentifier: mainResult.bundleIdentifier,
            teamIdentifier: mainResult.teamIdentifier,
            cdHash: mainResult.cdHash,
            signerCertificateSubject: mainResult.signerCertificateSubject,
            errors: errors,
            warnings: warnings
        )
    }

    private static func verifyCodeDirectoryPages(cdBlob: Data, thinData: Data) -> (isValid: Bool, errors: [String]) {
        guard cdBlob.count >= 44 else {
            return (false, ["CodeDirectory blob too small"])
        }

        let magic = cdBlob.readUInt32BigEndian(at: 0)
        guard magic == CodeSigningConstants.CSMAGIC_CODEDIRECTORY else {
            return (false, ["Invalid CodeDirectory magic: \(String(format: "0x%08X", magic))"])
        }

        let hashOffset = Int(cdBlob.readUInt32BigEndian(at: 16))
        let _ = Int(cdBlob.readUInt32BigEndian(at: 24))
        let nCodeSlots = Int(cdBlob.readUInt32BigEndian(at: 28))
        let codeLimit = Int(cdBlob.readUInt32BigEndian(at: 32))
        let hashSize = Int(cdBlob[36])
        let hashType = cdBlob[37]
        let pageSizeShift = Int(cdBlob[39])
        let pageSize = 1 << pageSizeShift

        guard hashType == CodeSigningConstants.CS_HASHTYPE_SHA256 || hashType == CodeSigningConstants.CS_HASHTYPE_SHA1 else {
            return (false, ["Unsupported CodeDirectory hash type: \(hashType)"])
        }

        var errors: [String] = []

        // Verify code page hashes
        for slot in 0..<nCodeSlots {
            let pageStart = slot * pageSize
            guard pageStart < codeLimit else { break }
            let pageEnd = min(pageStart + pageSize, codeLimit)
            guard pageEnd <= thinData.count else {
                errors.append("Page \(slot) extends beyond binary bounds")
                break
            }

            let pageData = thinData.subdata(in: pageStart..<pageEnd)
            let actualHash: Data
            if hashType == CodeSigningConstants.CS_HASHTYPE_SHA256 {
                actualHash = Data(SHA256.hash(data: pageData))
            } else {
                actualHash = Data(Insecure.SHA1.hash(data: pageData))
            }

            let slotOffset = hashOffset + slot * hashSize
            guard slotOffset + hashSize <= cdBlob.count else {
                errors.append("CodeDirectory slots truncated at slot \(slot)")
                break
            }

            let expectedHash = cdBlob.subdata(in: slotOffset..<slotOffset + hashSize)
            if actualHash != expectedHash {
                errors.append("Code page \(slot) hash mismatch (tampered binary content)")
            }
        }

        return (errors.isEmpty, errors)
    }

    private static func verifyCMSSignatureBlob(
        sigBlob: Data,
        codeDirectoryBlob: Data
    ) -> (isValid: Bool, signerSubject: String?, error: String?) {
        // Strip BlobWrapper (0xfade0b01) if present
        var derData = sigBlob
        if derData.count >= 8 {
            let magic = derData.readUInt32BigEndian(at: 0)
            if magic == CodeSigningConstants.CSMAGIC_BLOBWRAPPER {
                let len = Int(derData.readUInt32BigEndian(at: 4))
                if len <= derData.count && len > 8 {
                    derData = derData.subdata(in: 8..<len)
                }
            }
        }

        let inBio = BIO_new(BIO_s_mem())
        defer { BIO_free(inBio) }
        _ = derData.withUnsafeBytes { raw in
            BIO_write(inBio, raw.baseAddress, Int32(raw.count))
        }

        guard let cms = d2i_CMS_bio(inBio, nil) else {
            return (false, nil, "Failed to parse CMS signature ASN.1 structure")
        }
        defer { CMS_ContentInfo_free(cms) }

        // Extract signer certificate subject
        var subjectName: String? = nil
        if let certStack = CMS_get1_certs(cms) {
            let count = OPENSSL_sk_num(certStack)
            for idx in 0..<count {
                if let rawVal = OPENSSL_sk_value(certStack, idx) {
                    let cert = OpaquePointer(rawVal)
                    if subjectName == nil, let namePtr = X509_get_subject_name(cert) {
                        var buffer = [CChar](repeating: 0, count: 256)
                        X509_NAME_oneline(namePtr, &buffer, Int32(buffer.count))
                        subjectName = String(cString: buffer)
                    }
                    X509_free(cert)
                }
            }
            OPENSSL_sk_free(certStack)
        }

        // Verify CMS detached signature against CodeDirectory data
        let dataBio = BIO_new(BIO_s_mem())
        defer { BIO_free(dataBio) }
        _ = codeDirectoryBlob.withUnsafeBytes { raw in
            BIO_write(dataBio, raw.baseAddress, Int32(raw.count))
        }

        let flags: UInt32 = UInt32(CMS_NO_SIGNER_CERT_VERIFY | CMS_DETACHED | CMS_BINARY)
        let verifyResult = CMS_verify(cms, nil, nil, dataBio, nil, flags)

        if verifyResult == 1 {
            return (true, subjectName, nil)
        } else {
            return (false, subjectName, "Cryptographic CMS signature verification failed")
        }
    }

}

fileprivate extension Data {
    func readUInt32(at offset: Int) -> UInt32 {
        guard offset + 4 <= self.count else { return 0 }
        return self.withUnsafeBytes { $0.loadUnaligned(fromByteOffset: offset, as: UInt32.self) }
    }

    func readUInt32BigEndian(at offset: Int) -> UInt32 {
        guard offset + 4 <= self.count else { return 0 }
        return self.withUnsafeBytes { $0.loadUnaligned(fromByteOffset: offset, as: UInt32.self).bigEndian }
    }
}
