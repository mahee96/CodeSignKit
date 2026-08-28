//
//  CMSSigner.swift
//  CodeSignKit
//
//  Created by Magesh K on 28/08/26.
//  Copyright © 2026 CodeSignKit. All rights reserved.
//


import Foundation
import OpenSSL
import CryptoKit

public final class CMSSigner {


    // Apple Root Certificate (PEM)
    public static let AppleRootCertPEM = """
    -----BEGIN CERTIFICATE-----
    MIIEuzCCA6OgAwIBAgIBAjANBgkqhkiG9w0BAQUFADBiMQswCQYDVQQGEwJVUzET
    MBEGA1UEChMKQXBwbGUgSW5jLjEmMCQGA1UECxMdQXBwbGUgQ2VydGlmaWNhdGlv
    biBBdXRob3JpdHkxFjAUBgNVBAMTDUFwcGxlIFJvb3QgQ0EwHhcNMDYwNDI1MjE0
    MDM2WhcNMzUwMjA5MjE0MDM2WjBiMQswCQYDVQQGEwJVUzETMBEGA1UEChMKQXBw
    bGUgSW5jLjEmMCQGA1UECxMdQXBwbGUgQ2VydGlmaWNhdGlvbiBBdXRob3JpdHkx
    FjAUBgNVBAMTDUFwcGxlIFJvb3QgQ0EwggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAw
    ggEKAoIBAQDkkakJH5HbHkdQ6wXtXnmELes2oldMVeyLGYne+Uts9QerIjAC6Bg+
    +FAJ039BqJj50cpmnCRrEdCju+QbKsMflZ56DKRHi1vUFjczy8QPTc4UadHJGXL1
    XQ7Vf1+b8iUDulWPTV0N8WQ1IxVLFVkds5T39pyez1C6wVhQZ48ItCD3y6wsIG9w
    tj8BMIy3Q88PnT3zK0koGsj+zrW5DtleHNbLPbU6rfQPDgCSC7EhFi501TwN22IW
    q6NxkkdTVcGvL0Gz+PvjcM3mo0xFfh9Ma1CWQYnEdGILEINBhzOKgbEwWOxaBDKM
    aLOPHd5lc/9nXmW8Sdh2nzMUZaF3lMktAgMBAAGjggF6MIIBdjAOBgNVHQ8BAf8E
    BAMCAQYwDwYDVR0TAQH/BAUwAwEB/zAdBgNVHQ4EFgQUK9BpR5R2Cf70a40uQKb3
    R01/CF4wHwYDVR0jBBgwFoAUK9BpR5R2Cf70a40uQKb3R01/CF4wggERBgNVHSAE
    ggEIMIIBBDCCAQAGCSqGSIb3Y2QFATCB8jAqBggrBgEFBQcCARYeaHR0cHM6Ly93
    d3cuYXBwbGUuY29tL2FwcGxlY2EvMIHDBggrBgEFBQcCAjCBthqBs1JlbGlhbmNl
    IG9uIHRoaXMgY2VydGlmaWNhdGUgYnkgYW55IHBhcnR5IGFzc3VtZXMgYWNjZXB0
    YW5jZSBvZiB0aGUgdGhlbiBhcHBsaWNhYmxlIHN0YW5kYXJkIHRlcm1zIGFuZCBj
    b25kaXRpb25zIG9mIHVzZSwgY2VydGlmaWNhdGUgcG9saWN5IGFuZCBjZXJ0aWZp
    Y2F0aW9uIHByYWN0aWNlIHN0YXRlbWVudHMuMA0GCSqGSIb3DQEBBQUAA4IBAQBc
    NplMLXi37Yyb3PN3m/J20ncwT8EfhYOFG5k9RzfyqZtAjizUsZAS2L70c5vu0mQP
    y3lPNNiiPvl4/2vIB+x9OYOLUyDTOMSxv5pPCmv/K/xZpwUJfBdAVhEedNO3iyM7
    R6PVbyTi69G3cN8PReEnyvFteO3ntRcXqNx+IjXKJdXZD9Zr1KIkIxH3oayPc4Fg
    xhtbCS+SsvhESPBgOJ4V9T0mZyCKM2r3DYLP3uujL/lTaltkwGMzd/c6ByxW69oP
    IQ7aunMZT7XZNn/Bh1XZp5m5MkL72NVxnn6hUrcbvZNCJBIqxw8dtk2cXmPIS4AX
    UKqK1drk/NAJBzewdXUh
    -----END CERTIFICATE-----
    """

    // Apple WWDR G3 Certificate (PEM)
    public static let AppleWWDRCertPEM = """
    -----BEGIN CERTIFICATE-----
    MIIEUTCCAzmgAwIBAgIQfK9pCiW3Of57m0R6wXjF7jANBgkqhkiG9w0BAQsFADBi
    MQswCQYDVQQGEwJVUzETMBEGA1UEChMKQXBwbGUgSW5jLjEmMCQGA1UECxMdQXBw
    bGUgQ2VydGlmaWNhdGlvbiBBdXRob3JpdHkxFjAUBgNVBAMTDUFwcGxlIFJvb3Qg
    Q0EwHhcNMjAwMjE5MTgxMzQ3WhcNMzAwMjIwMDAwMDAwWjB1MUQwQgYDVQQDDDtB
    cHBsZSBXb3JsZHdpZGUgRGV2ZWxvcGVyIFJlbGF0aW9ucyBDZXJ0aWZpY2F0aW9u
    IEF1dGhvcml0eTELMAkGA1UECwwCRzMxEzARBgNVBAoMCkFwcGxlIEluYy4xCzAJ
    BgNVBAYTAlVTMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA2PWJ/KhZ
    C4fHTJEuLVaQ03gdpDDppUjvC0O/LYT7JF1FG+XrWTYSXFRknmxiLbTGl8rMPPbW
    BpH85QKmHGq0edVny6zpPwcR4YS8Rx1mjjmi6LRJ7TrS4RBgeo6TjMrA2gzAg9Dj
    +ZHWp4zIwXPirkbRYp2SqJBgN31ols2N4Pyb+ni743uvLRfdW/6AWSN1F7gSwe0b
    5TTO/iK1nkmw5VW/j4SiPKi6xYaVFuQAyZ8D0MyzOhZ71gVcnetHrg21LYwOaU1A
    0EtMOwSejSGxrC5DVDDOwYqGlJhL32oNP/77HK6XF8J4CjDgXx9UO0m3JQAaN4LS
    VpelUkl8YDib7wIDAQABo4HvMIHsMBIGA1UdEwEB/wQIMAYBAf8CAQAwHwYDVR0j
    BBgwFoAUK9BpR5R2Cf70a40uQKb3R01/CF4wRAYIKwYBBQUHAQEEODA2MDQGCCsG
    AQUFBzABhihodHRwOi8vb2NzcC5hcHBsZS5jb20vb2NzcDAzLWFwcGxlcm9vdGNh
    MC4GA1UdHwQnMCUwI6AhoB+GHWh0dHA6Ly9jcmwuYXBwbGUuY29tL3Jvb3QuY3Js
    MB0GA1UdDgQWBBQJ/sAVkPmvZAqSErkmKGMMl+ynsjAOBgNVHQ8BAf8EBAMCAQYw
    EAYKKoZIhvdjZAYCAQQCBQAwDQYJKoZIhvcNAQELBQADggEBAK1lE+j24IF3RAJH
    Qr5fpTkg6mKp/cWQyXMT1Z6b0KoPjY3L7QHPbChAW8dVJEH4/M/BtSPp3Ozxb8qA
    HXfCxGFJJWevD8o5Ja3T43rMMygNDi6hV0Bz+uZcrgZRKe3jhQxPYdwyFot30ETK
    XXIDMUacrptAGvr04NM++i+MZp+XxFRZ79JI9AeZSWBZGcfdlNHAwWx/eCHvDOs7
    bJmCS1JgOLU5gm3sUjFTvg+RTElJdI+mUcuER04ddSduvfnSXPN/wmwLCTbiZOTC
    NwMUGdXqapSqqdv+9poIZ4vvK7iqF0mDr8/LvOnP6pVxsLRFoszlh6oKw0E6eVza
    UDSdlTs=
    -----END CERTIFICATE-----
    """

    // Apple CDHashes ASN.1 OID (1.2.840.113635.100.9.1)
    public static let appleCDHashesOID = "1.2.840.113635.100.9.1"
    public static let appleCDHashes2OID = "1.2.840.113635.100.9.2"

    private static func resolveAppleCDHashesNID() -> Int32 {
        var nid = OBJ_txt2nid(appleCDHashesOID)
        if nid == NID_undef {
            nid = OBJ_create(appleCDHashesOID, "apple-cdhashes", "Apple CDHashes")
        }
        return nid
    }

    private static func resolveAppleCDHashes2NID() -> Int32 {
        var nid = OBJ_txt2nid(appleCDHashes2OID)
        if nid == NID_undef {
            nid = OBJ_create(appleCDHashes2OID, "apple-cdhashes2", "Apple CDHashes 2")
        }
        return nid
    }

    private let p12Data: Data
    private let password: String

    public init(p12Data: Data, password: String = "") {
        self.p12Data = p12Data
        self.password = password
    }

    public func getLeafCertificateSHA1() -> Data? {

        _ = OSSL_PROVIDER_load(nil, "legacy")
        _ = OSSL_PROVIDER_load(nil, "default")

        let bio = BIO_new(BIO_s_mem())
        defer { BIO_free(bio) }

        _ = p12Data.withUnsafeBytes { buf in
            BIO_write(bio, buf.baseAddress, Int32(p12Data.count))
        }

        guard let p12 = d2i_PKCS12_bio(bio, nil) else { return nil }
        defer { PKCS12_free(p12) }

        var pkey: OpaquePointer? = nil
        var cert: OpaquePointer? = nil
        var caStack: OpaquePointer? = nil

        let passCString = password.cString(using: .utf8)
        guard PKCS12_parse(p12, passCString, &pkey, &cert, &caStack) == 1, let cert = cert else {
            return nil
        }
        defer {
            if let pkey { EVP_PKEY_free(pkey) }
            X509_free(cert)
            if let caStack {
                OPENSSL_sk_pop_free(caStack) { X509_free(OpaquePointer($0)) }
            }
        }

        var md = [UInt8](repeating: 0, count: Int(EVP_MAX_MD_SIZE))
        var len: UInt32 = 0
        guard X509_digest(cert, EVP_sha1(), &md, &len) == 1, len == 20 else {
            return nil
        }
        return Data(md.prefix(Int(len)))
    }

    public func sign(codeDirectoryData: Data) throws -> Data {
        _ = OSSL_PROVIDER_load(nil, "legacy")
        _ = OSSL_PROVIDER_load(nil, "default")

        let bio = BIO_new(BIO_s_mem())
        defer { BIO_free(bio) }

        _ = p12Data.withUnsafeBytes { buf in
            BIO_write(bio, buf.baseAddress, Int32(p12Data.count))
        }

        guard let p12 = d2i_PKCS12_bio(bio, nil) else {
            throw CodeSignerError.certificateError("Failed to parse PKCS#12 signing data")
        }

        defer { PKCS12_free(p12) }

        var pkey: OpaquePointer? = nil
        var cert: OpaquePointer? = nil
        var caStack: OpaquePointer? = nil

        let passCString = password.cString(using: .utf8)
        guard PKCS12_parse(p12, passCString, &pkey, &cert, &caStack) == 1, let pkey = pkey, let cert = cert else {
            throw CodeSignerError.certificateError("Failed to extract private key and certificate from PKCS#12")
        }
        defer {
            EVP_PKEY_free(pkey)
            X509_free(cert)
            if let caStack {
                OPENSSL_sk_pop_free(caStack) { X509_free(OpaquePointer($0)) }
            }
        }
        // Initialize CMS structure
        let dataBio = BIO_new_mem_buf(codeDirectoryData.withUnsafeBytes { $0.baseAddress }, Int32(codeDirectoryData.count))
        defer { BIO_free(dataBio) }

        guard let cms = CMS_sign(nil, nil, nil, nil, UInt32(CMS_PARTIAL | CMS_DETACHED | CMS_BINARY | CMS_NOSMIMECAP)) else {
            throw CodeSignerError.signingFailed("Failed to create CMS structure")
        }
        defer { CMS_ContentInfo_free(cms) }

        // Add signer
        guard let signerInfo = CMS_add1_signer(cms, cert, pkey, EVP_sha256(), UInt32(CMS_PARTIAL | CMS_NOSMIMECAP | CMS_BINARY)) else {
            throw CodeSignerError.signingFailed("Failed to add signer to CMS")
        }

        // Add CA certificates if any
        if let caStack {
            let numCAs = OPENSSL_sk_num(caStack)
            for i in 0..<numCAs {
                if let caCert = OPENSSL_sk_value(caStack, i) {
                    CMS_add1_cert(cms, OpaquePointer(caCert))
                }
            }
        }

        // Add Apple CDHash sequence (1.2.840.113635.100.9.2)
        let cdHash = SHA256.hash(data: codeDirectoryData)
        let cdHashData = Data(cdHash)
        let appleNID2 = Self.resolveAppleCDHashes2NID()
        if appleNID2 != NID_undef {
            var seq = Data([0x30, 0x2D, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x01, 0x04, 0x20])
            seq.append(cdHashData)
            seq.withUnsafeBytes { raw in
                if let base = raw.baseAddress?.assumingMemoryBound(to: UInt8.self) {
                    var p: UnsafePointer<UInt8>? = base
                    if let asn1 = d2i_ASN1_TYPE(nil, &p, seq.count) {
                        CMS_signed_add1_attr_by_NID(signerInfo, appleNID2, Int32(asn1.pointee.type), asn1.pointee.value.ptr, -1)
                        ASN1_TYPE_free(asn1)
                    }
                }
            }
        }

        // Add Apple CDHash plist (1.2.840.113635.100.9.1)
        let truncatedCDHash = cdHashData.prefix(20)
        let plistDict: [String: Any] = ["cdhashes": [truncatedCDHash]]
        let plistData = (try? PropertyListSerialization.data(fromPropertyList: plistDict, format: .xml, options: 0)) ?? Data()


        let appleNID1 = Self.resolveAppleCDHashesNID()
        if appleNID1 != NID_undef, let octetStr = ASN1_OCTET_STRING_new() {
            _ = plistData.withUnsafeBytes { raw in
                ASN1_OCTET_STRING_set(octetStr, raw.baseAddress?.assumingMemoryBound(to: UInt8.self), Int32(raw.count))
            }
            CMS_signed_add1_attr_by_NID(signerInfo, appleNID1, V_ASN1_OCTET_STRING, UnsafeRawPointer(octetStr), -1)
            ASN1_OCTET_STRING_free(octetStr)
        }

        // Finalize CMS
        _ = BIO_ctrl(dataBio, 1 /* BIO_CTRL_RESET */, 0, nil)
        guard CMS_final(cms, dataBio, nil, UInt32(CMS_DETACHED | CMS_BINARY)) == 1 else {
            throw CodeSignerError.signingFailed("Failed to finalize CMS signature")
        }

        // Adjust signature algorithm OID to sha256WithRSAEncryption if using RSA
        var psigAlg: UnsafeMutablePointer<X509_ALGOR>? = nil
        CMS_SignerInfo_get0_algs(signerInfo, nil, nil, nil, &psigAlg)
        if let psigAlg {
            X509_ALGOR_set0(psigAlg, OBJ_nid2obj(NID_sha256WithRSAEncryption), V_ASN1_NULL, nil)
        }




        // Export CMS DER
        let outBio = BIO_new(BIO_s_mem())
        defer { BIO_free(outBio) }

        guard i2d_CMS_bio(outBio, cms) == 1 else {
            throw CodeSignerError.signingFailed("Failed to serialize CMS DER")
        }

        var derPtr: UnsafeMutablePointer<CChar>? = nil
        let derLen = Int(BIO_ctrl(outBio, 3 /* BIO_CTRL_INFO */, 0, &derPtr))
        guard derLen > 0, let derPtr = derPtr else {
            throw CodeSignerError.signingFailed("Failed to extract CMS DER bytes")
        }

        let rawDER = Data(bytes: derPtr, count: derLen)

        // Wrap in BlobWrapper (0xfade0b01)
        let totalWrapperSize = 8 + rawDER.count
        var wrapper = Data(count: totalWrapperSize)
        wrapper.writeUInt32BigEndian(CodeSigningConstants.CSMAGIC_BLOBWRAPPER, at: 0)
        wrapper.writeUInt32BigEndian(UInt32(totalWrapperSize), at: 4)
        wrapper.replaceSubrange(8..<totalWrapperSize, with: rawDER)

        return wrapper
    }
}

fileprivate extension Data {

    mutating func writeUInt32BigEndian(_ value: UInt32, at offset: Int) {
        var bigEndian = value.bigEndian
        Swift.withUnsafeBytes(of: &bigEndian) { bytes in
            self.replaceSubrange(offset..<offset + 4, with: bytes)
        }
    }
}

