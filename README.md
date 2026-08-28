# CodeSignKit

A high-performance, pure Swift Mach-O parser, CodeDirectory generator, CodeResources sealer, SuperBlob builder, and CMS code signer for **iOS, macOS, tvOS, and visionOS** via Swift Package Manager.

---

## Features

- **Full Mach-O Architecture Support**: Parses and signs 32-bit (`MH_MAGIC`), 64-bit (`MH_MAGIC_64`), and Universal / FAT binaries (`FAT_MAGIC`, `FAT_MAGIC_64`) across ARM64, ARM64e, and x86_64 architectures.
- **CodeDirectory Generation**: Generates `CS_CodeDirectory` structures with configurable hash types (SHA-1, SHA-256), page hashes, executive segment limits, flags, and slot hashing.
- **Sealed CodeResources**: Recursively traverses and seals app bundles into `_CodeSignature/CodeResources` XML property lists with dual SHA-1 and SHA-256 digests.
- **SuperBlob Assembly**: Builds compliant `CSMAGIC_EMBEDDED_SIGNATURE` SuperBlobs containing CodeDirectory, Requirements, Entitlements (XML & DER), and CMS Signatures.
- **CMS / PKCS#7 Signatures**: Generates RFC 5652 CMS / PKCS#7 detached signatures using pure Swift (`swift-crypto` and `swift-asn1`).
- **Recursive Bundle Signing**: Automatically signs embedded frameworks, dynamic libraries (`.dylib`), app extensions (`.appex`), and parent application bundles in correct hierarchical dependency order.
- **Entitlements Extraction**: Reads, parses, and extracts embedded XML entitlements and code requirements directly from unsigned or signed Mach-O binaries.

---

## Platforms Supported

| Platform                          | Signing Mode | Dependency Requirements        |
| :-------------------------------- | :----------- | :----------------------------- |
| **iOS (Real Device & Simulator)** | In-Process   | (`swift-crypto`, `swift-asn1`) |
| **macOS (ARM64 & x86_64)**        | In-Process   | (`swift-crypto`, `swift-asn1`) |
| **tvOS (Device & Simulator)**     | In-Process   | (`swift-crypto`, `swift-asn1`) |
| **visionOS (Device & Simulator)** | In-Process   | (`swift-crypto`, `swift-asn1`) |
| **Linux (ARM64 & x86_64)**        | In-Process   | (`swift-crypto`, `swift-asn1`) |

---

## Installation

Add `CodeSignKit` to your `Package.swift` dependencies:

```swift
dependencies: [
    .package(url: "https://github.com/mahee96/CodeSignKit.git", branch: "main")
]


```

Or add it to your target:

```swift
.target(
    name: "MyTarget",
    dependencies: ["CodeSignKit"]
)
```

---

## Public API Reference

### `CodeSigner`

High-level coordinator for recursively signing complete application bundles and nested binaries.

#### `sign(appPath:keyData:entitlementProvider:progress:) throws`

- **When to use**: High-level signing of an entire `.app` bundle including embedded frameworks and plugins.
- **Parameters**:
  - `appPath`: Path string to the target application bundle (`.app`).
  - `keyData`: Raw PKCS#12 (`.p12`) archive data containing the signing certificate and private key.
  - `entitlementProvider`: Closure returning custom XML entitlements for a given bundle identifier.
  - `progress`: Closure invoked as individual bundle components are signed.

---

### `MachOParser`

Low-level parser for Mach-O binaries, universal fat archives, load commands, and embedded signatures.

#### `init(data:) throws` / `init(url:) throws`

- **When to use**: Instantiates parser from raw binary `Data` or file `URL`.

#### `extractEntitlements() throws -> String?`

- **When to use**: Extracts the embedded XML entitlements string from the Mach-O SuperBlob.

#### `requirements() throws -> String`

- **When to use**: Extracts the code requirement binary blob as a decompiled string.

#### `findExecutable(at:) -> URL?`

- **When to use**: Locates the main executable binary within an app bundle or framework wrapper.

---

### `MachOSigner`

Constructs and injects `LC_CODE_SIGNATURE` load commands and SuperBlobs into Mach-O binaries.

#### `init(binaryData:bundleIdentifier:teamIdentifier:entitlementsXML:infoPlistData:codeResourcesData:cmsSigner:)`

- **When to use**: Prepares binary slice signing configuration.

#### `sign() throws -> Data`

- **When to use**: Processes binary slices, aligns segments, generates CodeDirectories, and outputs signed binary data.

---

### `CodeResourcesBuilder`

Constructs sealed resource manifests (`_CodeSignature/CodeResources`).

#### `init(bundleURL:executableName:)`

- **When to use**: Prepares recursive resource scanning for a given bundle URL.

#### `build() throws -> Data`

- **When to use**: Scans bundle files and serializes the signed plist payload.

---

### `CMSSigner`

Generates Cryptographic Message Syntax (CMS / PKCS#7) detached signatures.

#### `init(p12Data:password:)`

- **When to use**: Initializes CMS signer from PKCS#12 certificate and private key.

#### `sign(cdHash:dataToSign:) throws -> Data`

- **When to use**: Signs CodeDirectory digests and returns DER-encoded CMS signature blob.

---

## Disclaimer

This project is provided for **educational and research purposes only**.

- `CodeSignKit` is an independent project and is not affiliated with, sponsored by, or endorsed by Apple Inc.
- Use of this software is entirely at your own risk. The author and contributors assume no responsibility or liability for any damages, revoked certificates, or legal repercussions arising from the use or distribution of this code.
- By using this library, you agree to comply with all applicable terms, laws, and regulations.

---

## License & Terms

`CodeSignKit` is licensed under the **GNU Affero General Public License v3.0 (AGPLv3)**.

### Key Terms:

- **Strong Copyleft**: Any application, framework, or tool that compiles against, links against (statically or dynamically), or includes `CodeSignKit` is considered a combined/derivative work and **must be fully open-sourced under the AGPLv3** upon distribution.
- **Network / Cloud Trigger (AGPL Section 13)**: If you run `CodeSignKit` as part of any network service, cloud signing API, or remote server, you **must make the complete, corresponding source code of the entire service and all linked software available** to all users interacting with it over the network.
- **Closed-Source / Proprietary Use Prohibited**: Closed-source, commercial, or proprietary distribution without full source disclosure is **strictly prohibited** under the AGPLv3.
- **App Store Distribution Prohibited**: Inclusion in, linking against, or distribution through any App Store builds is **strictly prohibited**.

Copyright © 2026 Magesh K. All rights reserved.

Full license information can be found at [LICENSE](./LICENSE)
