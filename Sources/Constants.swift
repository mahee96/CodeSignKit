//
//  Constants.swift
//  CodeSignKit
//
//  Created by Magesh K on 03/09/26.
//  Copyright © 2026 CodeSignKit. All rights reserved.
//

import Foundation

public enum Constants {
    // Recognized bundle directory extensions across iOS, iPadOS, macOS, watchOS, and tvOS
    public static let bundleExtensions: Set<String> = [
        "app", 
        "appex", 
        "framework", 
        "bundle", 
        "xpc", 
        "xctest", 
        "octest",
        "systemextension", 
        "plugin", 
        "mdimporter", 
        "qlgenerator", 
        "action", 
        "prefpane", 
        "kext"
    ]

    // Extensions representing framework, static/dynamic bundle, or kext containers
    public static let frameworkBundleExtensions: Set<String> = [
        "framework", 
        "bundle", 
        "kext"
    ]

    // Dynamic library and loose Mach-O binary extensions
    public static let dynamicLibraryExtensions: Set<String> = [
        "dylib", 
        "so"
    ]
}
