//
//  LSJailBreakChecker.swift
//  LSJailBreakChecker
//
//  Created by 영준 이 on 2020/10/13.
//

import UIKit
import CryptoKit
import CommonCrypto

public class LSJailBreakChecker{
    fileprivate static let _breakerFiles = [
                        "/Applications/Cydia.app",
                        "/var/cache/apt",
                        "/var/lib/apt/",
                        "/var/lib/cydia",
                        "/var/log/syslog",
                        "/var/tmp/cydia.log",
                        "/usr/libexec/ssh-keysign",
                        "/etc/ssh/sshd_config",
                        "/jb",
                        "/private/var/tmp/cydia.log",
                        "/private/var/lib/cydia",
                        "/Library/MobileSubstrate/DynamicLibraries",
                        "/private/var/mobile/Library/SBSettings/",
                        "/Applications/blackra1n.app",
                        "/Applications/FakeCarrier.app",
                        "/Applications/Icy.app",
                        "/Applications/IntelliScreen.app",
                        "/Applications/MxTube.app",
                        "/Applications/RockApp.app",
                        "/Applications/SBSettings.app",
                        "/Applications/WinterBoard.app",
                        "/Library/MobileSubstrate/MobileSubstrate.dylib",
                        "/Library/MobileSubstrate/DynamicLibraries/LiveClock.plist",
                        "/Library/MobileSubstrate/DynamicLibraries/Veency.plist",
//                        "/private/var/mobile/Library/",
                        "/private/var/mobile/Library/SBSettings/Themes",
                        "/private/var/stash",
                        "/private/var/lib/cydia",
                        "/private/var/lib/apt/",
//                        "/System/Library/LaunchDaemons/",
                        "/System/Library/LaunchDaemons/com.ikey.bbot.plist",
                        "/System/Library/LaunchDaemons/com.saurik.Cydia.Startup.plist",
                        "/bin/bash",
                        "/bin/sh",
                        "/usr/sbin/sshd",
                        "/usr/bin/sshd",
                        "/usr/libexec/sftp-server",
                        "/etc/apt"]
    
    fileprivate static let _breakerApps = [ // accesing other IOS applications is a sandbox violations
        URL.init(string: "cydia://package/com.example.package")!]
    
    fileprivate static let _breakerLinks = [ // accesing other IOS applications is a sandbox violations
        "/Library/Ringtones",
        "/Library/Wallpaper",
        "/usr/arm-apple-darwin9",
        "/usr/include",
        "/usr/libexec",
        "/usr/share",
        "/Applications"]
    
    public enum JailBreakError: Error{
        case simulator
        case file(path: String)
        case app(package: URL)
        case link(path: String)
        case systemDirectory
        case libraryBroken
    }
    
    /// Check if the device is jail broken
    /// - Parameters:
    ///   - allowSimulator: Whether if allowed to launch app on simulator
    ///   - files: extra file paths to check if the device is jail broken
    ///   - apps: extra app url for jail breakers
    ///   - links: extra app scheme for jail breakers
    ///   - sum: Checksum to check if the LSJailBreakChecker's check list is broken
    /// - Throws: Error for Jail Break Reason
    /// - Returns: Check sum for LSJailBreakChecker's check list
    public static func check(allowSimulator: Bool = false, files: [String] = [], apps: [URL] = [], links: [String] = [], sum: String = "") throws -> String {
        #if targetEnvironment(simulator)
        guard allowSimulator else{
            throw JailBreakError.simulator;
        }
        #endif
        
        // Check if jail breaker files
        let totalFiles = files + self._breakerFiles;
        for path in totalFiles {
            if FileManager.default.fileExists(atPath: path) {
                throw JailBreakError.file(path: path);
            }
        }
        
        // Check if jail breaker apps
        let totalApps = apps + self._breakerApps;
        for app in totalApps {
            if UIApplication.shared.canOpenURL(app) {
                throw JailBreakError.app(package: app);
            }
        }
        
        // Check if jail breaker schemes
        let totalLinks = (links + self._breakerLinks).compactMap{ URL.init(string: $0) };
        for link in totalLinks {
            if self.isSymbolicLink(link) {
                throw JailBreakError.link(path: link.path);
            }
        }
        
        // Check if device is jail breaken
        let text = "Jailbreak Available"
        let testFile = "/private/JailbreakTest.txt";
        do {
            try text.write(toFile: testFile, atomically:true, encoding:String.Encoding.utf8)
            
            throw JailBreakError.systemDirectory
        } catch {
            //reasons["Read and write acces"] = false
        }

        // Check if LSJailBreakChecker is broken
        let shadata = totalFiles + totalApps.map{ $0.absoluteString } + totalLinks.map{ $0.absoluteString } + [testFile];
        do{
            let sha = try self.sha256(shadata);
            guard !sum.isEmpty else{
                return sha;
            }
            
            guard sha == sum else{
                throw JailBreakError.libraryBroken;
            }
        }catch{
            throw JailBreakError.libraryBroken;
        }
        
        return "";
    }
    
    fileprivate static func isSymbolicLink(_ url: URL) -> Bool{
        if let reachable = try? url.checkResourceIsReachable(), reachable {
            let vals = try? url.resourceValues(forKeys: [.isSymbolicLinkKey]);
            if let islink = vals?.isSymbolicLink, islink {
//                print("it's a symbolic link")
//                let dest = url.resolvingSymlinksInPath()
//                let report = dest != url ? "It exists" : "It doesn't exist"
                return true;
            }
        }
        
        return false;
    }
    
    fileprivate static func sha256(_ strings: [String]) throws -> String{
        let strsum = strings.reduce("", +);
        let data = Data(strsum.data(using: .utf8)!);
                
        if #available(iOS 13.0, *) {
            let hashed = SHA256.hash(data: data);
            return hashed.compactMap { String(format: "%02x", $0) }.joined();
        } else {
            var digest = [UInt8](repeating: 0, count: Int(CC_SHA256_DIGEST_LENGTH));
            data.withUnsafeBytes { bytes in
                _ = CC_SHA256(bytes.baseAddress, UInt32(data.count), &digest)
            }
            return digest.makeIterator().compactMap { String(format: "%02x", $0) }.joined();
        }
    }
}
