//
//  LSJailBreakChecker.swift
//  LSJailBreakChecker
//
//  Created by 영준 이 on 2020/10/13.
//

import UIKit

public class LSJailBreakChecker{
    static let _breakerFiles = [
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
    
    static let _breakerApps = [ // accesing other IOS applications is a sandbox violations
        URL.init(string: "cydia://package/com.example.package")!]
    
    static let _breakerLinks = [ // accesing other IOS applications is a sandbox violations
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
    }
    
    public static func check(allowSimulator: Bool = false, files: [String] = [], apps: [URL] = [], links: [String] = []) throws {
        #if targetEnvironment(simulator)
        guard allowSimulator else{
            throw JailBreakError.simulator;
            return;
        }
        #endif
        
        // Check 1 : existence of files that are common for jailbroken devices
        let files = files + self._breakerFiles;
        for path in files {
            if FileManager.default.fileExists(atPath: path) {
                throw JailBreakError.file(path: path);
            }
        }
        
        // Check 2: existence of applications that are common for jailbroken devices (if they are accesable then there is a sandbox violation wich means the device is jailbroken)
        let apps = apps + self._breakerApps;
        for app in apps {
            if UIApplication.shared.canOpenURL(app) {
                throw JailBreakError.app(package: app);
            }
        }
        
        // Check 2: existence of applications that are common for jailbroken devices (if they are accesable then there is a sandbox violation wich means the device is jailbroken)
        let links = (links + self._breakerLinks).compactMap{ URL.init(string: $0) };
        for link in links {
            if self.isSymbolicLink(link) {
                throw JailBreakError.link(path: link.path);
            }
        }
        
        // Check 3 : Reading and writing in system directories (sandbox violation)
        let text = "Jailbreak Available"
        do {
            try text.write(toFile:"/private/JailbreakTest.txt", atomically:true, encoding:String.Encoding.utf8)
            
            throw JailBreakError.systemDirectory
        } catch {
            //reasons["Read and write acces"] = false
        }
//
//        return reasons
    }
    
    static func isSymbolicLink(_ url: URL) -> Bool{
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
}
