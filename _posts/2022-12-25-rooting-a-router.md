---
title:  "CVE-2022-48127: Finding an Open Redirect and Some General Router Tomfoolery, rooting an ASUS Router via UART"
categories: iot
classes: wide
---

Had a ASUS RT-AC1200G+ router that was doing nothing, had been watching [Flashback team](https://www.youtube.com/@FlashbackTeam/videos) videos on youtube and was feeling a bit bored. Popped the router open and saw 4 pins in a row. "Thats UART", wondered what architecture and webserver the system was running so I poked at it one weekend.


## Detecting 3.3v, Ground, TX and RX pins.
- Ground is ground, plug the device in and use a multimeter in continuity mode. If it beeps when one probe is touching metal housing and the other is on a pin, you know you have a ground pin.
- 3.3v power pin, rinse and repeat the same as ground but the power on and your multimeter set to 0.00 DC detection.
- To detect TX, a pin which has a changing voltage needs to be found (e.g. in my case 3.2v/3.3v DC changing in patterns).

```
+         0     1     0     1     0     1     0     1     0        +
 ------+     +-----+     +-----+     +-----+     +-----+     +-----
+      |     |     |     |     |     |     |     |     |     |     +
       |     |     |     |     |     |     |     |     |     |
+ IDLE |     |     |     |     |     |     |     |     |     |     +
       |     |     |     |     |     |     |     |     |     |
+      +-----+     +-----+     +-----+     +-----+     +-----+     +
                                                         MSB  stop
                                                               bit
```
- RX will be 0v and no continuity.

Once all 4 have been found, UART likely has been identified.

TX(transmit) needs to transmit to RX(recieve) and ground needs to be grounded on both devices
```
+----------+         +----------+
|   UART   |         |   UART   |
|          |         |          |
|      TX  <--------->  RX      |
|          |         |          |
|      RX  <--------->  TX      |
|          |         |          |
|      GND <--------->  GND     |
|          |         |          |
+----------+         +----------+
```


## Setup of raspberry pi as serial (UART) console
Boredum leads to curiosity, curiosity leads to experimentation and experimentation leads to discovery. With no UART to USB dongle I remembered that the Raspberry Pi has GPIO pins. Quick gooling shows 2 pins of interest, 
    
- GPIO14 = TXD
- GPIO15 = RXD
(GPIO Pin layout[0])

Below is a basic diagram of the raspberry pi acting in place of a UART <-> USB dongle.
```
                            +----------+
                            |          |
                            | raspi    |
                            | 3B       |
                            | 4GB      |
                            |          |
                            |  6 10  8 |
                            +^-^-^--^--+
                            | | |  |
                            | | |  |
+---------------------------+-+-+--+
|                           1 2 3 4|
|    ASUS RT-AC1200G+              |
|                                  |
|    ---- UART PIN ----            |
|    1 = 3.3v power pin            |
|    2 = Ground pin                |
|    3 = TX                        |
|    4 = RX                        |
|                                  |
|    - raspberry GPIO -            |
|    pin 6  (ground) = ground      |
|    pin 8  (GPIO14) = TXD         |
|    pin 10 (GPIO15) = RXD         |
|                                  |
+----------------------------------+
Note:
============
TX <-> RXD
RX <-> TXD
ground <-> ground
```


## Nada
Upon SSHing into the rpi, using the following command had no output.
```
p4@raspberrypi:~ $ picocom -b 115200 /dev/AMA0
```
Thought that was a bit Weird as something should output even if I have the BAUD rate wrong...
The next morning I asked some people and turns out on new the newer raspberry Pis that serial needs to be enabled
```
sudo raspi-config
```
-> Interfacing options -> Serial -> No to login shell to be accessible over Serial -> Yes to Serial port hardware being enabled (Raspberry pi UART communication[1])


## Password....

Upon seeing the scrolling output from a successful UART I got excited, after about 30s of booting I was prompted with a login....
```
RT-AC1200G+ login:
```

I didn't know the password. Doing some google fu I found a russian blog reviewing this exact router.
(ASUS rt ac1200 review[2])
```
"""
Для доступа к командной строке используются та же пара логин-пароль, что и для доступа к веб-интерфейсу маршрутизатора. 
Микропрограммное обеспечение тестируемой модели построено на базе операционной системы 
Linux 2.6.36.4 с использованием BusyBox 1.17.4.
"""
```

Huh, interesting okay, at least we know its not protected with a device specific generated password or something hard to bruteforce
```
"""
To access the command line, the same login-password pair is used as for accessing the router's web interface.
The firmware of the tested model is based on the operating system
Linux 2.6.36.4 using BusyBox 1.17.4.
"""
```


## Reset -> Admin

Resetting the device and accessing the webpanel revealed that the default credentials were admin:admin...as expected...
Trying that combination on the UART granted a successful login as the admin user.

```
RT-AC1200G+ login: admin
Password:
admin@RT-AC1200G+:/tmp/home/root#
```


## Enumeration
Looking at what capabilities are available isn't too satisfying. Limited busybox 

```
admin@RT-AC1200G+:/tmp/home/root# busybox --help
BusyBox v1.17.4 (2020-06-19 13:52:12 CST) multi-call binary.
Copyright (C) 1998-2009 Erik Andersen, Rob Landley, Denys Vlasenko
and others. Licensed under GPLv2.
See source distribution for full notice.
    
Usage: busybox [function] [arguments]...
    or: function [arguments]...

        BusyBox is a multi-call binary that combines many common Unix
        utilities into a single executable.  Most people will create a
        link to busybox for each function they wish to use and BusyBox
        will act like whatever it was invoked as.

Currently defined functions:
        [, [[, arp, ash, awk, basename, blkid, cat, chmod, chown, chpasswd,
        clear, cmp, cp, crond, cut, date, dd, devmem, df, dirname, dmesg, du,
        e2fsck, echo, egrep, env, ether-wake, expr, fdisk, fgrep, find, flock,
        free, fsck, fsck.ext2, fsck.ext3, fsck.minix, fsync, grep, gunzip,
        gzip, head, ifconfig, insmod, ionice, kill, killall, klogd, less, ln,
        logger, login, ls, lsmod, lsusb, md5sum, mdev, mkdir, mke2fs,
        mkfs.ext2, mkfs.ext3, mknod, mkswap, modprobe, more, mount, mv,
        netstat, nice, nohup, nslookup, pidof, ping, ping6, printf, ps, pwd,
        readlink, renice, rm, rmdir, rmmod, route, sed, setconsole, sh, sleep,
        sort, strings, swapoff, swapon, sync, syslogd, tail, tar, telnetd,
        test, top, touch, tr, traceroute, traceroute6, true, tune2fs, udhcpc,
        umount, uname, unzip, uptime, usleep, vconfig, vi, watch, wc, which,
        zcat, zcip
```

No wget, no curl, but uname ifconfig and basic stream editing commands like tr, wc etc etc etc.
```
admin@RT-AC1200G+:/tmp/home/root# find / -name *ssh*
/sbin/run_sshd
/tmp/home/root/.ssh
/usr/bin/ssh
```

luckily scp is available, makes life nice and easy:
```
admin@RT-AC1200G+:/tmp/home/root# find / -name *scp*
/lib/modules/2.6.36.4brcmarm/kernel/net/netfilter/xt_dscp.ko
/usr/bin/scp
/usr/lib/xtables/libxt_dscp.so
```

Grabbed a full fledged busybox and dropped to disk so I can have QoL improvements
```
p4@raspberrypi:~ $ wget https://busybox.net/downloads/binaries/1.21.1/busybox-armv7l
admin@RT-AC1200G+:/tmp/home/root# scp p4@192.168.2.154:/home/p4/busybox-armv7l /tmp/busybox-armv7l
```

With the full armv7l busybox installed, the full suite can be obtained 
```
admin@RT-AC1200G+:/tmp# ./busybox-armv7l
BusyBox v1.21.1 (2013-07-08 10:26:30 CDT) multi-call binary.
BusyBox is copyrighted by many authors between 1998-2012.
Licensed under GPLv2. See source distribution for detailed
copyright notices.

Usage: busybox [function [arguments]...]
    or: busybox --list[-full]
    or: busybox --install [-s] [DIR]
    or: function [arguments]...

        BusyBox is a multi-call binary that combines many common Unix
        utilities into a single executable.  Most people will create a
        link to busybox for each function they wish to use and BusyBox
        will act like whatever it was invoked as.

Currently defined functions:
        [, [[, acpid, add-shell, addgroup, adduser, adjtimex, arp, arping, ash,
        awk, base64, basename, beep, blkid, blockdev, bootchartd, brctl,
        bunzip2, bzcat, bzip2, cal, cat, catv, chat, chattr, chgrp, chmod,
        chown, chpasswd, chpst, chroot, chrt, chvt, cksum, clear, cmp, comm,
        conspy, cp, cpio, crond, crontab, cryptpw, cttyhack, cut, date, dc, dd,
        deallocvt, delgroup, deluser, depmod, devmem, df, dhcprelay, diff,
        dirname, dmesg, dnsd, dnsdomainname, dos2unix, du, dumpkmap,
        dumpleases, echo, ed, egrep, eject, env, envdir, envuidgid, ether-wake,
        expand, expr, fakeidentd, false, fbset, fbsplash, fdflush, fdformat,
        fdisk, fgconsole, fgrep, find, findfs, flock, fold, free, freeramdisk,
        fsck, fsck.minix, fsync, ftpd, ftpget, ftpput, fuser, getopt, getty,
        grep, groups, gunzip, gzip, halt, hd, hdparm, head, hexdump, hostid,
        hostname, httpd, hush, hwclock, id, ifconfig, ifdown, ifenslave,
        ifplugd, ifup, inetd, init, insmod, install, ionice, iostat, ip,
        ipaddr, ipcalc, ipcrm, ipcs, iplink, iproute, iprule, iptunnel,
        kbd_mode, kill, killall, killall5, klogd, last, less, linux32, linux64,
        linuxrc, ln, loadfont, loadkmap, logger, login, logname, logread,
        losetup, lpd, lpq, lpr, ls, lsattr, lsmod, lsof, lspci, lsusb, lzcat,
        lzma, lzop, lzopcat, makedevs, makemime, man, md5sum, mdev, mesg,
        microcom, mkdir, mkdosfs, mke2fs, mkfifo, mkfs.ext2, mkfs.minix,
        mkfs.vfat, mknod, mkpasswd, mkswap, mktemp, modinfo, modprobe, more,
        mount, mountpoint, mpstat, mt, mv, nameif, nanddump, nandwrite,
        nbd-client, nc, netstat, nice, nmeter, nohup, nslookup, ntpd, od,
        openvt, passwd, patch, pgrep, pidof, ping, ping6, pipe_progress,
        pivot_root, pkill, pmap, popmaildir, poweroff, powertop, printenv,
        printf, ps, pscan, pstree, pwd, pwdx, raidautorun, rdate, rdev,
        readahead, readlink, readprofile, realpath, reboot, reformime,
        remove-shell, renice, reset, resize, rev, rm, rmdir, rmmod, route, rpm,
        rpm2cpio, rtcwake, run-parts, runlevel, runsv, runsvdir, rx, script,
        scriptreplay, sed, sendmail, seq, setarch, setconsole, setfont,
        setkeycodes, setlogcons, setserial, setsid, setuidgid, sh, sha1sum,
        sha256sum, sha3sum, sha512sum, showkey, slattach, sleep, smemcap,
        softlimit, sort, split, start-stop-daemon, stat, strings, stty, su,
        sulogin, sum, sv, svlogd, swapoff, swapon, switch_root, sync, sysctl,
        syslogd, tac, tail, tar, tcpsvd, tee, telnet, telnetd, test, tftp,
        tftpd, time, timeout, top, touch, tr, traceroute, traceroute6, true,
        tty, ttysize, tunctl, udhcpc, udhcpd, udpsvd, umount, uname, unexpand,
        uniq, unix2dos, unlzma, unlzop, unxz, unzip, uptime, users, usleep,
        uudecode, uuencode, vconfig, vi, vlock, volname, wall, watch, watchdog,
        wc, wget, which, who, whoami, whois, xargs, xz, xzcat, yes, zcat, zcip
```

WPS pin can be dumped with ease using nvram storage (nvram is used alot for random storage)
```
admin@RT-AC1200G+:/tmp# nvram show | grep -E "secret_code|wps_device_pin"
size: 40914 bytes (24622 left)
wps_device_pin=45441813
secret_code=45441813
```
(wootsec old asus explotation[4])
```
admin@RT-AC1200G+:/tmp# ./busybox-armv7l netstat -lptnu    
Active Internet connections (only servers)
Proto Recv-Q Send-Q Local Address           Foreign Address         State       PID/Program name
tcp        0      0 0.0.0.0:5473            0.0.0.0:*               LISTEN      354/u2ec
tcp        0      0 0.0.0.0:18017           0.0.0.0:*               LISTEN      165/wanduck
tcp        0      0 0.0.0.0:3394            0.0.0.0:*               LISTEN      354/u2ec
tcp        0      0 192.168.2.1:515         0.0.0.0:*               LISTEN      355/lpd
tcp        0      0 192.168.2.1:1990        0.0.0.0:*               LISTEN      170/wps_monitor
tcp        0      0 0.0.0.0:43655           0.0.0.0:*               LISTEN      494/miniupnpd
tcp        0      0 192.168.2.1:9100        0.0.0.0:*               LISTEN      355/lpd
tcp        0      0 127.0.0.1:80            0.0.0.0:*               LISTEN      189/httpd
tcp        0      0 192.168.2.1:80          0.0.0.0:*               LISTEN      189/httpd
tcp        0      0 127.0.0.1:53            0.0.0.0:*               LISTEN      183/dnsmasq
tcp        0      0 192.168.2.1:53          0.0.0.0:*               LISTEN      183/dnsmasq
tcp        0      0 192.168.2.1:3838        0.0.0.0:*               LISTEN      355/lpd
udp        0      0 0.0.0.0:9999            0.0.0.0:*                           190/infosvr
udp        0      0 0.0.0.0:42000           0.0.0.0:*                           168/eapd
udp        0      0 0.0.0.0:41748           0.0.0.0:*                           472/avahi-daemon: r
udp        0      0 127.0.0.1:42032         0.0.0.0:*                           180/acsd
udp        0      0 127.0.0.1:40500         0.0.0.0:*                           170/wps_monitor
udp        0      0 127.0.0.1:53            0.0.0.0:*                           183/dnsmasq
udp        0      0 192.168.2.1:53          0.0.0.0:*                           183/dnsmasq
udp        0      0 0.0.0.0:67              0.0.0.0:*                           183/dnsmasq
udp        0      0 0.0.0.0:5474            0.0.0.0:*                           354/u2ec
udp        0      0 0.0.0.0:18018           0.0.0.0:*                           165/wanduck
udp        0      0 0.0.0.0:1900            0.0.0.0:*                           494/miniupnpd
udp        0      0 0.0.0.0:1900            0.0.0.0:*                           170/wps_monitor
udp        0      0 0.0.0.0:38000           0.0.0.0:*                           168/eapd
udp        0      0 0.0.0.0:59000           0.0.0.0:*                           168/eapd
udp        0      0 0.0.0.0:37000           0.0.0.0:*                           168/eapd
udp        0      0 127.0.0.1:38032         0.0.0.0:*                           178/nas
udp        0      0 127.0.0.1:59032         0.0.0.0:*                           179/wlceventd
udp        0      0 127.0.0.1:37064         0.0.0.0:*                           170/wps_monitor
udp        0      0 192.168.2.1:50380       0.0.0.0:*                           494/miniupnpd
udp        0      0 192.168.2.1:5351        0.0.0.0:*                           494/miniupnpd
udp        0      0 0.0.0.0:5353            0.0.0.0:*                           472/avahi-daemon: r
udp        0      0 0.0.0.0:5355            0.0.0.0:*                           472/avahi-daemon: r
udp        0      0 0.0.0.0:43000           0.0.0.0:*                           168/eapd
udp        0      0 127.0.0.1:61689         0.0.0.0:*                           218/mastiff
```
(nice command i saw in a flashback team video[5])

With 25 ports listening externally, thats alot of attack surface area to cover.
- u2ec = some USB related binary
- lpd = Line Printer Daemon binary
- infosrv = some references to some AiCloud? S50aicloud
- wps_monitor = ?
- miniupnpd = https://github.com/miniupnp/miniupnp ?
- wanduck = https://github.com/RMerl/asuswrt-merlin/blob/master/release/src/router/rc/wanduck.c ? main webserver / logic binary ?

All these binaries have old Buildroots, interesting and likely vulns to be found. 
```
GCC: (GNU) 3.3.2 20031005 (Debian prerelease)
GCC: (Buildroot 2012.02) 4.5.3
```


## Dumb Open redirect CVE-2022-48127 

While reviewing the web source code i noticed a very dumb open redirect issue on password reset. 
```
D:\www>C:\TOOLING\rg.exe --hidden "nextPage"
state.js
633:location.href = 'Main_Password.asp?nextPage=' + window.location.pathname.substring(1 ,window.location.pathname.length);
Main_Password.asp
236:var nextPage = decodeURIComponent('<% get_ascii_parameter("nextPage"); %>');
238:location.href = (nextPage != "") ? nextPage : "<% rel_index_page(); %>";
```

Simply set the location.href to be the nextPage GET param content.
```js
function submitForm()
{
    if(validForm())
    {
        document.getElementById("error_status_field").style.display = "none";
        document.form.http_username.value = document.form.http_username_x.value;
        document.form.http_passwd.value = document.form.http_passwd_x.value;
        document.form.http_username_x.disabled = true;
        document.form.http_passwd_x.disabled = true;
        document.form.http_passwd_2_x.disabled = true;
        document.form.btn_modify.style.display = "none";
        document.getElementById('loadingIcon').style.display = '';
        document.form.submit();
        var nextPage = decodeURIComponent('<% get_ascii_parameter("nextPage"); %>');
        setTimeout(function()
        {
            location.href = (nextPage != "") ? nextPage : "<% rel_index_page(); %>";
        }, 3000);
    }
    else
    return;
}
```

the asp.net results in:
```js
var nextPage = decodeURIComponent('https://google.com');
location.href = (nextPage != "") ? nextPage : "<% rel_index_page(); %>";
```


Abuse via 
```
http://router.asus.com/Main_Password.asp?nextPage=https://google.com
```

Prompts a logged in user to change password and then upon password change redirects a user to an arbitrary site 


## Misc notes
enabling ssh 
```
dropbear -p 192.168.2.1:22 -a
```

```
admin@RT-AC1200G+:/tmp# ps
PID USER       VSZ STAT COMMAND
174 admin     1292 S    protect_srv
175 admin     1292 S    protect_srv
```

```
admin@RT-AC1200G+:/tmp# find / -name protect_srv
/usr/sbin/protect_srv
```

```
scp /usr/sbin/protect_srv p4@192.168.2.154:/home/p4/protect_srv
```

```
admin@RT-AC1200G+:/tmp# ./busybox-armv7l strings /usr/sbin/protect_srv
/lib/ld-uClibc.so.0
libnvram.so
strcpy
perror
read
fopen
nvram_get
fclose
fwrite
strlen
free
libshared.so
wan_primary_ifunit
snprintf
getpid
nvram_get_int
memcpy
system
sleep
sysinfo
socket
calloc
fprintf
bind
strlcpy
strncpy
unlink
sscanf
memset
strcmp
exit
libptcsrv.so
Debug2Console
GetDebugValue
isFileExist
libpthread.so.0
pthread_attr_destroy
pthread_create
pthread_attr_init
accept
__deregister_frame_info
pthread_attr_setstacksize
sigaction
_fini
_Jv_RegisterClasses
pthread_attr_setdetachstate
__register_frame_info
libgcc_s.so.1
abort
libc.so.0
listen
__uClibc_main
_edata
__bss_start
__bss_start__
__bss_end__
__end__
_end
_load_record_info
_dump_record_to_file
dump_all_record
handlesignal
_add_record
add_lock_rule
add_lockall_rule
del_lock_rule
del_lockall_rule
receive_s
IsLanSide
start_local_socket
main
/tmp/protect_srv_wan_ssh.log
/tmp/protect_srv_lan_ssh.log
/tmp/protect_srv_lan_telnet.log
local_socket_thread
/tmp/PTCSRV_DEBUG
[ProtectionSrv][%s:(%d)]Service not support at WAN
[ProtectionSrv][%s:(%d)]Service not support at LAN
[ProtectionSrv][%s:(%d)]Not support
        address     retry  since_last_try   block_time   block_status
%15s%10u%16ld%13d%15d
[ProtectionSrv][%s:(%d)]BUG !! wrong iptables rule count, %d != %d
[ProtectionSrv][%s:(%d)]BUG !! wrong record count, %d != %d
[ProtectionSrv][%s:(%d)]
WAN SSH list count: %d
iptables rule count: %d
iptables rule peak: %d
Please refer to %s
--------------------------
LAN SSH list count: %d
iptables rule count: %d
iptables rule peak: %d
Please refer to %s
--------------------------
LAN TELNET list count: %d
iptables rule count: %d
iptables rule peak: %d
Please refer to %s
[ProtectionSrv][%s:(%d)]Unknown SIGNAL
%u.%u.%u.%u
TELNET
logger -t %s [%s] login succeeded from %s after %d attempts
PTCSRV
[ProtectionSrv][%s:(%d)]FULL. Ignore this case: %s
wans_mode
wan%d_
0.0.0.0
lan_ipaddr
lan_netmask
sshd_port
%s%s
iptables -A %s -p tcp --dport %d -s %s -j DROP
[ProtectionSrv][%s:(%d)]Add %s rules of %s into %s chain.
iptables -I %s -p tcp --dport %d -j DROP
[ProtectionSrv][%s:(%d)]Insert locking %s rule into %s chain.
iptables -D %s -p tcp --dport %d -s %s -j DROP
[ProtectionSrv][%s:(%d)]Remove locking %s rule of %s from %s chain.
iptables -D %s -p tcp --dport %d -j DROP
[ProtectionSrv][%s:(%d)]Remove locking %s rule from %s chain.
[ProtectionSrv][%s:(%d)]ERROR reading from socket.
[ProtectionSrv][%s:(%d)][receive report] addr:[%s] s_type:[%d] status:[%d] msg:[%s]
echo "[ProtectionSrv][receive report] addr:[%s] s_type:[%d] status:[%d] msg:[%s]" >> %s
/tmp/protect_srv.log
[ProtectionSrv][%s:(%d)]From LAN side.
[ProtectionSrv][%s:(%d)]From WAN side.
write
[ProtectionSrv][%s:(%d)]Unknown message.
[ProtectionSrv][%s:(%d)]socket error
socket error
/var/run/protect_srv_socket
[ProtectionSrv][%s:(%d)]socket bind error
socket bind error
[ProtectionSrv][%s:(%d)]listen error
listen error
[ProtectionSrv][%s:(%d)]accept error
accept error
[ProtectionSrv][%s:(%d)][Start ProtectionSrv]
echo %d > %s
/var/run/protect_srv.pid
[ProtectionSrv][%s:(%d)]Start local socket thread.
[ProtectionSrv][%s:(%d)]ProtectionSrv Terminated
GCC: (GNU) 3.3.2 20031005 (Debian prerelease)
GCC: (Buildroot 2012.02) 4.5.3
[...SNIP...]
```
Part 2, enumeration, exfil and analysis....


## References / Resources
- [0] https://cdn.sparkfun.com/assets/learn_tutorials/1/5/9/5/GPIO.png
- [1] https://www.electronicwings.com/raspberry-pi/raspberry-pi-uart-communication-using-python-and-c
- [2] https://www.foxnetwork.ru/index.php/36-reviews/reviews/221-asus-rt-ac1200g 
- [3] https://asciiflow.com/#/
- [4] https://w00tsec.blogspot.com/2014/07/hacking-asus-rt-ac66u-and-preparing-for.html
- [5] https://youtu.be/vsg9YgvGBec?t=422