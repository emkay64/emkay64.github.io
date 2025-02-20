---
title:  "NO-CVE wontfix: Windows Zscaler Client Connector 4.2.0.190 Log Export Denial of Service"
categories: Windows
classes: wide
---

A directory junction could be created in place of a directory which the Zscaler Client Connector uses as part of the log file export process. This directory was under the control of a low-privileged user, effectively preventing a user from exporting logs from ZCC. This may hinder a ZCC user's ability to triage and investigate logs if required. 


## Overview

The ZCC made use of two directories for log file operations:
- `%PROGRAMDATA%\Zscaler`  - High privileged, protected log and configuration file directory.
- `%LOCALAPPDATA%\Zscaler` - Low privileged, non sensitive and unprotected log file directory. 

The `C:\ProgramData\Zscaler` directory was protected from modification by a low privileged user as shown below by the discretionary access control lists (DACLs) applied:
```
C:\>icacls C:\ProgramData\Zscaler
Zscaler NT AUTHORITY\SYSTEM:(OI)(CI)(F)
        BUILTIN\Administrators:(OI)(CI)(F)

Successfully processed 1 files; Failed processing 0 files
```

However, the `C:\Users\zscaler_live\AppData\Local\Zscaler` directory was under the full control of a low privileged user. This was denoted by the `F` parameter/value in the below DACLs:
```
C:\>icacls C:\Users\zscaler_live\AppData\Local\Zscaler
C:\Users\zscaler_live\AppData\Local\Zscaler NT AUTHORITY\SYSTEM:(I)(OI)(CI)(F)
                                            BUILTIN\Administrators:(I)(OI)(CI)(F)
                                            DESKTOP-1R17VVV\zscaler_live:(I)(OI)(CI)(F)

Successfully processed 1 files; Failed processing 0 files
```

If a low privileged user were to replace the `%LOCALAPPDATA%\Zscaler` directory with a directory junction which points to a non-existent directory then the ZCC would be unable to export the application logs. However, ZCC would still function as expected as it would be able to connect to configured resources. This could be achieved by creating a directory junction either before start-up of the application or prior to shutdown of the application.

This can be replicated by using the `mklink` built-in command with the `/J` command-line switch: 
```batch
mklink /J C:\Users\zscaler_live\AppData\Local\Zscaler C:\Zscaler
```


## Remedial Action
Zscaler can further harden their NTFS directory creation/deletion/modification implementation by ensuring that directories which are required for the ZCC's operations posses the intended New Technology File System (NTFS) attributes and not otherwise.

Junction points can be programatically identified by querying the attributes of the target for the following attributes:
- `FILE_ATTRIBUTE_REPARSE_POINT`, `FILE_ATTRIBUTE_HIDDEN`, and `FILE_ATTRIBUTE_SYSTEM` file attributes set.
- They also have their access control lists (ACLs) set to deny read access to everyone.

The `FILE_ATTRIBUTE_REPARSE_POINT` attribute can be queried by using the `GetFileAttributesW` windows API function from `Kernel32.dll`:

```c
DWORD fileAttributes = GetFileAttributesW(L"C:\Users\zscaler\_live\AppData\Local\Zscaler");

if (fileAttributes == INVALID_FILE_ATTRIBUTES) {
    // exit or handle failure GetLastError()
} 

if (fileAttributes & FILE_ATTRIBUTE_REPARSE_POINT) {
    // directory is a reparse point, handle accordingly
}
```

It is important to note that NTFS symbolic links are the source for a large number of logic bugs where arbitrary file overwrite / arbitrary file delete and local privilege escalation scenarios can arise.

## Further Information
- [Microsoft Learn -- mklink](https://learn.microsoft.com/en-us/windows-server/administration/windows-commands/mklink)
- [Microsoft Learn -- Junction Points](https://learn.microsoft.com/en-gb/windows/win32/vss/junction-points)
- [Microsoft Learn -- Reparse Points](https://learn.microsoft.com/en-gb/windows/win32/fileio/reparse-points)
- [Microsoft Learn -- Reparse Point Tags](https://learn.microsoft.com/en-us/windows/win32/fileio/reparse-point-tags)
- [Microsoft Learn -- File Attribute Constants](https://learn.microsoft.com/en-us/windows/win32/fileio/file-attribute-constants)