---
title:  "Visual Studio-less WDM Windows Kernel Driver Programming: cmake and FindWDK"
layout: post
categories: Windows
---

Visual Studio can be bloat, cmake and FindWDK allows for easy WDM driver compilation on the commandline



## Setup initial project directory
```bat
mkdir example_driver_root & cd example_driver_root & git clone https://github.com/SergiusTheBest/FindWDK.git & mkdir example_driver
```


### example_driver_root\CMakeLists.txt
```c
cmake_minimum_required(VERSION 3.15)
project(example_driver_demo)
set_property(GLOBAL PROPERTY USER_FOLDERS ON)
set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} /W4 /WX")
set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} /W4 /WX")
list(APPEND CMAKE_MODULE_PATH "${CMAKE_CURRENT_LIST_DIR}/../FindWDK/cmake")
find_package(WDK REQUIRED)
add_subdirectory(example_driver)
```

example_driver_root\example_driver\example_driver.c
```c
#include <wdm.h>

DRIVER_UNLOAD driverUnload;
VOID driverUnload(_In_ PDRIVER_OBJECT driverObject){
    UNREFERENCED_PARAMETER(driverObject);
    DbgPrint("[INFO] Driver unloaded\n");
}
                        
DRIVER_INITIALIZE DriverEntry;
NTSTATUS DriverEntry(_In_ PDRIVER_OBJECT driverObject, _In_ PUNICODE_STRING registryPath){
    UNREFERENCED_PARAMETER(registryPath);
    DbgPrint("[INFO] Driver loaded\n");
    static const UNICODE_STRING str = RTL_CONSTANT_STRING(L"[INFO]");
    DbgPrint("%wZ hello from KMDF with a passed UNICODE_STRING\n", str);
    driverObject->DriverUnload = driverUnload;
    return STATUS_SUCCESS;
}
```


### example_driver_root\example_driver\CMakeLists.txt
```c
cmake_minimum_required(VERSION 3.15)
    wdk_add_driver(example_driver
    example_driver.c
)
```

Directory structure should be as follows:
```
Z:\DRV-RESEARCH\example_driver_root>tree /A /F
Folder PATH listing for volume WD_Blue
Volume serial number is A1D4-1337
Z:.
|   CMakeLists.txt
|
+---example_driver
|       CMakeLists.txt
|       example_driver.c
|
\---FindWDK
    |   LICENSE
    |   README.md
    |
    \---cmake
        FindWdk.cmake
```


### launch_vis.bat
```bat
%comspec% /k "C:\Program Files (x86)\Microsoft Visual Studio\2019\Community\VC\Auxiliary\Build\vcvars64.bat"
```


### build.bat
```bat
@echo off
if exist build\ (
    echo "[INFO] build directory exists, using existing build directory"
    cd build\
) else (
    echo "[INFO] build directory doesn't exist, making new build directory"
    mkdir build\
    cd build
)
cmake -G Ninja ..
cmake --build . --config Debug
cd ..\
@echo on
```

Build output should be as follows
```
Z:\DRV-RESEARCH\example_driver_root>build.bat
"[INFO] build directory doesn't exist, making new build directory"
-- The C compiler identification is MSVC 19.29.30145.0
-- The CXX compiler identification is MSVC 19.29.30145.0
-- Detecting C compiler ABI info
-- Detecting C compiler ABI info - done
-- Check for working C compiler: C:/Program Files (x86)/Microsoft Visual Studio/2019/Community/VC/Tools/MSVC/14.29.30133/bin/Hostx64/x64/cl.exe - skipped
-- Detecting C compile features
-- Detecting C compile features - done
-- Detecting CXX compiler ABI info
-- Detecting CXX compiler ABI info - done
-- Check for working CXX compiler: C:/Program Files (x86)/Microsoft Visual Studio/2019/Community/VC/Tools/MSVC/14.29.30133/bin/Hostx64/x64/cl.exe - skipped
-- Detecting CXX compile features
-- Detecting CXX compile features - done
-- Found WDK: C:/Program Files (x86)/Windows Kits/10/Include/10.0.19041.0/km/ntddk.h
-- WDK_ROOT: C:/Program Files (x86)/Windows Kits/10
-- WDK_VERSION: 10.0.19041.0
-- Configuring done
-- Generating done
-- Build files have been written to: Z:/DRV-RESEARCH/example_driver_root/build
[6/6] Linking C executable example_va_to_pa\example_va_to_pa.sys
```


## Resources to read

- [FindWDK](https://github.com/SergiusTheBest/FindWDK)
- [manurautela cmake FindWDK guide/reference](https://manurautela.github.io/driver,/wdk,/cmake,/build,/windows/building-windows-driver-with-cmake-and-wdk-cmdline/)
- [wdksetup.exe](https://go.microsoft.com/fwlink/?linkid=2128854)
- [cmkr cmake.toml WDM example](https://github.com/build-cpp/cmkr/blob/bcbc9d2b20827322b4248772156f347356e62514/tests/driver/cmake.toml)

GitHub Twitter
