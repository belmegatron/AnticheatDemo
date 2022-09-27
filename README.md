
# Brief
This task is to write a Windows kernel driver that meets the requirements outlined below.
The driver should be implemented in C/C++ as that is the primary language our Anti Cheat
software uses.
Your driver should:

1) Create a process notification routine to detect when a process with the name of your
choice is started and stopped.
It should also maintain the information about that process while it is running, which
will be needed later.

2) Create a process handle callback to prevent other processes from being able to
obtain a handle to read/write memory of the process you previously detected
You might need to ignore a few specific system processes for the process to start
properly.

3) Create a thread to scan with an interval of your choice for any handles that are
opened to your previously protected process, and print a log message containing:

    * The name of the process that opened the handle.
    * The access of the handle.

4) In your thread, you will add a second scan. It will print a log message with the base
address, page protection and type of each executable memory region located in your
previously protected process.

# Notes

1) For the purpose of this demo, we are protecting `notepad.exe`. Make sure you are running `Dbgview.exe` from the `SysInternals` suite as this will allow you to see output from the driver. Once the driver has been started, you can launch `notepad.exe`. You should see a notification in `DbgView` when the process has been started/stopped. If you attempt to launch it a second time, the driver will deny you access. The rationale for this is that it's unlikely someone would ever need to concurrently run 2 copies of the same game.

2) Attempting to open a handle to `notepad.exe` will return a handle with the RW Memory permissions revoked. There are two executables which are exempt from the above, they are `csrss.exe` and `explorer.exe`. This is in order to ensure that process functions correctly.

3) A memory scan is scheduled to run every 30 seconds, this will print the name of the process that has an open handle to `notepad.exe` and a hex representation of the access mask.

4) As part of the above memory scan, we also enumerate all executable memory regions in `notepad.exe` and log them out via `KdPrint`.

# Setup

## Build

Open the `.sln` file up in Visual Studio 2022 and build (there's a single build configuration configuration for `Debug/x64`).

Binaries are output to `AntiCheatExercise\x64\Debug`.

## Install
```
# From an elevated command prompt.

# Install driver as a service.
sc create anticheat type= kernel binPath = <path to anticheat.sys>

# If it's not already enabled, enable test signing to allow you to load unsigned drivers.
# You will need to restart after.
bcdedit /set testsigning on

```

## Enable Debug Prints

Add a registry key under `HKLM\SYSTEM\CurrentControlSet\Control\Session Manager` (The key typically does not exist). Within this new key, add a `DWORD` value named `DEFAULT` (not the default value that exists in any key) and set its value to `8`. 

Credit to `Windows Kernel Programming` by `Pavel Yosifovich` for the above tip!

Make sure you run DbgView in an elevated session and ensure Kernel capture is enabled.

# Run

```
sc start anticheat
sc stop anticheat
```
