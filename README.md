# ANTI CHEAT CHALLENGE
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
a. The name of the process that opened the handle
b. The access of the handle
4) In your thread, you will add a second scan. It will print a log message with the base
address, page protection and type of each executable memory region located in your
previously protected process.