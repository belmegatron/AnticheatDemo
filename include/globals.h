#pragma once
#include <ntddk.h>

#define POOL_TAG 'ca'

struct GlobalState
{
    // This is the process we are going to protect.
    PWCHAR target_process_name;

    // PID of target process.
    HANDLE target_pid;

    // Pointer to target process.
    PEPROCESS target_process;

    // Registration handle for ObRegisterCallbacks.
    void* callback_reg_handle;

    // Handle to memory scanner thread.
    HANDLE scanner_thread;

    // Timer used to schedule memory scans.
    KTIMER timer;

    void Init()
    {
        target_process_name = L"notepad.exe";
        target_pid = 0;
        target_process = nullptr;
        callback_reg_handle = nullptr;
        scanner_thread = nullptr;
        timer = {};
    };

};
