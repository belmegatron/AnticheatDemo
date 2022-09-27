#pragma once
#include <ntddk.h>
#include "memory_scan.h"

#define POOL_TAG 'ca'


struct GlobalState
{
    // True if created symlink for driver.
    bool symlink_created;

    // True if we called PsSetCreateProcessNotifyRoutineEx successfully when setting our callback.
    bool process_notification_set;

    // This is the process we are going to protect.
    PWCHAR target_process_name;

    // PID of target process.
    HANDLE target_pid;

    // Pointer to target process.
    PEPROCESS target_process;

    // Registration handle for ObRegisterCallbacks.
    void* callback_reg_handle;

    // State associated with our memory scanning routine.
    MemoryScanner::State scanner;

    void Init()
    {
        symlink_created = false;
        process_notification_set = false;
        target_process_name = L"notepad.exe";
        target_pid = 0;
        target_process = nullptr;
        callback_reg_handle = nullptr;
        scanner.Init();
    };

};
