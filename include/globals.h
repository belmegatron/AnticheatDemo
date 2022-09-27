#pragma once
#include <ntddk.h>

#define POOL_TAG 'ca'

struct ScannerState
{
    // Handle to memory scanner thread.
    HANDLE thread;

    // Timer used to schedule memory scans.
    KTIMER timer;

    bool timer_set;

    void Init()
    {
        thread = nullptr;
        timer = {};
        timer_set = false;
    }
};

struct GlobalState
{
    bool symlink_created;

    bool process_notification_set;

    // This is the process we are going to protect.
    PWCHAR target_process_name;

    // PID of target process.
    HANDLE target_pid;

    // Pointer to target process.
    PEPROCESS target_process;

    // Registration handle for ObRegisterCallbacks.
    void* callback_reg_handle;

    ScannerState scanner;

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
