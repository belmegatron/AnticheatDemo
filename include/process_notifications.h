#pragma once
#include "nt_internals.h"

void OnProcessNotify(PEPROCESS p_process, HANDLE process_id, PPS_CREATE_NOTIFY_INFO p_create_info);
OB_PREOP_CALLBACK_STATUS OnPreOpenProcess(PVOID, POB_PRE_OPERATION_INFORMATION p_info);

namespace ProcessNotifications
{
    constexpr int PROCESS_VM_READ = 0x0010;
    constexpr int PROCESS_VM_WRITE = 0x0020;

    bool Setup();

    void RemoveRWMemoryAccess(POB_PRE_OPERATION_INFORMATION p_info);
    void OnPreOpenProcess(POB_PRE_OPERATION_INFORMATION p_info);
    bool ProcessEntryMatchesNameAndPID(const PSYSTEM_PROCESSES p_entry, const wchar_t* name, const HANDLE pid);
}