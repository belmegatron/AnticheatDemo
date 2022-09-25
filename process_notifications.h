#pragma once
#include "nt_internals.h"

void OnProcessNotify(PEPROCESS process, HANDLE process_id, PPS_CREATE_NOTIFY_INFO create_info);
OB_PREOP_CALLBACK_STATUS OnPreOpenProcess(PVOID, POB_PRE_OPERATION_INFORMATION info);

namespace Notifications
{
    constexpr int PROCESS_VM_READ = 0x0010;
    constexpr int PROCESS_VM_WRITE = 0x0020;

    NTSTATUS Setup();

    void RemoveRWMemoryAccess(POB_PRE_OPERATION_INFORMATION p_info);
    void OnPreOpenProcess(POB_PRE_OPERATION_INFORMATION p_info);
}