#pragma once
#include "common.h"
#include "nt_internals.h"

void OnProcessNotify(PEPROCESS p_process, HANDLE process_id, PPS_CREATE_NOTIFY_INFO p_create_info);
OB_PREOP_CALLBACK_STATUS OnPreOpenProcess(PVOID, POB_PRE_OPERATION_INFORMATION p_info);

namespace ProcessMonitor
{
    constexpr int PROCESS_VM_READ = 0x0010;
    constexpr int PROCESS_VM_WRITE = 0x0020;

    class Monitor
    {
    private:

        // Contains details on the target process that we are protecting.
        TargetProcess* mp_target_process;

        // True was called successfully PsSetCreateProcessNotifyRoutineEx successfully when setting our callback.
        bool m_notification_set;

        // Registration handle for ObRegisterCallbacks.
        void* mp_callback_reg_handle;

        void RemoveRWMemoryAccess(POB_PRE_OPERATION_INFORMATION p_info);
        bool ProcessEntryMatchesNameAndPID(const PSYSTEM_PROCESSES p_entry, const wchar_t* name, const HANDLE pid);

    public:
        Monitor(TargetProcess* p_target_process);
        virtual ~Monitor();

        void* operator new(size_t n);
        void operator delete(void* p);

        void OnPreOpenProcess(POB_PRE_OPERATION_INFORMATION p_info);
        void OnProcessNotify(PEPROCESS p_process, HANDLE process_id, PPS_CREATE_NOTIFY_INFO p_create_info);
    };
}