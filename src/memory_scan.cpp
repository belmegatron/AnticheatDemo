#include "memory_scan.h"
#include "globals.h"
#include "sysinfo.h"

extern GlobalState g_state;

void MemoryScanRoutine(PVOID p_context)
{
    UNREFERENCED_PARAMETER(p_context);

    // TODO: DriverUnload needs to signal this thread to terminate.

    while (true)
    {
        const NTSTATUS status = KeWaitForSingleObject(&g_state.timer, Executive, KernelMode, true, nullptr);

        if (NT_SUCCESS(status))
        {
            KdPrint(("Executing memory scan routine."));

            if (g_state.target_pid == 0)
            {
                KdPrint(("Aborting memory scan as %ws not running.", g_state.target_process_name));
                continue;
            }

            const PSYSTEM_PROCESSES p_process_list = SysInfo::ProcessList();

            if (!p_process_list)
            {
                KdPrint(("Failed to perform initial process list when executing memory scan"));
                continue;
            }

            const PSYSTEM_HANDLE_INFORMATION_EX p_handle_list = SysInfo::HandleList();

            if (p_handle_list)
            {
                for (unsigned int i = 0; i < p_handle_list->NumberOfHandles; ++i)
                {
                    const SYSTEM_HANDLE_TABLE_ENTRY_INFO_EX entry = p_handle_list->Handles[i];

                    if (entry.Object == g_state.target_process)
                    {
                        const PSYSTEM_PROCESSES p_process = SysInfo::FindProcess(p_process_list, entry.UniqueProcessId);
                        if (p_process)
                        {
                            // TODO: Perform lookup on access values maybe?
                            KdPrint(("Process: %wZ, Access: %x", p_process->ProcessName, entry.GrantedAccess));
                        }
                    }
                }

                ExFreePoolWithTag(p_handle_list, POOL_TAG);
            }

            Scanner::ScanMemoryRegions(p_process_list);

            ExFreePoolWithTag(p_process_list, POOL_TAG);
        }
    }
}

void Scanner::Setup()
{
    KeInitializeTimerEx(&g_state.timer, SynchronizationTimer);

    const LARGE_INTEGER interval{ 0 , 0 };
    KeSetTimerEx(&g_state.timer, interval, scanner_interval_ms, nullptr);

    PsCreateSystemThread(&g_state.scanner_thread, GENERIC_ALL, nullptr, nullptr, nullptr, MemoryScanRoutine, nullptr);
}

void Scanner::ScanMemoryRegions(PSYSTEM_PROCESSES p_process_list)
{
    if (!p_process_list)
    {
        return;
    }

    if (g_state.target_pid == 0)
    {
        return;
    }

    KdPrint(("Starting memory region scan"));

    const PSYSTEM_PROCESSES p_process = SysInfo::FindProcess(p_process_list, reinterpret_cast<ULONG_PTR>(g_state.target_pid));
    if (!p_process)
    {
        KdPrint(("Unable to find target process when performing memory region scan: %x", g_state.target_pid));
        return;
    }

    CLIENT_ID client_id = { g_state.target_pid, 0 };

    OBJECT_ATTRIBUTES attributes = {};
    InitializeObjectAttributes(&attributes, nullptr, OBJ_KERNEL_HANDLE, nullptr, nullptr);

    HANDLE h_process = INVALID_HANDLE_VALUE;

    NTSTATUS status = ZwOpenProcess(&h_process, GENERIC_ALL, &attributes, &client_id);
    if (!NT_SUCCESS(status))
    {
        KdPrint(("Unable to open handle to %ws: %x", g_state.target_process_name, status));
        return;
    }

    KdPrint(("Obtained handle to target process"));

    MEMORY_BASIC_INFORMATION info = {};
    ULONG_PTR base_address = 0;

    do
    {
        status = ZwQueryVirtualMemory(h_process, (PVOID)base_address, MemoryBasicInformation, &info, sizeof(info), nullptr);
        if (NT_SUCCESS(status))
        {
            PrintMemoryAllocation(&info);
        }

        base_address += info.RegionSize;
        RtlSecureZeroMemory(&info, sizeof(info));

    } while (NT_SUCCESS(status));

    ZwClose(h_process);
}

void Scanner::PrintMemoryAllocation(PMEMORY_BASIC_INFORMATION p_info)
{
    if (!p_info)
    {
        return;
    }

    PWCHAR protect = nullptr;
    PWCHAR type = nullptr;

    switch (p_info->Protect)
    {
    case PAGE_EXECUTE:
        protect = L"PAGE_EXECUTE";
        break;
    case PAGE_EXECUTE_READ:
        protect = L"PAGE_EXECUTE_READ";
        break;
    case PAGE_EXECUTE_READWRITE:
        protect = L"PAGE_EXECUTE_READWRITE";
        break;
    case PAGE_EXECUTE_WRITECOPY:
        protect = L"PAGE_EXECUTE_WRITECOPY";
        break;
    case PAGE_READONLY:
        protect = L"PAGE_READONLY";
        break;
    case PAGE_READWRITE:
    case PAGE_READWRITE | PAGE_GUARD:
        protect = L"PAGE_READWRITE";
        break;
    case PAGE_WRITECOPY:
        protect = L"PAGE_WRITECOPY";
        break;
    case PAGE_NOACCESS:
        protect = L"PAGE_NOACCESS";
        break;
    case NONE:
        protect = L"";
        break;
    default:
        protect = L"UNKNOWN";
    }

    switch (p_info->Type)
    {
    case MEM_PRIVATE:
        type = L"MEM_PRIVATE";
        break;
    case MEM_MAPPED:
        type = L"MEM_MAPPED";
        break;
    case MEM_IMAGE:
        type = L"MEM_IMAGE";
        break;
    case FREE:
        type = L"FREE";
        break;
    default:
        type = L"UNKNOWN";
    }

    KdPrint(("Base Address: 0x%Ix, Page Protection: %ws, Type: %ws", p_info->BaseAddress, protect, type));
}