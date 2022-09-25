#include "memory_scan.h"
#include "globals.h"
#include "sysinfo.h"

extern GlobalState g_state;

void MemoryScanRoutine(PVOID context)
{
    UNREFERENCED_PARAMETER(context);

    // TODO: DriverUnload needs to signal this thread to terminate.

    while (true)
    {
        NTSTATUS status = KeWaitForSingleObject(&g_state.timer, Executive, KernelMode, true, nullptr);

        if (NT_SUCCESS(status))
        {
            KdPrint(("Executing memory scan routine."));

            if (g_state.pid == 0)
            {
                KdPrint(("Aborting memory scan as notepad.exe not running."));
                continue;
            }

            PSYSTEM_PROCESSES process_list = SysInfo::ProcessList();

            if (!process_list)
            {
                KdPrint(("Failed to perform initial process list when executing memory scan"));
                continue;
            }

            PSYSTEM_HANDLE_INFORMATION_EX handle_information = SysInfo::HandleList();

            if (handle_information)
            {
                for (unsigned int i = 0; i < handle_information->NumberOfHandles; ++i)
                {
                    SYSTEM_HANDLE_TABLE_ENTRY_INFO_EX entry = handle_information->Handles[i];

                    if (g_state.process == entry.Object)
                    {
                        PSYSTEM_PROCESSES p_process = SysInfo::FindProcess(process_list, entry.UniqueProcessId);
                        if (p_process)
                        {
                            // TODO: Perform lookup on access values maybe?
                            KdPrint(("Process: %wZ, Access: %x", p_process->ProcessName, entry.GrantedAccess));
                        }
                    }
                }

                ExFreePoolWithTag(handle_information, POOL_TAG);
            }

            Scanner::ScanMemoryRegions(process_list);

            ExFreePoolWithTag(process_list, POOL_TAG);
        }
    }
}

void Scanner::Setup()
{
    KeInitializeTimerEx(&g_state.timer, SynchronizationTimer);
    LARGE_INTEGER interval{ 10000 , 0 };
    KeSetTimerEx(&g_state.timer, interval, 30000, nullptr);
    PsCreateSystemThread(&g_state.thread, GENERIC_ALL, nullptr, nullptr, nullptr, MemoryScanRoutine, nullptr);
}

void Scanner::ScanMemoryRegions(PSYSTEM_PROCESSES process_list)
{
    KdPrint(("Starting memory region scan"));

    if (g_state.pid == 0)
    {
        return;
    }

    PSYSTEM_PROCESSES process = SysInfo::FindProcess(process_list, reinterpret_cast<ULONG_PTR>(g_state.pid));
    if (!process)
    {
        KdPrint(("Unable to find target process when performing memory region scan: %x", g_state.pid));
        return;
    }

    CLIENT_ID client_id = { g_state.pid, 0 };

    HANDLE process_handle;
    OBJECT_ATTRIBUTES attributes;
    InitializeObjectAttributes(&attributes, nullptr, OBJ_KERNEL_HANDLE, nullptr, nullptr);

    NTSTATUS status = ZwOpenProcess(&process_handle, GENERIC_ALL, &attributes, &client_id);
    if (!NT_SUCCESS(status))
    {
        KdPrint(("Unable to open handle to notepad.exe: %x", status));
        return;
    }

    KdPrint(("Obtained handle to target process"));

    MEMORY_BASIC_INFORMATION info = {};
    ULONG_PTR base_address = 0;

    SIZE_T ReturnLength = 0;

    do
    {
        status = ZwQueryVirtualMemory(process_handle, (PVOID)base_address, MemoryBasicInformation, &info, sizeof(info), &ReturnLength);
        if (NT_SUCCESS(status))
        {
            PrintMemoryAllocation(&info);
        }

        base_address += info.RegionSize;
        RtlSecureZeroMemory(&info, sizeof(info));

    } while (NT_SUCCESS(status));

}

void Scanner::PrintMemoryAllocation(PMEMORY_BASIC_INFORMATION p_info)
{
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
#pragma warning ( push )
#pragma warning ( disable : 6273 )
    KdPrint(("Base Address: 0x%Ix, Page Protection: %ws, Type: %ws", p_info->BaseAddress, protect, type));
#pragma warning ( pop )
}