#include "memory_scan.h"
#include "globals.h"
#include "sysinfo.h"


extern GlobalState g_state;

void MemoryScanRoutine(PVOID p_context)
{
    UNREFERENCED_PARAMETER(p_context);

    // TODO: DriverUnload needs to signal this thread to terminate.
    g_state.p_scanner->Scan();
}

void MemoryScanner::Scanner::ScanMemoryRegions(const PSYSTEM_PROCESSES p_process_list)
{
    if (!p_process_list)
    {
        return;
    }

    if (g_state.target_pid == 0)
    {
        return;
    }

    const PSYSTEM_PROCESSES p_process = SysInfo::FindProcess(p_process_list, reinterpret_cast<ULONG_PTR>(g_state.target_pid));
    if (!p_process)
    {
        return;
    }

    CLIENT_ID client_id = { g_state.target_pid, 0 };

    OBJECT_ATTRIBUTES attributes = {};
    InitializeObjectAttributes(&attributes, nullptr, OBJ_KERNEL_HANDLE, nullptr, nullptr);

    HANDLE h_process = INVALID_HANDLE_VALUE;

    NTSTATUS status = ZwOpenProcess(&h_process, GENERIC_ALL, &attributes, &client_id);
    if (!NT_SUCCESS(status))
    {
        return;
    }

    ULONG_PTR base_address = 0;

    do
    {
        MEMORY_BASIC_INFORMATION info = {};

        status = ZwQueryVirtualMemory(h_process, reinterpret_cast<void*>(base_address), MemoryBasicInformation, &info, sizeof(info), nullptr);
        if (NT_SUCCESS(status))
        {
            PrintExecutableMemoryRegion(&info);
        }

        base_address += info.RegionSize;

    } while (NT_SUCCESS(status));

    ZwClose(h_process);
}

void MemoryScanner::Scanner::PrintExecutableMemoryRegion(const PMEMORY_BASIC_INFORMATION p_info)
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
    }

    if (protect && type)
    {
        KdPrint(("Base Address: 0x%Ix, Page Protection: %ws, Type: %ws", p_info->BaseAddress, protect, type));
    }
}

void MemoryScanner::Scanner::PrintHandlesOpenToTargetProcess(const PSYSTEM_PROCESSES p_process_list, const PSYSTEM_HANDLE_INFORMATION_EX p_handle_list)
{
    if (!p_process_list || !p_handle_list)
    {
        return;
    }

    KdPrint(("Processes with open handles to %ws:", g_state.target_process_name));

    for (unsigned int i = 0; i < p_handle_list->NumberOfHandles; ++i)
    {
        const SYSTEM_HANDLE_TABLE_ENTRY_INFO_EX entry = p_handle_list->Handles[i];

        if (entry.Object == g_state.target_process)
        {
            const PSYSTEM_PROCESSES p_process = SysInfo::FindProcess(p_process_list, entry.UniqueProcessId);
            if (p_process)
            {
                KdPrint(("Name: %wZ, Access: 0x%x", p_process->ProcessName, entry.GrantedAccess));
            }
        }
    }
}

MemoryScanner::Scanner::Scanner()
{
    KdPrint(("Scanner constructor called"));

    KeInitializeTimerEx(&m_timer, SynchronizationTimer);

    const LARGE_INTEGER interval{ 0 , 0 };
    KeSetTimerEx(&m_timer, interval, scanner_interval_ms, nullptr);

    PsCreateSystemThread(&m_thread, GENERIC_ALL, nullptr, nullptr, nullptr, MemoryScanRoutine, nullptr);
}

MemoryScanner::Scanner::~Scanner()
{
    KdPrint(("Scanner destructor called"));
    KeCancelTimer(&m_timer);
}

void MemoryScanner::Scanner::Scan()
{
    while (true)
    {
        const NTSTATUS status = KeWaitForSingleObject(&m_timer, Executive, KernelMode, true, nullptr);

        if (NT_SUCCESS(status))
        {
            KdPrint(("Executing memory scan routine."));

            if (g_state.target_pid == 0)
            {
                KdPrint(("Aborting memory scan as %ws is not running.", g_state.target_process_name));
                continue;
            }

            PSYSTEM_PROCESSES p_process_list = SysInfo::ProcessList();

            if (p_process_list)
            {
                PSYSTEM_HANDLE_INFORMATION_EX p_handle_list = SysInfo::HandleList();

                if (p_handle_list)
                {
                    PrintHandlesOpenToTargetProcess(p_process_list, p_handle_list);

                    ExFreePoolWithTag(p_handle_list, POOL_TAG);
                }

                ScanMemoryRegions(p_process_list);

                ExFreePoolWithTag(p_process_list, POOL_TAG);
            }
        }
    }
}
