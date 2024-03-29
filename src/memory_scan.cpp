#include "engine.h"
#include "memory_scan.h"
#include "sysinfo.h"

#pragma warning ( disable : 4996 ) // ExAllocatePoolWithTag is deprecated.

extern AntiCheat::Engine* gp_anticheat;

void MemoryScanRoutine(PVOID p_context)
{
    UNREFERENCED_PARAMETER(p_context);

    gp_anticheat->mp_scanner->Scan();
}

void AntiCheat::MemoryScanner::ScanMemoryRegions(const PSYSTEM_PROCESSES p_process_list)
{
    if (!p_process_list)
    {
        return;
    }

    // Check target process is running.
    if (mp_target_process->get_pid() == 0)
    {
        return;
    }

    // Check we can find our target process in the process list.
    const PSYSTEM_PROCESSES p_process = FindProcess(p_process_list, reinterpret_cast<ULONG_PTR>(mp_target_process->get_pid()));
    if (!p_process)
    {
        return;
    }

    CLIENT_ID client_id = { mp_target_process->get_pid(), 0 };

    OBJECT_ATTRIBUTES attributes = {};
    InitializeObjectAttributes(&attributes, nullptr, OBJ_KERNEL_HANDLE, nullptr, nullptr);

    HANDLE h_process = INVALID_HANDLE_VALUE;

    // Open a handle to our target process.
    NTSTATUS status = ZwOpenProcess(&h_process, GENERIC_ALL, &attributes, &client_id);
    if (NT_ERROR(status))
    {
        return;
    }

    ULONG_PTR base_address = 0;

    // Scan over all memory regions, printing info on only those that are executable.
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

void AntiCheat::MemoryScanner::PrintExecutableMemoryRegion(const PMEMORY_BASIC_INFORMATION p_info)
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

void AntiCheat::MemoryScanner::PrintHandlesOpenToTargetProcess(const PSYSTEM_PROCESSES p_process_list, const PSYSTEM_HANDLE_INFORMATION_EX p_handle_list)
{
    if (!p_process_list || !p_handle_list)
    {
        return;
    }

    KdPrint(("Processes with open handles to %ws:", mp_target_process->get_name()));

    for (unsigned int i = 0; i < p_handle_list->NumberOfHandles; ++i)
    {
        const SYSTEM_HANDLE_TABLE_ENTRY_INFO_EX entry = p_handle_list->Handles[i];

        // Check if the object associated with the handle entry is our target process.
        if (entry.Object != mp_target_process->get_process())
        {
            continue;
        }

        const PSYSTEM_PROCESSES p_process = FindProcess(p_process_list, entry.UniqueProcessId);
        if (p_process)
        {
            KdPrint(("Name: %wZ, Access: 0x%x", p_process->ProcessName, entry.GrantedAccess));
        }
    }
}

AntiCheat::MemoryScanner::MemoryScanner(const TargetProcess* p_target_process) :
    mp_target_process(p_target_process),
    m_thread(nullptr),
    m_timer({}),
    m_terminate_request({}),
    m_terminate_response({})
{
    KeInitializeTimerEx(&m_timer, SynchronizationTimer);
    KeInitializeEvent(&m_terminate_request, NotificationEvent, false);
    KeInitializeEvent(&m_terminate_response, NotificationEvent, false);

    const LARGE_INTEGER interval{ 0 , 0 };
    KeSetTimerEx(&m_timer, interval, scanner_interval_ms, nullptr);

    NTSTATUS status = PsCreateSystemThread(&m_thread, GENERIC_ALL, nullptr, nullptr, nullptr, MemoryScanRoutine, nullptr);
    if (NT_ERROR(status))
    {
        mp_initialization_error.code = InitializationError::create_scanner_thread;
        mp_initialization_error.status = status;
    }
}

AntiCheat::MemoryScanner::~MemoryScanner()
{
    if (m_thread)
    {
        // Signal our scanning thread to terminate.
        KeSetEvent(&m_terminate_request, 0, true);

        // Wait for scanning thread to terminate.
        KeWaitForSingleObject(&m_terminate_response, Executive, KernelMode, false, nullptr);

        // Close handle to thread.
        ZwClose(m_thread);
    }

    // Cancel the timer we were using for scheduling our scans.
    KeCancelTimer(&m_timer);
}

AntiCheat::Error AntiCheat::MemoryScanner::Initialized()
{
    return mp_initialization_error;
}

void AntiCheat::MemoryScanner::Scan()
{
    void* waitables[2] = { &m_terminate_request, &m_timer};

    while (true)
    {
        const NTSTATUS status = KeWaitForMultipleObjects(2, waitables, WaitAny, Executive, KernelMode, false, nullptr, nullptr);
        if (status == STATUS_WAIT_0)
        {
            KdPrint(("Terminating scanning thread."));
            KeSetEvent(&m_terminate_response, 0, false);
            return;
        }
        else if (status == STATUS_WAIT_1)
        {
            KdPrint(("Executing memory scan routine."));

            if (mp_target_process->get_pid() == 0)
            {
                KdPrint(("Aborting memory scan as %ws is not running.", mp_target_process->get_name()));
                continue;
            }

            const PSYSTEM_PROCESSES p_process_list = SysInfo<SYSTEM_PROCESSES>(SystemProcessInformation);

            if (p_process_list)
            {
                const PSYSTEM_HANDLE_INFORMATION_EX p_handle_list = SysInfo<SYSTEM_HANDLE_INFORMATION_EX>(SystemExtendedHandleInformation);

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

void* AntiCheat::MemoryScanner::operator new(size_t n)
{
    void* const p = ExAllocatePoolWithTag(PagedPool, n, POOL_TAG);
    return p;
}

void AntiCheat::MemoryScanner::operator delete(void* p)
{
    ExFreePoolWithTag(p, POOL_TAG);
}
