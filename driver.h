#pragma once
#include <ntddk.h>

typedef struct _SYSTEM_THREADS {
    LARGE_INTEGER  KernelTime;
    LARGE_INTEGER  UserTime;
    LARGE_INTEGER  CreateTime;
    ULONG          WaitTime;
    PVOID          StartAddress;
    CLIENT_ID      ClientId;
    KPRIORITY      Priority;
    KPRIORITY      BasePriority;
    ULONG          ContextSwitchCount;
    LONG           State;
    LONG           WaitReason;
} SYSTEM_THREADS, * PSYSTEM_THREADS;

typedef struct _SYSTEM_PROCESSES {
    ULONG            NextEntryDelta;
    ULONG            ThreadCount;
    ULONG            Reserved1[6];
    LARGE_INTEGER    CreateTime;
    LARGE_INTEGER    UserTime;
    LARGE_INTEGER    KernelTime;
    UNICODE_STRING   ProcessName;
    KPRIORITY        BasePriority;
    SIZE_T           ProcessId;
    SIZE_T           InheritedFromProcessId;
    ULONG            HandleCount;
    ULONG            Reserved2[2];
    VM_COUNTERS      VmCounters;
    IO_COUNTERS      IoCounters;
    SYSTEM_THREADS   Threads[1];
} SYSTEM_PROCESSES, * PSYSTEM_PROCESSES;

typedef enum _SYSTEM_INFORMATION_CLASS {
    SystemBasicInformation = 0,
    SystemPerformanceInformation = 2,
    SystemTimeOfDayInformation = 3,
    SystemProcessInformation = 5,
    SystemProcessorPerformanceInformation = 8,
    SystemInterruptInformation = 23,
    SystemExceptionInformation = 33,
    SystemRegistryQuotaInformation = 37,
    SystemLookasideInformation = 45,
    SystemCodeIntegrityInformation = 103,
    SystemPolicyInformation = 134,
} SYSTEM_INFORMATION_CLASS;

extern "C"
NTSTATUS
ZwQuerySystemInformation(
    SYSTEM_INFORMATION_CLASS SystemInformationClass,
    PVOID SystemInformation,
    ULONG SystemInformationLength,
    ULONG * ReturnLength);

struct GlobalState
{
    HANDLE pid;
    PEPROCESS process;
    void* reg_handle;

    void Init();
};