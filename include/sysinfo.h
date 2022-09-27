#pragma once
#include "nt_internals.h"

namespace SysInfo
{
    PSYSTEM_PROCESSES ProcessList();
    PSYSTEM_HANDLE_INFORMATION_EX  HandleList();
    PSYSTEM_PROCESSES FindProcess(const PSYSTEM_PROCESSES process_list, ULONG_PTR pid);
}