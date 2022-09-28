#pragma once
#include <ntddk.h>

#define POOL_TAG 'ca'

namespace AntiCheat
{
    enum class InitializationError
    {
        success,
        unknown,
        set_notify_routine,
        register_callbacks,
        create_scanner_thread
    };

    struct Error
    {
        InitializationError code;
        NTSTATUS status;

        Error() : code(InitializationError::success), status(STATUS_SUCCESS) {}
    };

    class TargetProcess
    {
    private:
        // Name of the target process.
        PWCHAR m_name;

        // PID of target process.
        HANDLE m_pid;

        // Pointer to target process.
        PEPROCESS mp_process;

    public:
        TargetProcess();
        virtual ~TargetProcess() = default;

        void* operator new(size_t n);
        void operator delete(void* p);

        const PWCHAR& get_name() const;
        void set_name(const PWCHAR name);

        const HANDLE& get_pid() const;
        void set_pid(const HANDLE pid);

        const PEPROCESS& get_process() const;
        void set_process(const PEPROCESS process);
    };
}