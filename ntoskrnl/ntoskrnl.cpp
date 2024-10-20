#include "../ntdll/ntdll.h"
#include <windows.h>
#include <stdint.h>

#include "../utils/debug.h"

#include <stdio.h>
#include <stdarg.h>
#include "nmd_assembly.h"

struct SpecialState
{
    ULONG_PTR DebugRegisters[16] = {};
    CONTEXT* Context = nullptr;
    DWORD tid = GetCurrentThreadId();

    ULONG_PTR getReg(uint8_t reg)
    {
        if (reg >= NMD_X86_REG_DR0 && reg <= NMD_X86_REG_DR15)
        {
            return DebugRegisters[reg - NMD_X86_REG_DR0];
        }

        switch (reg)
        {
#ifdef _WIN64
        case NMD_X86_REG_RAX:
            return Context->Rax;
        case NMD_X86_REG_RBX:
            return Context->Rbx;
        case NMD_X86_REG_RCX:
            return Context->Rcx;
        case NMD_X86_REG_RDX:
            return Context->Rdx;
        case NMD_X86_REG_RSP:
            return Context->Rsp;
        case NMD_X86_REG_RBP:
            return Context->Rbp;
        case NMD_X86_REG_RSI:
            return Context->Rsi;
        case NMD_X86_REG_RDI:
            return Context->Rdi;
#else
        case NMD_X86_REG_EAX:
            return Context->Eax;
        case NMD_X86_REG_EBX:
            return Context->Ebx;
        case NMD_X86_REG_ECX:
            return Context->Ecx;
        case NMD_X86_REG_EDX:
            return Context->Edx;
        case NMD_X86_REG_ESP:
            return Context->Esp;
        case NMD_X86_REG_EBP:
            return Context->Ebp;
        case NMD_X86_REG_ESI:
            return Context->Esi;
        case NMD_X86_REG_EDI:
            return Context->Edi;
#endif // _WIN64
        default:
            dlogp("Unsupported register %u", reg);
            __debugbreak();
            return 0;
        }

    }

    void setReg(uint8_t reg, ULONG_PTR value)
    {
        if (reg >= NMD_X86_REG_DR0 && reg <= NMD_X86_REG_DR15)
        {
            DebugRegisters[reg - NMD_X86_REG_DR0] = value;
            return;
        }

        switch (reg)
        {
#ifdef _WIN64
        case NMD_X86_REG_RAX:
            Context->Rax = value;
            break;
        case NMD_X86_REG_RBX:
            Context->Rbx = value;
            break;
        case NMD_X86_REG_RCX:
            Context->Rcx = value;
            break;
        case NMD_X86_REG_RDX:
            Context->Rdx = value;
            break;
        case NMD_X86_REG_RSP:
            Context->Rsp = value;
            break;
        case NMD_X86_REG_RBP:
            Context->Rbp = value;
            break;
        case NMD_X86_REG_RSI:
            Context->Rsi = value;
            break;
        case NMD_X86_REG_RDI:
            Context->Rdi = value;
            break;
#else
        case NMD_X86_REG_EAX:
            Context->Eax = value;
            break;
        case NMD_X86_REG_EBX:
            Context->Ebx = value;
            break;
        case NMD_X86_REG_ECX:
            Context->Ecx = value;
            break;
        case NMD_X86_REG_EDX:
            Context->Edx = value;
            break;
        case NMD_X86_REG_ESP:
            Context->Esp = value;
            break;
        case NMD_X86_REG_EBP:
            Context->Ebp = value;
            break;
        case NMD_X86_REG_ESI:
            Context->Esi = value;
            break;
        case NMD_X86_REG_EDI:
            Context->Edi = value;
            break;
#endif // _WIN64
        default:
            dlogp("Unsupported register %u", reg);
            __debugbreak();
            break;
        }
    }
};

static DWORD tlsIndex = 0;

SpecialState& state()
{
    auto ptr = (SpecialState*)TlsGetValue(tlsIndex);
    if (ptr == nullptr)
        __debugbreak();
    return *ptr;
}

static LONG NTAPI VectoredHandler(
    struct _EXCEPTION_POINTERS* ExceptionInfo
)
{
    const auto& exception = *ExceptionInfo->ExceptionRecord;
    auto context = ExceptionInfo->ContextRecord;
#ifdef _WIN64
#define Cip(ctx) ctx->Rip
#else
#define Cip(ctx) ctx->Eip
#endif // _WIN64
    if (exception.ExceptionCode == DBG_PRINTEXCEPTION_C)
    {
        return EXCEPTION_CONTINUE_SEARCH;
    }
    else if (exception.ExceptionCode == EXCEPTION_PRIV_INSTRUCTION)
    {
        nmd_x86_instruction instr;
        if (nmd_x86_decode((const uint8_t*)Cip(context), 15, &instr, NMD_X86_MODE_64, NMD_X86_DECODER_FLAGS_ALL))
        {
            char formatted[256];
            auto formatFlags = (NMD_X86_FORMAT_FLAGS_HEX | NMD_X86_FORMAT_FLAGS_0X_PREFIX);
            nmd_x86_format(&instr, formatted, Cip(context), formatFlags);
            dlogp("privileged instruction: %s", formatted);

            state().Context = context;

            // mov X, Y
            if (instr.id == NMD_X86_INSTRUCTION_MOV && instr.operands[0].type == NMD_X86_OPERAND_TYPE_REGISTER && instr.operands[1].type == NMD_X86_OPERAND_TYPE_REGISTER)
            {
                state().setReg(instr.operands[0].fields.reg, state().getReg(instr.operands[1].fields.reg));
                Cip(context) += instr.length;
                return EXCEPTION_CONTINUE_EXECUTION;
            }
        }
    }
    return EXCEPTION_CONTINUE_SEARCH;
}

BOOL WINAPI DllMain(
    _In_ HINSTANCE hinstDLL,
    _In_ DWORD     fdwReason,
    _In_ LPVOID    lpvReserved
)
{
    if (fdwReason == DLL_PROCESS_ATTACH)
    {
        tlsIndex = TlsAlloc();
        TlsSetValue(tlsIndex, new SpecialState());

        // TODO: hook entry point and set DriverEntry parameters up properly
        dinit(true);

        auto base = (ULONG_PTR)GetModuleHandleW(nullptr);
        DWORD oldProtect = 0;
        VirtualProtect((void*)base, 0x1000, PAGE_READWRITE, &oldProtect);
        auto pdh = PIMAGE_DOS_HEADER(base);
        auto pnth = PIMAGE_NT_HEADERS(base + pdh->e_lfanew);

        HANDLE hFile = INVALID_HANDLE_VALUE;
        {
            wchar_t szDriverName[MAX_PATH];
            if (GetModuleFileNameW((HMODULE)base, szDriverName, _countof(szDriverName)))
            {
                auto period = wcsrchr(szDriverName, L'.');
                if (period)
                {
                    period[0] = L'\0';
                    wcscat_s(szDriverName, L".sys");
                }
                hFile = CreateFileW(szDriverName, GENERIC_READ, FILE_SHARE_READ, nullptr, OPEN_EXISTING, 0, nullptr);
            }
        }
        bool success = false;
        if (hFile != INVALID_HANDLE_VALUE)
        {
            IMAGE_NT_HEADERS nth;
            DWORD read = 0;
            if (SetFilePointer(hFile, pdh->e_lfanew, nullptr, FILE_BEGIN))
            {
                if (ReadFile(hFile, &nth, (DWORD)sizeof(nth), &read, nullptr))
                {
                    memcpy(pnth, &nth, sizeof(nth));
                    success = true;
                }
            }
            CloseHandle(hFile);
        }

        if (success)
        {
            dputs("Restored PE header from sys file");
        }
        else
        {
            dputs("Failed to restore PE header from sys file");
            //__debugbreak(); //TODO: change this to whatever the original .sys used
            pnth->OptionalHeader.Subsystem = IMAGE_SUBSYSTEM_NATIVE;
            pnth->OptionalHeader.MajorOperatingSystemVersion = 10;
            pnth->OptionalHeader.MinorOperatingSystemVersion = 0;
            pnth->OptionalHeader.MajorImageVersion = 10;
            pnth->OptionalHeader.MinorImageVersion = 0;
            pnth->OptionalHeader.MajorSubsystemVersion = 6;
            pnth->OptionalHeader.MinorSubsystemVersion = 1;
            pnth->OptionalHeader.DllCharacteristics = 0x4160;
            __debugbreak();
        }
        VirtualProtect((void*)base, 0x1000, oldProtect, &oldProtect);
        
        AddVectoredExceptionHandler(1, VectoredHandler);
    }
    else if (fdwReason == DLL_PROCESS_DETACH)
    {
        delete& state();
    }
    else if (fdwReason == DLL_THREAD_ATTACH)
    {
        TlsSetValue(tlsIndex, new SpecialState());
    }
    else if (fdwReason == DLL_THREAD_DETACH)
    {
        delete& state();
    }
    return TRUE;
}

#define NTKERNELAPI

#pragma optimize("", off)
BOOL MmIsAddressValid_FAKE(LPCVOID addr)
{
    dlogp("%p", addr);
    __try
    {
        auto x = *(char*)addr;
        return TRUE;
    }
    __except(EXCEPTION_ACCESS_VIOLATION)
    {
        return FALSE;
    }
}
#pragma optimize("", on)

using POOL_TYPE = uint32_t;

NTKERNELAPI PVOID ExAllocatePool_FAKE(
    POOL_TYPE PoolType,
    SIZE_T NumberOfBytes
)
{
    auto p = VirtualAlloc(0, NumberOfBytes, MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE);
    dlogp("%u, %p -> %p", PoolType, NumberOfBytes, p);
    return p;
}

NTKERNELAPI PVOID ExAllocatePoolWithTag_FAKE(
    POOL_TYPE PoolType,
    SIZE_T NumberOfBytes,
    ULONG Tag
)
{
    auto p = VirtualAlloc(0, NumberOfBytes, MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE);
    dlogp("%u, %p, %08X -> %p", PoolType, NumberOfBytes, Tag, p);
    return p;
}

#include <Psapi.h>
#pragma comment(lib, "psapi.lib")

NTSTATUS
NTAPI
NtQuerySystemInformation_FAKE(
    _In_ SYSTEM_INFORMATION_CLASS SystemInformationClass,
    _Out_opt_ PVOID SystemInformation,
    _In_ ULONG SystemInformationLength,
    _Out_opt_ PULONG ReturnLength
)
{
    dlogp("%u, %p, %u, %p", SystemInformationClass, SystemInformation, SystemInformationLength, ReturnLength);
    auto status = NtQuerySystemInformation(SystemInformationClass, SystemInformation, SystemInformationLength, ReturnLength);
    if(NT_SUCCESS(status) && SystemInformationClass == SystemModuleInformation)
    {
        auto modules = PRTL_PROCESS_MODULES(SystemInformation);
        for(ULONG i = 0; i < modules->NumberOfModules; i++)
        {
            auto& mod = modules->Modules[i];
            auto modname = (char*)mod.FullPathName + mod.OffsetToFileName;
            auto hMod = GetModuleHandleA(modname);
            if(hMod)
            {
                MODULEINFO info;
                GetModuleInformation(GetCurrentProcess(), hMod, &info, sizeof(info));
                mod.ImageBase = info.lpBaseOfDll;
                mod.ImageSize = info.SizeOfImage;
                mod.MappedBase = mod.ImageBase;
            }
        }
    }
    return status;
}

extern "C" __declspec(dllexport) KSYSTEM_TIME KeTickCount = {};

VOID ExFreePoolWithTag_FAKE(
    PVOID P,
    ULONG Tag
)
{
    dlogp("%p, %08X", P, Tag);
    //who cares about leaks amirite?
}

ULONG DbgPrint_FAKE(
    PCSTR Format,
    ...
)
{
    va_list args;

    va_start(args, Format);

    auto buffer = new char[16384];
    auto result = vsnprintf_s(buffer, 16384, _TRUNCATE, Format, args);
    dlogp("%s", buffer);
    delete[] buffer;

    va_end(args);

    return result;
}

using PIRP = void*;
typedef short CSHORT;
typedef struct _EPROCESS {} EPROCESS, *PEPROCESS;

typedef
_Struct_size_bytes_(_Inexpressible_(sizeof(struct _MDL) +    // 747934
(ByteOffset + ByteCount + PAGE_SIZE - 1) / PAGE_SIZE * sizeof(PFN_NUMBER)))
struct _MDL
{
    struct _MDL *Next;
    CSHORT Size;
    CSHORT MdlFlags;

    struct _EPROCESS *Process;
    PVOID MappedSystemVa;   /* see creators for field size annotations. */
    PVOID StartVa;   /* see creators for validity; could be address 0.  */
    ULONG ByteCount;
    ULONG ByteOffset;
    //added for hax
    DWORD OldProtect;
} MDL, *PMDL;

#define MDL_MAPPED_TO_SYSTEM_VA     0x0001
#define MDL_PAGES_LOCKED            0x0002
#define MDL_SOURCE_IS_NONPAGED_POOL 0x0004
#define MDL_ALLOCATED_FIXED_SIZE    0x0008
#define MDL_PARTIAL                 0x0010
#define MDL_PARTIAL_HAS_BEEN_MAPPED 0x0020
#define MDL_IO_PAGE_READ            0x0040
#define MDL_WRITE_OPERATION         0x0080
#define MDL_LOCKED_PAGE_TABLES      0x0100
#define MDL_PARENT_MAPPED_SYSTEM_VA MDL_LOCKED_PAGE_TABLES
#define MDL_FREE_EXTRA_PTES         0x0200
#define MDL_DESCRIBES_AWE           0x0400
#define MDL_IO_SPACE                0x0800
#define MDL_NETWORK_HEADER          0x1000
#define MDL_MAPPING_CAN_FAIL        0x2000
#define MDL_PAGE_CONTENTS_INVARIANT 0x4000
#define MDL_ALLOCATED_MUST_SUCCEED  MDL_PAGE_CONTENTS_INVARIANT
#define MDL_INTERNAL                0x8000

#define MDL_MAPPING_FLAGS (MDL_MAPPED_TO_SYSTEM_VA     | \
                           MDL_PAGES_LOCKED            | \
                           MDL_SOURCE_IS_NONPAGED_POOL | \
                           MDL_PARTIAL_HAS_BEEN_MAPPED | \
                           MDL_PARENT_MAPPED_SYSTEM_VA | \
                           MDL_SYSTEM_VA               | \
                           MDL_IO_SPACE )

PMDL IoAllocateMdl_FAKE(
    PVOID VirtualAddress,
    ULONG Length,
    BOOLEAN SecondaryBuffer,
    BOOLEAN ChargeQuota,
    PIRP Irp
)
{
    dlogp("0x%p, 0x%x, %d, %d, %p", VirtualAddress, Length, SecondaryBuffer, ChargeQuota, Irp);
    auto mdl = new MDL();
    mdl->Next = nullptr;
    mdl->Size = 1;
    mdl->MdlFlags = MDL_ALLOCATED_FIXED_SIZE;
    mdl->Process = (EPROCESS*)0xffffffff00000000;
    mdl->MappedSystemVa = VirtualAddress;
    mdl->StartVa = VirtualAddress;
    mdl->ByteCount = Length;
    mdl->ByteOffset = 0;
    mdl->OldProtect = 0;
    return mdl;
}

VOID MmProbeAndLockPages_FAKE(
    PMDL MemoryDescriptorList,
    KPROCESSOR_MODE AccessMode,
    ULONG Operation
)
{
    dlogp("0x%p, %d, %d", MemoryDescriptorList, AccessMode, Operation);
    if(Operation == 1 /* IoWriteAccess*/)
    {
        DWORD oldProtect = 0;
        if(VirtualProtect(MemoryDescriptorList->StartVa, MemoryDescriptorList->ByteCount, PAGE_EXECUTE_READWRITE, &oldProtect))
        {
            MemoryDescriptorList->OldProtect = oldProtect;
        }
        else
        {
            dputs("VirtualProtect failed!");
        }
    }
}

PVOID MmMapLockedPagesSpecifyCache_FAKE(
    PMDL MemoryDescriptorList,
    KPROCESSOR_MODE AccessMode,
    ULONG CacheType,
    PVOID RequestedAddress,
    ULONG BugCheckOnFailure,
    ULONG Priority
)
{
    dlogp("0x%p, %d, %u, 0x%p, %u, %u", MemoryDescriptorList, AccessMode, CacheType, RequestedAddress, BugCheckOnFailure, Priority);
    return MemoryDescriptorList->StartVa;
}

KAFFINITY KeQueryActiveProcessors_FAKE()
{
    dlog();
    return 1;
}

VOID KeSetSystemAffinityThread_FAKE(
    KAFFINITY Affinity
)
{
    dlog();
}

VOID KeRevertToUserAffinityThread_FAKE()
{
    dlog();
}

typedef struct _RKMUTEX {} RKMUTEX, *PRKMUTEX;

VOID KeInitializeMutex_FAKE(
    PRKMUTEX Mutex,
    ULONG    Level
)
{
    dlog();
}

void KeInitializeSpinLock_FAKE(
    PKSPIN_LOCK SpinLock
)
{
    dlog();
    *SpinLock = 0;
}

using KIRQL = ULONG;

KIRQL KeAcquireSpinLockRaiseToDpc_FAKE(
    PKSPIN_LOCK SpinLock
)
{
    dlog();
    return DISPATCH_LEVEL;
}

void KeReleaseSpinLock_FAKE(
    PKSPIN_LOCK SpinLock,
    KIRQL NewIrql
)
{
    dlogp("NewIrql: %u", NewIrql);
}

using PDRIVER_OBJECT = void*;
using PDEVICE_OBJECT = void*;

NTSTATUS IoCreateDevice_FAKE(
    PDRIVER_OBJECT  DriverObject,
    ULONG           DeviceExtensionSize,
    PUNICODE_STRING DeviceName,
    DEVICE_TYPE     DeviceType,
    ULONG           DeviceCharacteristics,
    BOOLEAN         Exclusive,
    PDEVICE_OBJECT* DeviceObject
)
{
    dlogp("DriverObject: %p, DeviceName: %wZ", DriverObject, DeviceName);
    return STATUS_SUCCESS;
}

NTSTATUS IoCreateSymbolicLink_FAKE(
    PUNICODE_STRING SymbolicLinkName,
    PUNICODE_STRING DeviceName
)
{
    dlogp("%wZ -> %wZ", SymbolicLinkName, DeviceName);
    return STATUS_SUCCESS;
}

typedef struct _GUARDED_MUTEX {} GUARDED_MUTEX, * PKGUARDED_MUTEX;

void KeInitializeGuardedMutex_FAKE(
    PKGUARDED_MUTEX Mutex
)
{
    dlog();
}

VOID MmUnlockPages_FAKE(
    PMDL MemoryDescriptorList
)
{
    dlogp("0x%p", MemoryDescriptorList);
    if(MemoryDescriptorList->OldProtect)
    {
        DWORD old = 0;
        if(!VirtualProtect(MemoryDescriptorList->StartVa, MemoryDescriptorList->ByteCount, MemoryDescriptorList->OldProtect, &old))
            dputs("VirtualProtect failed!");
    }
}

VOID IoFreeMdl_FAKE(
    PMDL Mdl
)
{
    dlogp("0x%p", Mdl);
    delete Mdl;
}

NTSTATUS KeGetProcessorNumberFromIndex_FAKE(
    ULONG             ProcIndex,
    PPROCESSOR_NUMBER ProcNumber
)
{
    dlogp("%u", ProcIndex);
    *ProcNumber = { 0, (BYTE)ProcIndex };
    return STATUS_SUCCESS;
}

void KeSetSystemGroupAffinityThread_FAKE(
    PGROUP_AFFINITY Affinity,
    PGROUP_AFFINITY PreviousAffinity
)
{
    dlogp("Mask: %X, Group: %u", Affinity->Mask, Affinity->Group);
    if (PreviousAffinity)
        *PreviousAffinity = *Affinity;
}

void KeRevertToUserGroupAffinityThread_FAKE(
    PGROUP_AFFINITY PreviousAffinity
)
{
    dlogp("Mask: %X, Group: %u", PreviousAffinity->Mask, PreviousAffinity->Group);
}

using PCREATE_PROCESS_NOTIFY_ROUTINE_EX = void*;

NTSTATUS PsSetCreateProcessNotifyRoutineEx_FAKE(
    PCREATE_PROCESS_NOTIFY_ROUTINE_EX NotifyRoutine,
    BOOLEAN                           Remove
)
{
    dlogp("NotifyRoutine: %p, Remove: %d", NotifyRoutine, Remove);
    return STATUS_SUCCESS;
}

using POB_CALLBACK_REGISTRATION = void*;

NTSTATUS ObRegisterCallbacks_FAKE(
    POB_CALLBACK_REGISTRATION CallbackRegistration,
    PVOID* RegistrationHandle
)
{
    dlogp("CallbackRegistration: %p", CallbackRegistration);
    *RegistrationHandle = CallbackRegistration;
    return STATUS_SUCCESS;
}

using PCREATE_THREAD_NOTIFY_ROUTINE = void*;

NTSTATUS PsSetCreateThreadNotifyRoutine_FAKE(
    PCREATE_THREAD_NOTIFY_ROUTINE NotifyRoutine
)
{
    dlogp("NotifyRoutine: %p", NotifyRoutine);
    return STATUS_SUCCESS;
}

void RtlCopyUnicodeString_FAKE(
    PUNICODE_STRING  DestinationString,
    PCUNICODE_STRING SourceString
)
{
    dlogp("%wZ -> %wZ", SourceString, DestinationString);
    RtlCopyUnicodeString(DestinationString, SourceString);
}
