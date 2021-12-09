#ifdef __cplusplus
extern "C"
{
#endif

#include <ntifs.h>
#include <ntddstor.h>
#include <mountdev.h>
#include <ntddvol.h>
#include <ntstrsafe.h>
#include <ntimage.h>
#include <stdint.h>

#ifdef __cplusplus
}
#endif

#include "../utils/debug.h"

#pragma optimize("", off)
BOOLEAN MmIsAddressValid_FAKE(PVOID VirtualAddress)
{
    dlogp("%p", VirtualAddress);
    __try
    {
        auto x = *(char*)VirtualAddress;
        return TRUE;
    }
    __except(GetExceptionCode() == STATUS_ACCESS_VIOLATION)
    {
        return FALSE;
    }
}
#pragma optimize("", on)

PVOID ExAllocatePool_FAKE(
    POOL_TYPE PoolType,
    SIZE_T NumberOfBytes
)
{
    auto p = VirtualAlloc(0, NumberOfBytes, MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE);
    dlogp("%u, %p -> %p", PoolType, NumberOfBytes, p);
    return p;
}

PVOID ExAllocatePoolWithTag_FAKE(
    POOL_TYPE PoolType,
    SIZE_T NumberOfBytes,
    ULONG Tag
)
{
    auto p = VirtualAlloc(0, NumberOfBytes, MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE);
    dlogp("%u, %p, %08X -> %p", PoolType, NumberOfBytes, Tag, p);
    return p;
}

extern "C"
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

#if 0
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
#endif

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

extern "C" PMDL IoAllocateMdl_FAKE(
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

extern "C" VOID MmProbeAndLockPages_FAKE(
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

extern "C" PVOID MmMapLockedPagesSpecifyCache_FAKE(
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

extern "C" KAFFINITY KeQueryActiveProcessors_FAKE()
{
    dlog();
    return 1;
}

extern "C" VOID KeSetSystemAffinityThread_FAKE(
    KAFFINITY Affinity
)
{
    dlog();
}

extern "C" VOID KeRevertToUserAffinityThread_FAKE()
{
    dlog();
}

typedef struct _RKMUTEX {} RKMUTEX, *PRKMUTEX;

extern "C" VOID KeInitializeMutex_FAKE(
    PRKMUTEX Mutex,
    ULONG    Level
)
{
    dlog();
}

extern "C" void KeInitializeSpinLock_FAKE(
    PKSPIN_LOCK SpinLock
)
{
    dlog();
    *SpinLock = 0;
}

using KIRQL = ULONG;

extern "C" KIRQL KeAcquireSpinLockRaiseToDpc_FAKE(
    PKSPIN_LOCK SpinLock
)
{
    dlog();
    return DISPATCH_LEVEL;
}

extern "C" void KeReleaseSpinLock_FAKE(
    PKSPIN_LOCK SpinLock,
    KIRQL NewIrql
)
{
    dlogp("NewIrql: %u", NewIrql);
}

using PDRIVER_OBJECT = void*;
using PDEVICE_OBJECT = void*;

extern "C" NTSTATUS IoCreateDevice_FAKE(
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

extern "C" void KeInitializeGuardedMutex_FAKE(
    PKGUARDED_MUTEX Mutex
)
{
    dlog();
}

extern "C" VOID MmUnlockPages_FAKE(
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

extern "C" VOID IoFreeMdl_FAKE(
    PMDL Mdl
)
{
    dlogp("0x%p", Mdl);
    delete Mdl;
}

extern "C" NTSTATUS KeGetProcessorNumberFromIndex_FAKE(
    ULONG             ProcIndex,
    PPROCESSOR_NUMBER ProcNumber
)
{
    dlogp("%u", ProcIndex);
    *ProcNumber = { 0, (BYTE)ProcIndex };
    return STATUS_SUCCESS;
}

extern "C" void KeSetSystemGroupAffinityThread_FAKE(
    PGROUP_AFFINITY Affinity,
    PGROUP_AFFINITY PreviousAffinity
)
{
    dlogp("Mask: %X, Group: %u", Affinity->Mask, Affinity->Group);
    if (PreviousAffinity)
        *PreviousAffinity = *Affinity;
}

extern "C" void KeRevertToUserGroupAffinityThread_FAKE(
    PGROUP_AFFINITY PreviousAffinity
)
{
    dlogp("Mask: %X, Group: %u", PreviousAffinity->Mask, PreviousAffinity->Group);
}