#include "dprintf.h"

#define FAKE(x) extern "C" __declspec(dllexport) void* x() { OutputDebugStringA(#x); return nullptr; }

FAKE(FltCloseClientPort)
FAKE(FltReleaseContext)
FAKE(FltSetVolumeContext)
FAKE(FltGetDiskDeviceObject)
FAKE(FltGetVolumeProperties)
FAKE(FltAllocateContext)
FAKE(FltStartFiltering)
FAKE(FltFreeSecurityDescriptor)
FAKE(FltCreateCommunicationPort)
FAKE(FltBuildDefaultSecurityDescriptor)
FAKE(FltUnregisterFilter)
FAKE(FltRegisterFilter)
FAKE(FltObjectDereference)
FAKE(FltCloseCommunicationPort)
FAKE(FltGetVolumeFromName)
FAKE(FltClose)
FAKE(FltFlushBuffers)
FAKE(FltQueryInformationFile)
FAKE(FltCreateFileEx)
FAKE(FltParseFileName)
FAKE(FltReleaseFileNameInformation)
FAKE(FltGetFileNameInformation)
FAKE(FltSetCallbackDataDirty)
FAKE(FltSetInformationFile)
FAKE(FltSendMessage)
FAKE(FltGetBottomInstance)
FAKE(FltFreePoolAlignedWithTag)
FAKE(FltDoCompletionProcessingWhenSafe)
FAKE(FltReadFile)
FAKE(FltGetRequestorProcess)
FAKE(FltLockUserBuffer)
FAKE(FltAllocatePoolAlignedWithTag)
FAKE(FltGetVolumeContext)
FAKE(FltGetFilterFromInstance)
FAKE(FltGetVolumeFromInstance)
FAKE(FltWriteFile)
FAKE(FltGetTopInstance)
FAKE(FltIsOperationSynchronous)
FAKE(FltFsControlFile)
FAKE(FltCompletePendedPreOperation)
FAKE(FltCancelIo)
FAKE(FltSetCancelCompletion)
FAKE(FltClearCancelCompletion)
FAKE(FltParseFileNameInformation)
FAKE(FltGetVolumeFromFileObject)

#pragma optimize("", off)
BOOL MmIsAddressValid_FAKE(LPCVOID addr)
{
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