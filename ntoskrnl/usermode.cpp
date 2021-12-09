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

    ULONG_PTR getReg(uint8_t reg)
    {
        if (reg >= NMD_X86_REG_DR0 && reg <= NMD_X86_REG_DR15)
        {
            return DebugRegisters[reg - NMD_X86_REG_DR0];
        }
        
        switch (reg)
        {
        case NMD_X86_REG_RAX:
            return Context->Rax;
        case NMD_X86_REG_RCX:
            return Context->Rcx;
        case NMD_X86_REG_RDX:
            return Context->Rdx;
        case NMD_X86_REG_RBX:
            return Context->Rbx;
        case NMD_X86_REG_RSP:
            return Context->Rsp;
        case NMD_X86_REG_RBP:
            return Context->Rbp;
        case NMD_X86_REG_RSI:
            return Context->Rsi;
        case NMD_X86_REG_RDI:
            return Context->Rdi;
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
        case NMD_X86_REG_RAX:
            Context->Rax = value;
            break;
        case NMD_X86_REG_RCX:
            Context->Rcx = value;
            break;
        case NMD_X86_REG_RDX:
            Context->Rdx = value;
            break;
        case NMD_X86_REG_RBX:
            Context->Rbx = value;
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
        default:
            dlogp("Unsupported register %u", reg);
            __debugbreak();
            break;
        }
    }
};

static thread_local SpecialState special;

static LONG NTAPI VectoredHandler(
    struct _EXCEPTION_POINTERS* ExceptionInfo
)
{
    const auto& exception = *ExceptionInfo->ExceptionRecord;
    auto& context = *ExceptionInfo->ContextRecord;
    special.Context = &context;
    if (exception.ExceptionCode == DBG_PRINTEXCEPTION_C)
    {
        return EXCEPTION_CONTINUE_SEARCH;
    }
    else if (exception.ExceptionCode == EXCEPTION_PRIV_INSTRUCTION)
    {
        nmd_x86_instruction instr;
        if (nmd_x86_decode((const uint8_t*)context.Rip, 15, &instr, NMD_X86_MODE_64, NMD_X86_DECODER_FLAGS_ALL))
        {
            char formatted[256];
            auto formatFlags = (NMD_X86_FORMAT_FLAGS_HEX | NMD_X86_FORMAT_FLAGS_0X_PREFIX);
            nmd_x86_format(&instr, formatted, context.Rip, formatFlags);
            dlogp("privileged instruction: %s, %d %d", formatted, instr.operands[0].fields.reg, instr.operands[1].fields.reg);

            // mov X, Y
            if (instr.id == NMD_X86_INSTRUCTION_MOV && instr.operands[0].type == NMD_X86_OPERAND_TYPE_REGISTER && instr.operands[1].type == NMD_X86_OPERAND_TYPE_REGISTER)
            {
                special.setReg(instr.operands[0].fields.reg, special.getReg(instr.operands[1].fields.reg));
                context.Rip += instr.length;
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
    return TRUE;
}

#include <Psapi.h>
#pragma comment(lib, "psapi.lib")