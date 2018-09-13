#include "debug.h"

#include <Windows.h>
#include <stdarg.h>
#include <stdio.h>

static char dprintf_msg[66000];
static CRITICAL_SECTION cr;
static bool consoleEnabled = false;
static HANDLE hLog = INVALID_HANDLE_VALUE;

void dinit(bool consoleEnabled)
{
	if (consoleEnabled)
		AllocConsole();
	::consoleEnabled = consoleEnabled;
	InitializeCriticalSection(&cr);
	hLog = CreateFileW(L"ntoskrnl.log", GENERIC_WRITE, FILE_SHARE_WRITE, nullptr, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, nullptr);
}

void dprintf(const char* format, ...)
{
	EnterCriticalSection(&cr);
	va_list args;
	va_start(args, format);
	*dprintf_msg = 0;
	auto len = vsnprintf(dprintf_msg, sizeof(dprintf_msg), format, args);
	if (consoleEnabled)
	{
		DWORD written = 0;
		WriteFile(GetStdHandle(STD_OUTPUT_HANDLE), dprintf_msg, (DWORD)strlen(dprintf_msg), &written, nullptr);
	}
	if (hLog != INVALID_HANDLE_VALUE)
	{
		DWORD written = 0;
		WriteFile(hLog, dprintf_msg, (DWORD)strlen(dprintf_msg), &written, nullptr);
	}
	dprintf_msg[len - 1] = '\0';
	OutputDebugStringA(dprintf_msg);
	LeaveCriticalSection(&cr);
}

void dputs(const char* text)
{
	dprintf("%s\n", text);
}