#pragma once

#include <cstdio>
#include <cstdarg>
#include <windows.h>

static void dprintf(const char* format, ...)
{
    static char dprintf_msg[66000];
    va_list args;
    va_start(args, format);
    *dprintf_msg = 0;
    vsnprintf(dprintf_msg, sizeof(dprintf_msg), format, args);
    OutputDebugStringA(dprintf_msg);
}

static void dputs(const char* text)
{
    dprintf("%s\n", text);
}