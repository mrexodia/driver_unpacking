#pragma once

#include <Windows.h>

void dinit(bool consoleEnabled);
void dprintf(const char* format, ...);
void dputs(const char* text);

#define dlog() dprintf("[%u] " __FUNCTION__ "\n", GetCurrentProcessId())
#define dlogp(fmt, ...) dprintf("[%u] " __FUNCTION__ "(" fmt ")\n", GetCurrentProcessId(), __VA_ARGS__)
#define dtodo() dprintf("[%u] [TODO] " __FUNCTION__ "\n", GetCurrentProcessId())
#define dtodop(fmt, ...) dprintf("[%u] [TODO] " __FUNCTION__ "(" fmt ")\n", GetCurrentProcessId(), __VA_ARGS__)