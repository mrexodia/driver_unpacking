#pragma once

#include <Windows.h>

void dinit(bool consoleEnabled);
void dprintf(const char* format, ...);
void dputs(const char* text);
size_t unfake(const char* function);

#define dlog() dprintf("[%u] %.*s\n", GetCurrentProcessId(), unfake(__FUNCTION__), __FUNCTION__)
#define dlogp(fmt, ...) dprintf("[%u] %.*s(" fmt ")\n", GetCurrentProcessId(), unfake(__FUNCTION__), __FUNCTION__, __VA_ARGS__)
#define dtodo() dprintf("[%u] [TODO] %.*s\n", GetCurrentProcessId(), unfake(__FUNCTION__), __FUNCTION__)
#define dtodop(fmt, ...) dprintf("[%u] [TODO] %.*s(" fmt ")\n", GetCurrentProcessId(), unfake(__FUNCTION__), __FUNCTION__, __VA_ARGS__)