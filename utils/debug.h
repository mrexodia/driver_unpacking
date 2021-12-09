#pragma once

void dinit(bool consoleEnabled);
void dprintf(const char* format, ...);
void dputs(const char* text);
size_t unfake(const char* function);
unsigned int pid();

#define dlog() dprintf("[%u] %.*s\n", pid(), unfake(__FUNCTION__), __FUNCTION__)
#define dlogp(fmt, ...) dprintf("[%u] %.*s(" fmt ")\n", pid(), unfake(__FUNCTION__), __FUNCTION__, __VA_ARGS__)
#define dtodo() dprintf("[%u] [TODO] %.*s\n", pid(), unfake(__FUNCTION__), __FUNCTION__)
#define dtodop(fmt, ...) dprintf("[%u] [TODO] %.*s(" fmt ")\n", pid(), unfake(__FUNCTION__), __FUNCTION__, __VA_ARGS__)