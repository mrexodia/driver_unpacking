#define DLL_EXPORT extern "C" __declspec(dllexport)
#define FAKE(x) void* x() { return #x; }
#include "ntoskrnl.h"