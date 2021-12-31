# driver_unpacking

Ghetto user mode emulation of Windows kernel drivers. See the [Kernel driver unpacking](https://x64dbg.com/blog/2017/06/08/kernel-driver-unpacking.html) blog post for a practical application.

## Usage

You can use `MakeUsermode` to convert the driver to a user-mode program, it will then import the fake `ntoskrnl.exe` which acts as an emulator. It is meant as a way to conduct simple research and only a few APIs are implemented. A more comprehensive tool is [speakeasy](https://github.com/mandiant/speakeasy), but this allows you to debug drivers in [x64dbg](https://x64dbg.com).

Related utility: [SysShellHandler](https://github.com/mrexodia/FunUtils/blob/master/README.md#sysshellhandler).