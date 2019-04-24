# vmp driver notes

convert to user mode (cff explorer):
- optional header -> subsystem: windows console
- optional header -> MajorOperatingSystemVersion: 5, MinorOperatingSystemVersion: 2
- optional header -> MajorImageVersion: 0, MinorImageVersion: 0
- optional header -> MajorSubsystemVersion: 5, MinorSubsystemVersion: 2
- optional header -> DllCharacteristics -> uncheck code integrity image

See: https://x64dbg.com/blog/2017/06/08/kernel-driver-unpacking.html