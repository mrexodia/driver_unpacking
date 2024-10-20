#include <windows.h>
#include <string>

int wmain(int argc, wchar_t* argv[])
{
	if (argc < 2)
	{
		puts("Usage: MakeUsermode driver.sys [driver.exe]");
		return EXIT_FAILURE;
	}
	std::wstring dest = argv[1];
	if (argc > 2)
	{
		dest = argv[2];
	}
	else
	{
		auto idx = dest.rfind('.');
		if (idx != dest.npos)
			dest.resize(idx);
		dest += L".exe";
	}
	int status = EXIT_FAILURE;
	if (CopyFileW(argv[1], dest.c_str(), FALSE))
	{
		HANDLE hFile = CreateFileW(dest.c_str(), GENERIC_READ | GENERIC_WRITE, 0, nullptr, OPEN_EXISTING, 0, nullptr);
		if (hFile != INVALID_HANDLE_VALUE)
		{
			IMAGE_DOS_HEADER idh = { 0 };
			DWORD read = 0;
			if (ReadFile(hFile, &idh, sizeof(idh), &read, nullptr))
			{
				if (idh.e_magic == IMAGE_DOS_SIGNATURE)
				{
					if (SetFilePointer(hFile, idh.e_lfanew, nullptr, FILE_BEGIN))
					{
						IMAGE_NT_HEADERS nth = { 0 };
						if (ReadFile(hFile, &nth, sizeof(nth), &read, nullptr))
						{
							if (nth.Signature == IMAGE_NT_SIGNATURE)
							{
								if (nth.FileHeader.Machine == IMAGE_FILE_MACHINE_AMD64)
								{
									nth.OptionalHeader.Subsystem = IMAGE_SUBSYSTEM_WINDOWS_GUI;
									nth.OptionalHeader.DllCharacteristics &= ~(IMAGE_DLLCHARACTERISTICS_FORCE_INTEGRITY | IMAGE_DLLCHARACTERISTICS_DYNAMIC_BASE);
									if (SetFilePointer(hFile, idh.e_lfanew, nullptr, FILE_BEGIN))
									{
										DWORD written = 0;
										if (WriteFile(hFile, &nth, sizeof(nth), &written, nullptr))
										{
											status = EXIT_SUCCESS;
											puts("Yay!");
										}
										else
										{
											puts("Failed to write file");
										}
									}
									else
									{
										puts("Failed to set write pointer");
									}
								}
								else if (nth.FileHeader.Machine == IMAGE_FILE_MACHINE_I386)
								{
									auto& nth32 = *(IMAGE_NT_HEADERS32*)&nth;
									nth32.OptionalHeader.Subsystem = IMAGE_SUBSYSTEM_WINDOWS_GUI;
									nth32.OptionalHeader.DllCharacteristics &= ~(IMAGE_DLLCHARACTERISTICS_FORCE_INTEGRITY | IMAGE_DLLCHARACTERISTICS_DYNAMIC_BASE);
									if (SetFilePointer(hFile, idh.e_lfanew, nullptr, FILE_BEGIN))
									{
										DWORD written = 0;
										if (WriteFile(hFile, &nth32, sizeof(nth32), &written, nullptr))
										{
											status = EXIT_SUCCESS;
											puts("Yay!");
										}
										else
										{
											puts("Failed to write file");
										}
									}
									else
									{
										puts("Failed to set write pointer");
									}
								}
								else
								{
									puts("Invalid machine");
								}
							}
							else
							{
								puts("Invalid NT signature");
							}
						}
						else
						{
							puts("Failed to read NT header");
						}
					}
					else
					{
						puts("Failed to seek DOS header");
					}
				}
				else
				{
					puts("Invalid DOS header");
				}
			}
			else
			{
				puts("Failed to read DOS header");
			}
			CloseHandle(hFile);
		}
		else
		{
			puts("Failed to open file");
		}
	}
	else
	{
		puts("Failed to copy file");
	}
	return status;
}