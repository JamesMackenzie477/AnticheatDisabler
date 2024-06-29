#include <Windows.h>

const char ReturnFalse[] = { 0xB8, 0x00, 0x00, 0x00, 0x00, 0xC3 };

BOOL WINAPI DllMain(HINSTANCE hinstDLL, DWORD fdwReason, LPVOID lpvReserved)
{
	DWORD OldProtect, NewProtect;

	// Gets function addresses.

	auto pIDP = reinterpret_cast<char *>(GetProcAddress(GetModuleHandle(L"KernelBase.dll"), "IsDebuggerPresent"));
	auto pCRDP = reinterpret_cast<char *>(GetProcAddress(GetModuleHandle(L"Kernel32.dll"),	"CheckRemoteDebuggerPresent"));
	auto pODS = reinterpret_cast<char *>(GetProcAddress(GetModuleHandle(L"KernelBase.dll"), "OutputDebugStringA"));

	if (!pIDP || !pCRDP || !pODS) return false;

	// Removes memory protections.

	VirtualProtect(pIDP, sizeof(ReturnFalse), PAGE_EXECUTE_READWRITE, &OldProtect);
	VirtualProtect(pCRDP, sizeof(ReturnFalse), PAGE_EXECUTE_READWRITE, &OldProtect);
	VirtualProtect(pODS, sizeof(ReturnFalse), PAGE_EXECUTE_READWRITE, &OldProtect);

	// Hooks functions.

	memcpy(pIDP, ReturnFalse, sizeof(ReturnFalse));
	memcpy(pCRDP, ReturnFalse, sizeof(ReturnFalse));
	memcpy(pODS, ReturnFalse, sizeof(ReturnFalse));

	NewProtect = OldProtect;

	// Restores memory protections.

	VirtualProtect(pIDP, sizeof(ReturnFalse), NewProtect, &OldProtect);
	VirtualProtect(pCRDP, sizeof(ReturnFalse), NewProtect, &OldProtect);
	VirtualProtect(pODS, sizeof(ReturnFalse), NewProtect, &OldProtect);
}