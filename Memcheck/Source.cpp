//#include <Windows.h>
#include "Memcheck.h"
#include <Windows.h>
#include <string>
#include <iostream>
#include <stdlib.h>
#include <vector>
#include <iterator>
#include <fstream>
#include <intrin.h>
#include <Tlhelp32.h>
#include <CommCtrl.h>
#include <fstream>
#include <sstream>
#include <Psapi.h>
#include <stdint.h>
#include <memory>
#include <d3d9.h>
#include <Dwmapi.h>

namespace Security
{
	int WINAPI Hooked_MessageBoxA(HWND hWnd, LPCTSTR lpText, LPCTSTR lpCaption, UINT uType) {
		return MessageBoxW(GetDesktopWindow(), L"", L"", MB_OK);
		//system("taskkill /F /IM RobloxPlayerBeta.exe 2>NULL");
	}

	void HookMessageBoxA() {
		DWORD Protection;
		VirtualProtect((LPVOID)& MessageBoxA, 1, PAGE_EXECUTE_READWRITE, &Protection);
		*(BYTE*)(&MessageBoxA) = 0xE9;
		*(DWORD*)((DWORD)& MessageBoxA + 1) = (DWORD)& Hooked_MessageBoxA - (DWORD)& MessageBoxA - 5;
		VirtualProtect((LPVOID)& MessageBoxA, 1, Protection, &Protection);
	}

	void BypassDetection() {
		HookMessageBoxA(); // Just so users don't panic because they think they've been tainted
		CreateMutexA(NULL, FALSE, "RobloxCrashDumpUploaderMutex");
	}

}
int main()
{
	Security::BypassDetection();
	memcheck::load_bypass();
}


BOOL APIENTRY DllMain(HMODULE Module, DWORD Reason, LPVOID) {
	switch (Reason)
	{
	case DLL_PROCESS_ATTACH:
		DWORD consoleOldProtect = 0;
		VirtualProtect(FreeConsole, 1, PAGE_EXECUTE_READWRITE, &consoleOldProtect);
		*(UINT*)FreeConsole = 0xC2;
		AllocConsole();
		freopen("CONOUT$", "w", stdout);
		freopen("CONIN$", "r", stdin);
		DWORD cons = (WS_CAPTION | DS_MODALFRAME | WS_MINIMIZEBOX | WS_SYSMENU);
		SetWindowLong(GetConsoleWindow(), GWL_STYLE, cons);
		SetWindowPos(GetConsoleWindow(), HWND_TOPMOST, 0, 0, 0, 0, SWP_DRAWFRAME | SWP_NOSIZE | SWP_NOMOVE | SWP_SHOWWINDOW);
		SetConsoleTitleA("MemCheck");
		DisableThreadLibraryCalls(Module);
		DWORD OldProtection;
		VirtualProtect(Module, 0x1000, PAGE_READWRITE, &OldProtection);
		ZeroMemory(Module, 0x1000);
		CreateThread(NULL, NULL, (LPTHREAD_START_ROUTINE)main, NULL, NULL, NULL);
		break;
	}
	return TRUE;
}
