// dllmain.cpp : Defines the entry point for the DLL application.
#include "stdafx.h"
#include "mhook-lib/mhook.h"
#include "hosts.h"
#include <WinSock2.h>
#include <iostream>
#include <algorithm>
#include <Psapi.h>

#pragma comment(lib, "Ws2_32.lib")
#pragma comment(lib, "Psapi.lib")

typedef int (WSAAPI* _getaddrinfo)(
	_In_opt_       PCSTR      pNodeName,
	_In_opt_       PCSTR      pServiceName,
	_In_opt_ const ADDRINFOA  *pHints,
	_Out_          PADDRINFOA *ppResult
	);

typedef int (WSAAPI* _WSASend)(
	_In_  SOCKET                             s,
	_In_  LPWSABUF                           lpBuffers,
	_In_  DWORD                              dwBufferCount,
	_Out_ LPDWORD                            lpNumberOfBytesSent,
	_In_  DWORD                              dwFlags,
	_In_  LPWSAOVERLAPPED                    lpOverlapped,
	_In_  LPWSAOVERLAPPED_COMPLETION_ROUTINE lpCompletionRoutine
);

static _getaddrinfo getaddrinfo_orig;
static _WSASend WSASend_orig;

int WSAAPI getaddrinfo_hook(
	_In_opt_       PCSTR      pNodeName,
	_In_opt_       PCSTR      pServiceName,
	_In_opt_ const ADDRINFOA  *pHints,
	_Out_          PADDRINFOA *ppResult)
{
	if (pNodeName)
	{
		for (size_t i = 0; i < sizeof(HostNames) / sizeof(HostNames[0]); i++)
		{
			if (!_strcmpi(pNodeName, HostNames[i]))
				return WSANO_RECOVERY;
		}
	}
	return getaddrinfo_orig(pNodeName, pServiceName, pHints, ppResult);
}

LPVOID Search(char* pPattern, size_t patternSize, uint8_t* scanStart, size_t scanSize)
{
	__try
	{
		auto res = std::search(
			scanStart, scanStart + scanSize, pPattern, pPattern + patternSize,
			[](uint8_t val1, uint8_t val2) { return (val1 == val2); }
		);

		return (res >= scanStart + scanSize) ? nullptr : res;
	}
	__except (EXCEPTION_EXECUTE_HANDLER) {
		return nullptr;
	}
}

// https://www.unknowncheats.me/forum/1064672-post23.html
bool DataCompare(BYTE* pData, BYTE* bSig, char* szMask)
{
	for (; *szMask; ++szMask, ++pData, ++bSig)
	{
		if (*szMask == 'x' && *pData != *bSig)
			return false;
	}
	return (*szMask) == NULL;
}

BYTE* FindPattern(BYTE* dwAddress, DWORD dwSize, BYTE* pbSig, char* szMask)
{
	DWORD length = strlen(szMask);
	for (DWORD i = NULL; i < dwSize - length; i++)
	{
		__try
		{
			if (DataCompare(dwAddress + i, pbSig, szMask))
				return dwAddress + i;
		}
		__except (EXCEPTION_EXECUTE_HANDLER) {
			return nullptr;
		}
	}
	return 0;
}

#define HOST_STR "Host: "

int WSAAPI WSASend_hook(
	_In_  SOCKET                             s,
	_In_  LPWSABUF                           lpBuffers,
	_In_  DWORD                              dwBufferCount,
	_Out_ LPDWORD                            lpNumberOfBytesSent,
	_In_  DWORD                              dwFlags,
	_In_  LPWSAOVERLAPPED                    lpOverlapped,
	_In_  LPWSAOVERLAPPED_COMPLETION_ROUTINE lpCompletionRoutine
)
{
	if (lpBuffers)
	{
		for (DWORD x = 0; x < dwBufferCount; x++)
		{
			LPVOID res = Search(HOST_STR, sizeof(HOST_STR) - 1, (uint8_t*)lpBuffers[x].buf, lpBuffers[x].len);

			if (res)
			{
				size_t max_len = (uint8_t*)lpBuffers[x].buf + lpBuffers[x].len - (uint8_t*) res;

				for (size_t i = 0; i < sizeof(HostNames) / sizeof(HostNames[0]); i++)
				{
					size_t l = strlen(HostNames[i]);
					if (l < max_len && !_strnicmp((char*)res + sizeof(HOST_STR) - 1, HostNames[i], l))
						return WSAENETUNREACH;
				}
			}
		}
	}

	return WSASend_orig(s, lpBuffers, dwBufferCount, lpNumberOfBytesSent, dwFlags, lpOverlapped, lpCompletionRoutine);
}

void __stdcall LoadAPI(LPVOID* destination, LPCSTR apiName)
{
	if (*destination)
		return;
	
	wchar_t path[MAX_PATH];
	wchar_t windows[MAX_PATH];
	GetSystemDirectoryW(windows, MAX_PATH);
	wsprintf(path, L"%s\\netutils.dll", windows);

	HMODULE hModule = GetModuleHandle(path);
	if (!hModule && !(hModule = LoadLibrary(path)))
		return;
	*destination = GetProcAddress(hModule, apiName);
}

#define API_EXPORT_ORIG(N) \
	static LPVOID _##N = NULL;	\
	char S_##N[] = "" # N; \
	extern "C" __declspec(dllexport) __declspec(naked) void N ## () \
	{ \
		__asm pushad \
		__asm push offset S_##N \
		__asm push offset _##N \
		__asm call LoadAPI \
		__asm popad \
		__asm jmp [_##N] \
	} \

API_EXPORT_ORIG(NetApiBufferAllocate)
API_EXPORT_ORIG(NetApiBufferFree)
API_EXPORT_ORIG(NetApiBufferReallocate)
API_EXPORT_ORIG(NetApiBufferSize)
API_EXPORT_ORIG(NetRemoteComputerSupports)
API_EXPORT_ORIG(NetapipBufferAllocate)
API_EXPORT_ORIG(NetpIsComputerNameValid)
API_EXPORT_ORIG(NetpIsDomainNameValid)
API_EXPORT_ORIG(NetpIsGroupNameValid)
API_EXPORT_ORIG(NetpIsRemote)
API_EXPORT_ORIG(NetpIsRemoteNameValid)
API_EXPORT_ORIG(NetpIsShareNameValid)
API_EXPORT_ORIG(NetpIsUncComputerNameValid)
API_EXPORT_ORIG(NetpIsUserNameValid)
API_EXPORT_ORIG(NetpwListCanonicalize)
API_EXPORT_ORIG(NetpwListTraverse)
API_EXPORT_ORIG(NetpwNameCanonicalize)
API_EXPORT_ORIG(NetpwNameCompare)
API_EXPORT_ORIG(NetpwNameValidate)
API_EXPORT_ORIG(NetpwPathCanonicalize)
API_EXPORT_ORIG(NetpwPathCompare)
API_EXPORT_ORIG(NetpwPathType)

#define API_COPY(M, N) \
	_##N = GetProcAddress(M, #N);


typedef char (__fastcall* _is_skippable)(
	char* This,
	void*
);

typedef int(__fastcall* _can_focus)(
	char* This,
	void*
);

typedef int(__fastcall* _now_playing)(
	char* This,
	void*,
	void* Unk
);


static _is_skippable is_skippable_orig;
static _can_focus can_focus_orig;
static _now_playing now_playing_orig;

static DWORD dwCurrentTrackUriOffset = 0x0;
static LPVOID pfnSkippableStart = NULL;
static char lastPlayingUri[2048] = {0};
static bool skipTrack = false;

__declspec(naked) void is_skippable_hook()
{
	__asm {
		mov eax, 1
		ret
	}
}

_declspec(naked) void can_focus_hook()
{
	__asm {
		xor eax, eax
		ret
	}
}

DWORD WINAPI SkipTrack(LPVOID)
{
	int cnt = 0;
	while (skipTrack && cnt++ < 2)
	{
		Sleep(250);
		if (skipTrack)
		{
			keybd_event(VK_MEDIA_NEXT_TRACK, 0x0, KEYEVENTF_EXTENDEDKEY, NULL);
			keybd_event(VK_MEDIA_NEXT_TRACK, 0x0, KEYEVENTF_EXTENDEDKEY | KEYEVENTF_KEYUP, NULL);
			break;
		}
	}
	return 0;
}

int __fastcall now_playing_hook(char* This, void* Edx, void* Track)
{
	char* szCurrentTrackUri = (char*)*(void**)((char*)Track + dwCurrentTrackUriOffset);

	__try
	{
		if (strncmp(szCurrentTrackUri, lastPlayingUri, 2048))
		{
			strncpy_s(lastPlayingUri, szCurrentTrackUri, 2048);

			// If the now playing track is an ad or interruption, immediately skip using old method (simulating a "skip" media button press)
			if (!strncmp(szCurrentTrackUri, "spotify:ad:", 11) || !strncmp(szCurrentTrackUri, "spotify:interruption:", 21))
			{
				skipTrack = true;
				CreateThread(NULL, 0, SkipTrack, NULL, 0, NULL);
			}
			else
			{
				skipTrack = false;
			}
		}
	} __except (EXCEPTION_EXECUTE_HANDLER) {
	}

	return now_playing_orig(This, Edx, Track);
}

LPVOID FindFunction(char* hModule, DWORD hModuleSize, char* midFuncPtn, int lenMidFuncPtn, int seekBackCount, char* startFuncPtn, int lenStartFuncPtn)
{
	LPVOID pfnAddr = Search(midFuncPtn, lenMidFuncPtn, (uint8_t*) hModule, hModuleSize);
	if (!pfnAddr) return NULL;
	char* pfnStart = NULL;
	char* pfnCurrent = (char*) pfnAddr - seekBackCount;
	while ((pfnCurrent = (char*) Search(startFuncPtn, lenStartFuncPtn, (uint8_t*)pfnCurrent, hModule + hModuleSize - pfnCurrent)) &&
			pfnCurrent < pfnAddr)
	{
		pfnStart = pfnCurrent;
		pfnCurrent++;
	}

	return pfnStart;
}

static char* ZeroString = "0\0";

void Patch(HMODULE hModule, MODULEINFO mInfo)
{
	DWORD d;
	VirtualProtect(hModule, mInfo.SizeOfImage, PAGE_EXECUTE_READWRITE, &d);
	LPVOID hEndOfModule = (uint8_t*)hModule + mInfo.SizeOfImage;

	// Hook skippable function (make all tracks skippable)
	pfnSkippableStart = FindFunction((char*)hModule, mInfo.SizeOfImage, "\x74\x04\xc6\x45\xbf\x01\xf6\xc3\x02\x74\x0b", 11, 1024,
		"\x55\x8b\xec\x6a\xff", 5);

	// fix for 1.0.91.183
	if (!pfnSkippableStart)
		pfnSkippableStart = FindFunction((char*)hModule, mInfo.SizeOfImage, "\x8D\x46\x1C\xC7\x45\xB8\x01\x00\x00\x00\x50\x8D\x45\xC0\x50\xE8", 16, 1024,
			"\x55\x8b\xec\x6a\xff", 5);

	if (pfnSkippableStart)
	{
		is_skippable_orig = (_is_skippable)pfnSkippableStart;
		Mhook_SetHook((PVOID*)&is_skippable_orig, is_skippable_hook);
	}

	// Hook now playing function (determine what current track is playing)
	LPVOID szNowPlaying = Search("now_playing_uri\0", 16, (uint8_t*)hModule, mInfo.SizeOfImage);
	if (szNowPlaying) {
		char szNowPlayingPattern[7];
		strcpy_s(szNowPlayingPattern, "\x6a\x0f\x68\x00\x00\x00\x00");
		memcpy(szNowPlayingPattern + 3, &szNowPlaying, sizeof(LPVOID));

		LPVOID pfnNowPlaying = FindFunction((char*)hModule, mInfo.SizeOfImage, szNowPlayingPattern, 7, 1024,
			"\x55\x8b\xec\x6a\xff", 5);

		if (pfnNowPlaying)
		{
			LPVOID pfnUriPtn = Search("\x6a\xff\x8d\x87", 4, (uint8_t*)pfnNowPlaying, (char*)hEndOfModule - (char*)pfnNowPlaying);

			// fix for 1.0.91.183
			if (!pfnUriPtn)
				pfnUriPtn = Search("\x74\x1a\x8d\x86", 4, (uint8_t*)pfnNowPlaying, (char*)hEndOfModule - (char*)pfnNowPlaying);

			if (pfnUriPtn)
			{
				dwCurrentTrackUriOffset = *(DWORD*)((char*)pfnUriPtn + 4);
				now_playing_orig = (_now_playing)pfnNowPlaying;
				Mhook_SetHook((PVOID*)&now_playing_orig, now_playing_hook);
			}
		}
	}

	// Hook focus function (disable focus for ads)
	LPVOID pfnRequireFocus = (uint8_t*)hModule;
	while ((pfnRequireFocus = Search("\x8d\x46\x40\x50\x8d\x45\xc0\x50\xe8", 9, (uint8_t*)pfnRequireFocus, (char*)hEndOfModule - (char*)pfnRequireFocus)))
	{
		if (*((char*)pfnRequireFocus - 5) == 0x68 &&
			!strcmp((char*)*(LPVOID*)((char*)pfnRequireFocus - 4), "require_focus"))
		{
			// Find the start of the function
			LPVOID pfnRequireFocusStart = NULL;
			LPVOID pfnRequireFocusCurrent = (char*)pfnRequireFocus - 500;
			while ((pfnRequireFocusCurrent = Search("\x55\x8b\xec\x6a\xff", 5, (uint8_t*)pfnRequireFocusCurrent, (char*)hEndOfModule - (char*)pfnRequireFocusCurrent)) &&
				pfnRequireFocusCurrent < pfnRequireFocus)
			{
				pfnRequireFocusStart = pfnRequireFocusCurrent;
				pfnRequireFocusCurrent = (char*)pfnRequireFocusCurrent + 1;
			}
			if (pfnRequireFocusStart)
			{
				can_focus_orig = (_can_focus)pfnRequireFocusStart;
				Mhook_SetHook((PVOID*)&can_focus_orig, can_focus_hook);
				break;
			}
		}
		pfnRequireFocus = (char*)pfnRequireFocus + 1;
	}

	uint8_t* cur = (uint8_t*)hModule;
	uint8_t* end = cur + mInfo.SizeOfImage;

	while (cur < end)
	{
		MEMORY_BASIC_INFORMATION mbi;
		VirtualQuery(cur, &mbi, sizeof(mbi));
		if (mbi.Protect & PAGE_EXECUTE_READ ||
			mbi.Protect & PAGE_EXECUTE_READWRITE ||
			mbi.Protect & PAGE_READWRITE ||
			mbi.Protect & PAGE_READONLY ||
			mbi.Protect & PAGE_EXECUTE_WRITECOPY)
		{
			// Patch 5 second minimum wait to skip video ads
			LPVOID skipStuckSeconds = (LPVOID)FindPattern((uint8_t*)mbi.BaseAddress, mbi.RegionSize, (BYTE*) "\x83\xc4\x08\x6a\x00\x68\xe8\x03\x00\x00\xff\x70\x04\xff\x30\xe8\x00\x00\x00\x00\x8d\x4d\xc0", "xxxxxxxxxxxxxxxx????xxx");
			int oneThousandMsOffset = 6;

			// fix for 1.0.91.183
			if (!skipStuckSeconds)
			{
				skipStuckSeconds = (LPVOID)FindPattern((uint8_t*)mbi.BaseAddress, mbi.RegionSize, (BYTE*) "\xb9\xe8\x03\x00\x00\xf7\xe9\x83\xc4\x1c", "xxxxxxxxxx");
				oneThousandMsOffset = 1;
			}
			if (skipStuckSeconds)
			{
				DWORD oldProtect;
				VirtualProtect((char*)skipStuckSeconds + oneThousandMsOffset, 4, PAGE_EXECUTE_READWRITE, &oldProtect);
				*(DWORD*)((char*)skipStuckSeconds + oneThousandMsOffset) = 0;
				VirtualProtect((char*)skipStuckSeconds + oneThousandMsOffset, 4, oldProtect, &oldProtect);
				break;
			}
		}
		cur = (uint8_t*)mbi.BaseAddress + mbi.RegionSize;
	}
}

void PatchNet()
{
	HMODULE hModule = GetModuleHandle(L"ws2_32.dll");
	if (!hModule)
		hModule = LoadLibrary(L"ws2_32.dll");

	if (hModule)
	{
		getaddrinfo_orig = (_getaddrinfo)GetProcAddress(hModule, "getaddrinfo");
		if (getaddrinfo_orig)
			Mhook_SetHook((PVOID*)&getaddrinfo_orig, getaddrinfo_hook);
		WSASend_orig = (_WSASend)GetProcAddress(hModule, "WSASend");
		if (WSASend_orig)
			Mhook_SetHook((PVOID*)&WSASend_orig, WSASend_hook);
	}
}

void PatchAdMain(HMODULE hModule, MODULEINFO mInfo)
{
	// fix for 1.0.91.183
	LPVOID adMissingIdAddr = FindPattern((uint8_t*)hModule, mInfo.SizeOfImage, (BYTE*) "\x84\xC0\x0F\x85\x00\x00\x00\x00\x6A\x0D\x68", "xxxx????xxx");
	int adMissingNopOffset = 2;
	int adMissingNopCount = 6;

	// fallback old version
	if (!adMissingIdAddr) {
		adMissingIdAddr = FindPattern((uint8_t*)hModule, mInfo.SizeOfImage, (BYTE*) "\x84\xc0\x75\x00\x6a\x0d\x68", "xxx?xxx");
		adMissingNopOffset = 2, adMissingNopCount = 2;
	}
	if (adMissingIdAddr)
	{
		DWORD oldProtect;
		VirtualProtect((char*)adMissingIdAddr + adMissingNopOffset, adMissingNopCount, PAGE_EXECUTE_READWRITE, &oldProtect);
		memset((char*)adMissingIdAddr + adMissingNopOffset, 0x90, adMissingNopCount);
		VirtualProtect((char*)adMissingIdAddr + adMissingNopOffset, adMissingNopCount, oldProtect, &oldProtect);
	}
}

void WriteAll(HMODULE hModule, MODULEINFO mInfo)
{
	uint8_t* cur = (uint8_t*)hModule;
	uint8_t* end = cur + mInfo.SizeOfImage;

	while (cur < end)
	{
		MEMORY_BASIC_INFORMATION mbi;
		VirtualQuery(cur, &mbi, sizeof(mbi));
		if (!(mbi.Protect & PAGE_GUARD)) {
			DWORD dwOldProtect;
			if (!VirtualProtect(mbi.BaseAddress, mbi.RegionSize, PAGE_EXECUTE_READWRITE, &dwOldProtect) &&
				mbi.Type & MEM_MAPPED)
				VirtualProtect(mbi.BaseAddress, mbi.RegionSize, PAGE_EXECUTE_WRITECOPY, &dwOldProtect);
		}
		cur = (uint8_t*)mbi.BaseAddress + mbi.RegionSize;
	}
}

DWORD WINAPI MainThread(LPVOID)
{
	// Block known ad hosts via function hooks
	__try {
		PatchNet();
	}
	__except (EXCEPTION_EXECUTE_HANDLER)
	{
	}

	HMODULE hModule = GetModuleHandle(NULL);
	MODULEINFO mInfo = { 0 };
	if (GetModuleInformation(GetCurrentProcess(), hModule, &mInfo, sizeof(MODULEINFO))) {
		// Attempt to make entire module writable
		__try {
			WriteAll(hModule, mInfo);
		}
		__except (EXCEPTION_EXECUTE_HANDLER)
		{
		}

		// Perform fallback patches (just in-case the main method fails)
		__try {
			Patch(hModule, mInfo);
		}
		__except (EXCEPTION_EXECUTE_HANDLER)
		{
		}

		// Perform main ad patch
		__try {
			PatchAdMain(hModule, mInfo);
		}
		__except (EXCEPTION_EXECUTE_HANDLER)
		{
		}
	}
	return 0;
}

BOOL APIENTRY DllMain( HMODULE hModule,
                       DWORD  ul_reason_for_call,
                       LPVOID lpReserved
					 )
{
	switch (ul_reason_for_call)
	{
	case DLL_PROCESS_ATTACH:
		DisableThreadLibraryCalls(hModule);

		// Only patch the main process and none of the renderers/workers
		if (!wcsstr(GetCommandLine(), L"--type="))
			CreateThread(NULL, NULL, MainThread, NULL, 0, NULL);
		break;
	}
	return TRUE;
}

