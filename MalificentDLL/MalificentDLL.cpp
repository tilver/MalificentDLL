// MalificentDLL.cpp : Defines the exported functions for the DLL application.
//

#include "stdafx.h"


__declspec(dllexport) BOOL APIENTRY DllMain(HMODULE hModule,
	DWORD  ul_reason_for_call,
	LPVOID lpReserved
);

__declspec(dllexport) void init() {
	return;
}