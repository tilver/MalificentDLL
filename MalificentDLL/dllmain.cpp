// dllmain.cpp : Defines the entry point for the DLL application.
#include "stdafx.h"
#include "keepalive.h"
#include "effects.h"
#include "packetwatch.h"

BOOL APIENTRY DllMain( HMODULE hModule,
                       DWORD  ul_reason_for_call,
                       LPVOID lpReserved
                     )
{
    switch (ul_reason_for_call)
    {
    case DLL_PROCESS_ATTACH:
		break;
    case DLL_THREAD_ATTACH:
		return TRUE;
    case DLL_THREAD_DETACH:
		return TRUE;
    case DLL_PROCESS_DETACH:
		return TRUE;
        break;
    }

//	KeepAlive ka;
	Effects ef;
	PacketWatch pw;

//	ka.start();
	ef.start();
	pw.start();
//	while (1 == 1) {
//		Sleep(10000);
//	}
	std::cout << "DLL Main Called\n";

    return TRUE;
}

