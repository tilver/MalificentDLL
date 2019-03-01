#include "stdafx.h"
#include "effects.h"


Effects::Effects()
{
}

Effects::~Effects()
{
}

void effects_trampoline(Effects *p) {
	std::cout << "trampoline with pointer of" << p << "\n";
	p->mymain(NULL);
}


void Effects::start()
{
	std::cout << "starting Effects Thread\n";
	mythread = CreateThread(
		NULL,
		0,
		(PTHREAD_START_ROUTINE)effects_trampoline,
		this,
		0,
		0
	);
}

DWORD WINAPI Effects::mymain(LPVOID lpParam)
{
	//I am the master of the thread created in start
	while (1 == 1) {
		//MessageBox(NULL, (LPCWSTR)L"Thread Ran", (LPCWSTR)L"Caption", MB_OK);
		std::cout << "Effects::mymain Thread Ran\n";
		Sleep(60000);
	}

}
void Effects::implement()
{
}
