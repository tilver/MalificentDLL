#pragma once

#include "stdafx.h"

//Meat of the application.  Doing all the interesting things

class Effects {
private:
	HANDLE mythread;
public:
	Effects();
	~Effects();
	void start();
	DWORD WINAPI mymain(LPVOID lpParam);
	void implement();
};