#pragma once

#include "stdafx.h"

class Friend {
public:
	Friend();
	~Friend();
private:
	int processhandle;

};

class KeepAlive {
private:
	HANDLE mythread;
	int master;
public:
	KeepAlive();
	~KeepAlive();
	void start();
    DWORD WINAPI mymain(LPVOID lpParam);
	void quit();
	void make_child();
	int pick_new_friend();
	Friend spawn_friend(int processid);
	bool check_friend(Friend f);
};

