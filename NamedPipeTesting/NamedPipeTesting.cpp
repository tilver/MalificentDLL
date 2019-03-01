// NamedPipeTesting.cpp : This file contains the 'main' function. Program execution begins and ends there.
//

#include "pch.h"
#include <iostream>
#include <Windows.h>


#define BUFFERSIZE 1024

int main()
{
	HANDLE hPipe;

	const char *Pipename = "\\\\.\\pipe\\MyPipe";
	BOOL fConnected, fSuccess;
	char buffer[BUFFERSIZE];
	DWORD countbytesread;
	DWORD countbyteswritten;
	int ErrorHolder;

	//At this point we don't know if we're master or child, assume child
	BOOL master = false;

	while (true)
	{
		/*hPipe = CreateNamedPipeA(
			Pipename,
			PIPE_ACCESS_DUPLEX, //dwOpenMode
			PIPE_TYPE_MESSAGE | PIPE_READMODE_MESSAGE | PIPE_NOWAIT, //dsPipeMode
			PIPE_UNLIMITED_INSTANCES, //nMaxInstances
			BUFFERSIZE, //OutBufferSize
			BUFFERSIZE, //InBufferSize
			50, //nDefaultTimeOut
			NULL //Security Attributes
		); */

		hPipe = CreateNamedPipeA(Pipename,
//			PIPE_ACCESS_OUTBOUND | 
			PIPE_ACCESS_DUPLEX,
//			FILE_FLAG_FIRST_PIPE_INSTANCE |  //Master works
//			FILE_FLAG_OVERLAPPED,          // read/write access
			PIPE_TYPE_MESSAGE |             // message type pipe
			PIPE_READMODE_MESSAGE |         // message-read mode
			PIPE_NOWAIT,                          // blocking mode
			PIPE_UNLIMITED_INSTANCES,   // max. instances
			BUFFERSIZE,                        // output buffer size
			BUFFERSIZE,                        // input buffer size
			2000,                 // client time-out
			NULL);

		if (hPipe == INVALID_HANDLE_VALUE)
		{
			ErrorHolder = GetLastError();
			if (ErrorHolder == ERROR_PIPE_BUSY)
			{
				if (!WaitNamedPipeA(Pipename, NMPWAIT_USE_DEFAULT_WAIT))
					continue;   // timeout, try again
			}
			else if (ErrorHolder == ERROR_ACCESS_DENIED) {
				//We're the client (second to pipe)
				hPipe = CreateFileA(Pipename,
					GENERIC_READ | GENERIC_WRITE,
					FILE_SHARE_READ | FILE_SHARE_WRITE,
					NULL,
//					OPEN_EXISTING,
					CREATE_NEW,  //Open_EXISTING was there, but trying this.
					0,
					NULL);
				if (hPipe == INVALID_HANDLE_VALUE) {
					std::cout << "CreateFile (client) failed with " << GetLastError() << "\n";
				}
				break;
			}
				return false;   // error
		}
		else
			break;   // success
	}

	fConnected = false;
	while (!fConnected) {
		std::cout << "Waiting for connect\n";

		//Waits for someone else to connect.
		fConnected = ConnectNamedPipe(hPipe, NULL);

		Sleep(1000);
		
	}

	std::cout << "Got Connection";

	strncpy_s(buffer, "Master", strlen("Master"));

	while (strncmp(buffer, "quit", strlen("quit")) != 0) {
		fSuccess = ReadFile(hPipe, buffer, 1024, &countbytesread, NULL);
		if (fSuccess) {
			std::cout << "The number of bytes read is " << countbytesread << "\n";
		}

		strncpy_s(buffer, "Master", strlen("Master"));
		WriteFile(hPipe, buffer, strlen(buffer), &countbyteswritten, NULL);

		Sleep(10000);
	}

    std::cout << "Quitting!\n"; 
}


// Run program: Ctrl + F5 or Debug > Start Without Debugging menu
// Debug program: F5 or Debug > Start Debugging menu

// Tips for Getting Started: 
//   1. Use the Solution Explorer window to add/manage files
//   2. Use the Team Explorer window to connect to source control
//   3. Use the Output window to see build output and other messages
//   4. Use the Error List window to view errors
//   5. Go to Project > Add New Item to create new code files, or Project > Add Existing Item to add existing code files to the project
//   6. In the future, to open this project again, go to File > Open > Project and select the .sln file
