#include "stdafx.h"
#include "keepalive.h"
#include <ctime>

#pragma comment (lib, "Ws2_32.lib")

Friend::Friend()
{
}

Friend::~Friend()
{
}

KeepAlive::KeepAlive()
{
	master = 0;
}

KeepAlive::~KeepAlive()
{
}

//Thread reference is: https://docs.microsoft.com/en-us/windows/desktop/procthread/creating-threads

//Trampoline - for thread creation
void keepalive_trampoline(KeepAlive *p) {
	std::cout << "trampoline with pointer of" << p << "\n"; 
	p->mymain(NULL);
}


void KeepAlive::start()
{
	std::cout << "starting KeepAlive Thread\n";
	mythread =  CreateThread(
		NULL,
		0,
		(PTHREAD_START_ROUTINE) keepalive_trampoline,
		this,
		0,
		0
	);
}

DWORD WINAPI KeepAlive::mymain(LPVOID lpParam) {
	//Unfortunately going to UDP Client / Listener format because named pipes are too cryptic.

	//Init Winsock
	WSADATA wsaData;
	WSAStartup(MAKEWORD(2, 2), &wsaData);

	SOCKET socketS;
	char buffer[2024];

	const int MYPORT = 8888;

	struct sockaddr_in local;
	struct sockaddr_in from;
	int fromlen = sizeof(from);

	local.sin_family = AF_INET;
	local.sin_port = htons(MYPORT); // UDP PORT Currently 8888 defined above
	local.sin_addr.s_addr = INADDR_LOOPBACK;

	socketS = socket(AF_INET, SOCK_DGRAM, 0);  // Not sure why protocol parm is zero, but from example so going with it.
	bind(socketS, (sockaddr *)&local, sizeof(local));

	//This time is should be able to do a select
	FD_SET fds;
	int total;


	//This is stuff left over where trying to do select stuff.
	//https://stackoverflow.com/questions/9596014/select-sometimes-does-not-wait
	//Have to do a lastpacketseenatwhattime scenario

	timeval timeout;
	timeout.tv_sec = 5;

	clock_t lpsawt;
	int failcount = 0;
	lpsawt = clock();

	while (1 == 1) {

		ZeroMemory(buffer, sizeof(buffer));
		FD_ZERO(&fds);

		FD_SET(socketS, &fds);		

		if ((total = select(0, &fds, NULL, NULL, &timeout) == SOCKET_ERROR)) {
			std::cout << "Select failed.\n";
		}
		else {
			if (FD_ISSET(socketS, &fds)) {
				recvfrom(socketS, buffer, sizeof(buffer), 0, (sockaddr *)&from, &fromlen);
				failcount = 0;
				lpsawt = clock();
			}
			else {
				if (failcount < 4) {
					if (((clock() - lpsawt) / CLOCKS_PER_SEC) > 5) {
						failcount++;
						std::cout << "Nothing received.  Failcount:" << failcount << "\n";

						std::cout << "last packet: " << lpsawt << " and clock is: " << clock() << "\n";
						lpsawt = clock();
					}
					else {
						//std::cout << "Clocks per sec is " << CLOCKS_PER_SEC << "\n";
						//std::cout << "last packet: " << lpsawt << " and clock is: " << clock() << "\n";
					}
				}
				else {
					//Timed out for fourth time.
					//If master we need a new client.
					//If client we are now master.... and need a new client.
					if (master == 0) {
						std::cout << "Becomming master.\n";
						failcount = 0;
						lpsawt = clock();
						make_child();

					}
					else {
						std::cout << "Master needs child.\n";
						failcount = 0;
						lpsawt = clock();
						make_child();
					}
				}
			}
		}

		//std::cout << "KeepAlive::mymain Looped\n";
		//Sleep(60000);
	}

}

/*DWORD WINAPI KeepAlive::mymain(LPVOID lpParam)
{

	//I am the master of the thread created in start

	//If I can create a pipe then I'm the master.  

	HANDLE hPipe;
	const char *Pipename = "\\\\.\\pipe\\MyPipe";
	BOOL fConnected, fSuccess;
	char buffer[1024];
	DWORD countbytesread;
	DWORD countbyteswritten;

	//At this point we don't know if we're master or child, assume child
	BOOL master = false;

	hPipe = CreateNamedPipeA(
		Pipename,
		PIPE_ACCESS_DUPLEX | FILE_FLAG_FIRST_PIPE_INSTANCE, //dwOpenMode
		PIPE_TYPE_MESSAGE | PIPE_READMODE_MESSAGE | PIPE_NOWAIT, //dsPipeMode
		1, //nMaxInstances
		1024, //OutBufferSize
		1024, //InBufferSize
		50, //nDefaultTimeOut
		NULL //Security Attributes
		);

	if (hPipe == INVALID_HANDLE_VALUE) {
		if (GetLastError() == ERROR_ACCESS_DENIED) {
			master = false;
		}
		// Create will fail if already exists.
		//std::cout << "Invalid Handle... No idea what to do next... return I suppose.\n";
		//return 0;
	}
	else {
		master = true;
	}

	fd_set fds; // File descript stuff for select call
	int maxfd;
    timeval timeout;
	timeout.tv_sec = 20;

	while (1 == 1) {

		fConnected = ConnectNamedPipe(hPipe, NULL);
		
		if (fConnected) {

			//FD_ZERO(&fds);
			//FD_SET(hPipe, &fds);
			//maxfd = (int)hPipe;


			//select(maxfd + 1, &fds, NULL, NULL, &timeout);

			if (FD_ISSET(hPipe, &fds)) {
				fSuccess = ReadFile(hPipe, buffer, 1024, &countbytesread, NULL);
				buffer[countbytesread] = '\0';
			}
			else { // Timed out, takeover as master.
				master = true;
				strcpy(buffer, "Master");
				WriteFile(hPipe, buffer, strlen(buffer), &countbyteswritten, NULL);
			}
		}

		if (fSuccess) {
			std::cout << "Read from pipe: " << buffer << "\n";
			if (strstr(buffer, "Master") >= 0) {
				//Saw a master message
				//Write a client message and continue
				master = false;
				strcpy(buffer, "Client");
				WriteFile(hPipe, buffer, strlen(buffer), &countbyteswritten, NULL);
			}
		}

		//MessageBox(NULL, (LPCWSTR)L"Thread Ran", (LPCWSTR)L"Caption", MB_OK);
		std::cout << "KeepAlive::mymain Looped\n";
		//Don't think I want a sleep here anymore.
		//Sleep(60000);
	}
}
*/

void KeepAlive::quit()
{
}

void KeepAlive::make_child() {

}

int KeepAlive::pick_new_friend()
{

	return 0;
}

Friend KeepAlive::spawn_friend(int processid)
{
	return Friend();
}

bool KeepAlive::check_friend(Friend f)
{
	return false;
}
