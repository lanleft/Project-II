// MultipleIOCRServer.cpp : This file contains the 'main' function. Program execution begins and ends there.
//

#include <winsock2.h>
#include <windows.h>
#include <stdio.h> 
#include <process.h>
#include <WS2tcpip.h>
#include <time.h>
#include <stdlib.h>

#pragma warning(disable:4996)
#pragma comment(lib, "Ws2_32.lib")

#define RECEIVE 0
#define SEND 1
#define PORT 6000
#define DATA_BUFSIZE 8192
#define MAX_CLIENT 1024
#define BUFF_SIZE 1024

/*Struct contains information of the socket communicating with client*/
typedef struct SocketInfo {
	WSAOVERLAPPED overlapped;
	SOCKET socket;
	WSABUF dataBuf;
	char buffer[DATA_BUFSIZE];
	int operation;
	int sentBytes;
	int recvBytes;
	char ip[INET_ADDRSTRLEN];
	int port;
	char user[256];
	char post[BUFF_SIZE];
	bool stt_login;
};

void CALLBACK workerRoutine(DWORD error, DWORD transferredBytes, LPWSAOVERLAPPED overlapped, DWORD inFlags);
unsigned __stdcall IoThread(LPVOID lpParameter);
void processData(SocketInfo*, char*, char*);
int loginSession(SocketInfo*, char*);
int postSession(SocketInfo*, char*);
int logoutSession(SocketInfo*);
char* getTime();
int checkUser(char*);
void writeLog(int, SocketInfo*, int);


SOCKET acceptSocket;
SocketInfo* clients[MAX_CLIENT];
int nClients = 0;
CRITICAL_SECTION criticalSection;

SOCKADDR_IN serverAddr, clientAddr;
int clientAddrLen = sizeof(clientAddr);

int main()
{
	WSADATA wsaData;
	SOCKET listenSocket;	
	INT ret;
	WSAEVENT acceptEvent;

	InitializeCriticalSection(&criticalSection);

	if ((ret = WSAStartup((2, 2), &wsaData)) != 0) {
		printf("WSAStartup() failed with error %d\n", ret);
		WSACleanup();
		return 1;
	}

	if ((listenSocket = WSASocket(AF_INET, SOCK_STREAM, 0, NULL, 0, WSA_FLAG_OVERLAPPED)) == INVALID_SOCKET) {
		printf("Failed to get a socket %d\n", WSAGetLastError());
		return 1;
	}

	serverAddr.sin_family = AF_INET;
	serverAddr.sin_addr.s_addr = htonl(INADDR_ANY);
	serverAddr.sin_port = htons(PORT);
	if (bind(listenSocket, (PSOCKADDR)&serverAddr, sizeof(serverAddr)) == SOCKET_ERROR) {
		printf("bind() failed with error %d\n", WSAGetLastError());
		return 1;
	}

	if (listen(listenSocket, 20)) {
		printf("listen() failed with error %d\n", WSAGetLastError());
		return 1;
	}

	printf("Server started!\n");

	if ((acceptEvent = WSACreateEvent()) == WSA_INVALID_EVENT) {
		printf("WSACreateEvent() failed with error %d\n", WSAGetLastError());
		return 1;
	}

	// Create a worker thread to service completed I/O requests	
	_beginthreadex(0, 0, IoThread, (LPVOID)acceptEvent, 0, 0);

	while (TRUE) {
		if ((acceptSocket = accept(listenSocket, (PSOCKADDR)&clientAddr, &clientAddrLen)) == SOCKET_ERROR) {
			printf("accept() failed with error %d\n", WSAGetLastError());
			return 1;
		}

		if (WSASetEvent(acceptEvent) == FALSE) {
			printf("WSASetEvent() failed with error %d\n", WSAGetLastError());
			return 1;
		}
	}
	return 0;
}

unsigned __stdcall IoThread(LPVOID lpParameter)
{
	DWORD flags;
	WSAEVENT events[1];
	DWORD index;
	DWORD recvBytes;

	// Save the accept event in the event array
	events[0] = (WSAEVENT)lpParameter;
	while (TRUE) {
		// Wait for accept() to signal an event and also process workerRoutine() returns
		while (TRUE) {
			index = WSAWaitForMultipleEvents(1, events, FALSE, WSA_INFINITE, TRUE);
			if (index == WSA_WAIT_FAILED) {
				printf("WSAWaitForMultipleEvents() failed with error %d\n", WSAGetLastError());
				return 1;
			}

			if (index != WAIT_IO_COMPLETION) {
				// An accept() call event is ready - break the wait loop
				break;
			}
		}

		WSAResetEvent(events[index - WSA_WAIT_EVENT_0]);

		EnterCriticalSection(&criticalSection);

		if (nClients == MAX_CLIENT) {
			printf("Too many clients.\n");
			closesocket(acceptSocket);
			continue;
		}

		// Create a socket information structure to associate with the accepted socket
		if ((clients[nClients] = (SocketInfo*)GlobalAlloc(GPTR, sizeof(SocketInfo))) == NULL) {
			printf("GlobalAlloc() failed with error %d\n", GetLastError());
			return 1;
		}

		// Fill in the details of our accepted socket
		clients[nClients]->socket = acceptSocket;
		sprintf(clients[nClients]->ip, "%s", inet_ntoa(clientAddr.sin_addr));		// get client's IP
		clients[nClients]->port = ntohs(clientAddr.sin_port);
		clients[nClients]->stt_login = 0;

		memset(&clients[nClients]->overlapped, 0, sizeof(WSAOVERLAPPED));
		clients[nClients]->sentBytes = 0;
		clients[nClients]->recvBytes = 0;
		clients[nClients]->dataBuf.len = DATA_BUFSIZE;
		clients[nClients]->dataBuf.buf = clients[nClients]->buffer;
		clients[nClients]->operation = RECEIVE;
		flags = 0;

		if (WSARecv(clients[nClients]->socket, &(clients[nClients]->dataBuf), 1, &recvBytes,
			&flags, &(clients[nClients]->overlapped), workerRoutine) == SOCKET_ERROR) {
			if (WSAGetLastError() != WSA_IO_PENDING) {
				printf("WSARecv() failed with error %d\n", WSAGetLastError());
				return 1;
			}
		}
		
		printf("Socket %d got connected...\n", acceptSocket);
		nClients++;
		LeaveCriticalSection(&criticalSection);
	}

	return 0;
}

void CALLBACK workerRoutine(DWORD error, DWORD transferredBytes, LPWSAOVERLAPPED overlapped, DWORD inFlags)
{
	DWORD sendBytes, recvBytes;
	DWORD flags;

	// Reference the WSAOVERLAPPED structure as a SOCKET_INFORMATION structure
	SocketInfo* sockInfo = (SocketInfo*)overlapped;

	if (error != 0)
		printf("I/O operation failed with error %d\n", error);

	else if (transferredBytes == 0)
		printf("Closing socket %d\n\n", sockInfo->socket);

	if (error != 0 || transferredBytes == 0) {
		//Find and remove socket
		EnterCriticalSection(&criticalSection);

		int index;
		for (index = 0; index < nClients; index++)
			if (clients[index]->socket == sockInfo->socket)
				break;

		closesocket(clients[index]->socket);
		memset(&clients[index]->ip, 0, sizeof(INET_ADDRSTRLEN));
		memset(&clients[index]->user, 0, 256);
		clients[index]->port = 0;
		clients[index]->stt_login = 0;

		GlobalFree(clients[index]);
		clients[index] = 0;

		for (int i = index; i < nClients - 1; i++)
			clients[i] = clients[i + 1];
		nClients--;

		LeaveCriticalSection(&criticalSection);

		return;
	}

	// Check to see if the recvBytes field equals zero. If this is so, then
	// this means a WSARecv call just completed so update the recvBytes field
	// with the transferredBytes value from the completed WSARecv() call	
	if (sockInfo->operation == RECEIVE) {
		sockInfo->recvBytes = transferredBytes;
		sockInfo->sentBytes = 0;
		sockInfo->operation = SEND;

		char error_code[10];
		memset(error_code, 0, 10);
		processData(sockInfo, sockInfo->buffer, error_code);
		//printf("error_code: %s\n", error_code);
		sockInfo->dataBuf.len = strlen(error_code);
		ZeroMemory(sockInfo->dataBuf.buf, DATA_BUFSIZE);
		memcpy(sockInfo->dataBuf.buf, error_code, 2);
	}
	else {
		sockInfo->sentBytes += transferredBytes;
	}

	if (sockInfo->recvBytes > sockInfo->sentBytes) {
		// Post another WSASend() request.
		// Since WSASend() is not guaranteed to send all of the bytes requested,
		// continue posting WSASend() calls until all received bytes are sent
		ZeroMemory(&(sockInfo->overlapped), sizeof(WSAOVERLAPPED));
		sockInfo->dataBuf.buf = sockInfo->buffer + sockInfo->sentBytes;
		sockInfo->dataBuf.len = sockInfo->recvBytes - sockInfo->sentBytes;
		sockInfo->operation = SEND;
		if (WSASend(sockInfo->socket, &(sockInfo->dataBuf), 1, &sendBytes, 0, &(sockInfo->overlapped), workerRoutine) == SOCKET_ERROR) {
			if (WSAGetLastError() != WSA_IO_PENDING) {
				printf("WSASend() failed with error %d\n", WSAGetLastError());
				return;
			}
		}
	}
	else {
		// Now that there are no more bytes to send post another WSARecv() request
		sockInfo->recvBytes = 0;
		flags = 0;
		ZeroMemory(&(sockInfo->overlapped), sizeof(WSAOVERLAPPED));
		sockInfo->dataBuf.len = DATA_BUFSIZE;
		sockInfo->dataBuf.buf = sockInfo->buffer;
		sockInfo->operation = RECEIVE;
		if (WSARecv(sockInfo->socket, &(sockInfo->dataBuf), 1, &recvBytes, &flags, &(sockInfo->overlapped), workerRoutine) == SOCKET_ERROR) {
			if (WSAGetLastError() != WSA_IO_PENDING) {
				printf("WSARecv() failed with error %d\n", WSAGetLastError());
				return;
			}
		}
		
	}
}


/* my protocol like this:
LOGIN		10: Login successed
			11: User does not exit
			12: User is blocked
			13: User is logged in other device
			14: You have not logged out
----------------------------------------------------
POST		20: Post successed
			21: You have not logged in
----------------------------------------------------
LOGOUT		30: Log out successed
			31: You have not logged in
----------------------------------------------------
OTHER		41: Invalid chosen
			42: Data is lost during transmission
*/

/* The processData function copies the input string to output
* @param in Pointer to input string
* @param out Pointer to output string
* @return No return value
*/
void processData(SocketInfo* client, char* in, char* out) {
	int sizeData = 0;
	int code_error;

	memset(out, 0, sizeof(out));
	// stream processing
	memcpy(&sizeData, in, 2);
	sizeData -= 3;
	//printf("data1: %s\n", (in+3));
	//printf("sizeDAta: %d\n", sizeData);
	if (sizeData != strlen(in+3)) {
		sprintf(out, "%d", 42);
		return;
	}

	//for (int i = 0; i < sizeData + 3; i++) printf("%x ", in[i]);
	//printf("\n");
	char c = in[2];
	//printf("in: %s\n", in);
	//printf("c: %c\n", c);
	switch (c)
	{
	case 1:	// login
		code_error = loginSession(client, in+3);
		writeLog(1, client, code_error);
		break;
	case 2: // post
		code_error = postSession(client, in+3);
		writeLog(2, client, code_error);
		break;
	case 3: // logout
		code_error = logoutSession(client);
		writeLog(3, client, code_error);
		break;
	default:	// otherwise
		code_error = 41;
		break;
	}
	
	sprintf(out, "%d", code_error);
	return;
}

/* The getTime function get the time at the current time
* No param
* @return: string date/mounth/year and hour/min/sec at the time the function is called
*/
char* getTime()
{
	char* str_time;
	time_t t = time(NULL);
	struct tm tm = *localtime(&t);

	str_time = (char*)malloc(256);
	sprintf(str_time, "%d/%0d/%0d %02d:%02d:%02d", tm.tm_mday, tm.tm_mon + 1, tm.tm_year + 1900, tm.tm_hour, tm.tm_min, tm.tm_sec);

	return str_time;
}

/* The loginSession function is processed when a user wants to login PostRoom
* @param1: SocketInfo* nclients[] is a list of clients connected server
* @param2: SocketInfo* clients is a client connected in this session
* @param3: char* buff is a buffer which is stored client's data
* @return: The function return code error when user is logged in or otherwise
*/
int loginSession(SocketInfo* client, char* buff)
{
	memset(client->user, 0, sizeof(client->user));

	// check if other devices login with the same user
	printf("nClients: %d\n", nClients);
	for (int i = 0; i < nClients; i++) {
		if (!strcmp(clients[i]->user, buff))
			return 13;
	}
	// copy username from client's data to client's struct in server
	memcpy(client->user, buff, sizeof(client->user));
	if (client->stt_login == 1)
		return 14;
	int nUser = checkUser(buff);
	switch (nUser)
	{
	case 200:
		return 12;
	case 201:
		return 11;
	default:
		client->stt_login = 1;
		return 10;
	}
}

/* The postSession function is processed when user wants to post something into PostRoom
* @param1: SocketInfo* client is the client's session
* @param2: char* buff is the client's data (something that client want to post, such as: status, message, etc)
* @return: this function return the code error which is defined success or fail.
*/
int postSession(SocketInfo* client, char* buff)
{
	if (client->stt_login == 0)	// client have not login, so they cant post anything in PostRoom
		return 21;
	else {
		memcpy(client->post, buff, sizeof(client->post)); // stored post in client's struct 
		return 20;
	}
}

/* The logoutSession is processed when user wants to logout of this session
* @param1: SocketInfo* client is the client's session
* @return: this function return code error when client logouted, like this:
* 30: success
* 31: fail (may be you dont login)
*/
int logoutSession(SocketInfo* client)
{
	if (client->stt_login == 1) {
		memset(client->user, 0, sizeof(client->user));
		client->stt_login = 0;
		return 30;
	}
	else
		return 31;
}

/* The checkUser function is processed when user login. It checks the user in the database
* and the current status of that account
* @param1: char*name is the buffer that stored username
* @return: code error of account that i want to check, like this:
* 201: this account dont exist
* 200: this account is blocked
* other: this account exists and dont blocked
*/
int checkUser(char* name)
{
	char str[100];
	int i = 0;
	FILE* acc = fopen("account.txt", "r");

	if (acc == NULL) {
		puts("Error while opening the file");
		exit(1);
	}

	// read all user in file
	while (fgets(str, 256, acc) != NULL)
	{
		if (memcmp(str, name, strlen(name)) == 0) {
			fclose(acc);
			if (str[strlen(name) + 1] == '0')
				return i;
			else
				return 200;
		}
		i++;
	}
	fclose(acc);
	return 201;
}

/* The writeLog function writes log into file name log_20183781.txt (this is my studentID)
* @param1: define type of log
* @param2: SocketInfo* client is client's session
* @param3: int code_error is the status code
* @return: this function not return value
*/
void writeLog(int log, SocketInfo* client, int code_error)
{
	FILE* hlog = fopen("log_20183781.txt", "a+");
	switch (log)
	{
	case 1: // login
		fprintf(hlog, "%s:%d [%s] $ LOGIN %s $ %d\n", client->ip, client->port, getTime(), client->user, code_error);
		break;
	case 2:	// post
		fprintf(hlog, "%s:%d [%s] $ POST %s $ %d\n", client->ip, client->port, getTime(), client->post, code_error);
		break;
	case 3: // logout
		fprintf(hlog, "%s:%d [%s] $ LOGOUT $ %d\n", client->ip, client->port, getTime(), code_error);
		break;
	default: // exception	
		break;
	}
	fclose(hlog);
}