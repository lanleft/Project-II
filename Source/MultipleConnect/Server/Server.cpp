// Server 

#include "Server.h"
#include <winsock2.h>
#include <windows.h>
#include <WS2tcpip.h>
#include <stdio.h>
#include <conio.h>
#include <time.h>
#include <stdlib.h>
#include "aes.h"
#include "ecdh.h"
#include <assert.h>

#define WM_SOCKET WM_USER + 1
#define SERVER_PORT 6000
#define SERVER_ADDR "127.0.0.1"
#define MAX_CLIENT 1024
#define BUFF_SIZE 2048
#define DATA_BUFSIZE 8192
#define MAX_CLIENT 1024
#define BUFF_SIZE 1024

#pragma warning(disable:4996)
#pragma comment(lib, "Ws2_32.lib")


/*Struct contains information of the socket communicating with client*/
typedef struct SocketInfo {
	SOCKET sock;
	char ip[INET_ADDRSTRLEN];
	int port;
	char user[256];
	char filename[256];
	char keyAES[17] = "aaaaaaaaaaaaaaaa";
	char buff[DATA_BUFSIZE];
	bool stt_login;
};

void processData(SocketInfo*, char*, char*);
int loginSession(SocketInfo*, char*);
int postSession(SocketInfo*, char*);
int logoutSession(SocketInfo*);
char* getTime();
int checkUser(char*);
void writeLog(int, SocketInfo*, int);


// Forward declarations of functions included in this code module:
ATOM				MyRegisterClass(HINSTANCE hInstance);
HWND				InitInstance(HINSTANCE, int);
LRESULT CALLBACK	windowProc(HWND, UINT, WPARAM, LPARAM);

SOCKET client[MAX_CLIENT];
SOCKET listenSock;
//struct client
SocketInfo* nclients[MAX_CLIENT];
int cnt=0; // count clients connect

int WINAPI WinMain(HINSTANCE hInstance, HINSTANCE hPrevInstance, LPSTR lpCmdLine, int nCmdShow)
{

	MSG msg;
	HWND serverWindow;

	//Registering the Window Class
	MyRegisterClass(hInstance);

	//Create the window
	if ((serverWindow = InitInstance(hInstance, nCmdShow)) == NULL)
		return FALSE;

	//Initiate WinSock
	WSADATA wsaData;
	WORD wVersion = MAKEWORD(2, 2);
	if (WSAStartup(wVersion, &wsaData)) {
		MessageBox(serverWindow, L"Winsock 2.2 is not supported.", L"Error!", MB_OK);
		return 0;
	}

	//Construct socket	
	listenSock = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);

	//requests Windows message-based notification of network events for listenSock
	WSAAsyncSelect(listenSock, serverWindow, WM_SOCKET, FD_ACCEPT | FD_CLOSE | FD_READ);

	//Bind address to socket
	sockaddr_in serverAddr;
	serverAddr.sin_family = AF_INET;
	serverAddr.sin_port = htons(SERVER_PORT);
	inet_pton(AF_INET, SERVER_ADDR, &serverAddr.sin_addr);


	for (int i = 0; i < FD_SETSIZE; i++)
	{
		nclients[i] = (SocketInfo*)malloc(sizeof(SocketInfo));
	}

	if (bind(listenSock, (sockaddr*)&serverAddr, sizeof(serverAddr)))
	{
		MessageBox(serverWindow, L"Cannot associate a local address with server socket.", L"Error!", MB_OK);
	}

	//Listen request from client
	if (listen(listenSock, MAX_CLIENT)) {
		MessageBox(serverWindow, L"Cannot place server socket in state LISTEN.", L"Error!", MB_OK);
		return 0;
	}

	// Main message loop:
	while (GetMessage(&msg, NULL, 0, 0)) {
		TranslateMessage(&msg);
		DispatchMessage(&msg);
	}

	return 0;
}


//
//  FUNCTION: MyRegisterClass()
//
//  PURPOSE: Registers the window class.
//
//  COMMENTS:
//
//    This function and its usage are only necessary if you want this code
//    to be compatible with Win32 systems prior to the 'RegisterClassEx'
//    function that was added to Windows 95. It is important to call this function
//    so that the application will get 'well formed' small icons associated
//    with it.
//
ATOM MyRegisterClass(HINSTANCE hInstance)
{
	WNDCLASSEX wcex;

	wcex.cbSize = sizeof(WNDCLASSEX);

	wcex.style = CS_HREDRAW | CS_VREDRAW;
	wcex.lpfnWndProc = windowProc;
	wcex.cbClsExtra = 0;
	wcex.cbWndExtra = 0;
	wcex.hInstance = hInstance;
	wcex.hIcon = LoadIcon(hInstance, MAKEINTRESOURCE(IDI_WSAASYNCSELECTSERVER));
	wcex.hCursor = LoadCursor(NULL, IDC_ARROW);
	wcex.hbrBackground = (HBRUSH)(COLOR_WINDOW + 1);
	wcex.lpszMenuName = NULL;
	wcex.lpszClassName = L"WindowClass";
	wcex.hIconSm = LoadIcon(wcex.hInstance, MAKEINTRESOURCE(IDI_SMALL));

	return RegisterClassEx(&wcex);
}

//
//   FUNCTION: InitInstance(HINSTANCE, int)
//
//   PURPOSE: Saves instance handle and creates main window
//
//   COMMENTS:
//
//        In this function, we save the instance handle in a global variable and
//        create and display the main program window.
//
HWND InitInstance(HINSTANCE hInstance, int nCmdShow)
{
	HWND hWnd;
	int i;
	for (i = 0; i < MAX_CLIENT; i++)
		client[i] = 0;
	hWnd = CreateWindow(L"WindowClass", L"WSAAsyncSelect TCP Server", WS_OVERLAPPEDWINDOW,
		CW_USEDEFAULT, 0, CW_USEDEFAULT, 0, NULL, NULL, hInstance, NULL);

	if (!hWnd)
		return FALSE;

	ShowWindow(hWnd, nCmdShow);
	UpdateWindow(hWnd);

	return hWnd;
}

//
//  FUNCTION: WndProc(HWND, UINT, WPARAM, LPARAM)
//
//  PURPOSE:  Processes messages for the main window.
//
//  WM_SOCKET	- process the events on the sockets
//  WM_DESTROY	- post a quit message and return
//
//

LRESULT CALLBACK windowProc(HWND hWnd, UINT message, WPARAM wParam, LPARAM lParam)
{
	SOCKET connSock;
	sockaddr_in clientAddr;
	int ret, clientAddrLen = sizeof(clientAddr), i;
	char rcvBuff[BUFF_SIZE], sendBuff[BUFF_SIZE];

	switch (message) {
	case WM_SOCKET:
	{
		if (WSAGETSELECTERROR(lParam)) {
			for (i = 0; i < MAX_CLIENT; i++)
				if (client[i] == (SOCKET)wParam) {
					closesocket(client[i]);
					client[i] = 0;

					// clears login status when user disconnects
					nclients[i]->stt_login = 0;
					memset(nclients[i]->user, 0, sizeof(nclients[i]->user));
					continue;
				}
		}

		switch (WSAGETSELECTEVENT(lParam)) {
		case FD_ACCEPT:
		{
			connSock = accept((SOCKET)wParam, (sockaddr*)&clientAddr, &clientAddrLen);
			if (connSock == INVALID_SOCKET) {
				break;
			}
			for (i = 0; i < MAX_CLIENT; i++)
				if (client[i] == 0) {
					client[i] = connSock;
					nclients[i]->sock = connSock;	// SocketInfo
					sprintf(nclients[i]->ip, "%s", inet_ntoa(clientAddr.sin_addr));		// get client's IP
					nclients[i]->port = ntohs(clientAddr.sin_port);						// get client's Port
					cnt++;

					break;
					//requests Windows message-based notification of network events for listenSock
					WSAAsyncSelect(client[i], hWnd, WM_SOCKET, FD_READ | FD_CLOSE);
				}
			if (i == MAX_CLIENT)
				MessageBox(hWnd, L"Too many clients!", L"Notice", MB_OK);
		}
		break;

		case FD_READ:
		{
			for (i = 0; i < MAX_CLIENT; i++)
				if (client[i] == (SOCKET)wParam)
					break;
			memset(rcvBuff, 0, sizeof(rcvBuff));
			ret = recv(client[i], rcvBuff, BUFF_SIZE, 0);
			if (ret > 0) {
				memset(sendBuff, 0, sizeof(sendBuff));
				processData(nclients[i], rcvBuff, sendBuff);		// process data receive from client
				send(client[i], sendBuff, sizeof(sendBuff), 0);
			}
		}
		break;

		case FD_CLOSE:
		{
			for (i = 0; i < MAX_CLIENT; i++)
				if (client[i] == (SOCKET)wParam) {
					closesocket(client[i]);
					client[i] = 0;

					// fclose
					nclients[i]->stt_login = 0;
					memset(nclients[i]->user, 0, sizeof(nclients[i]->user));
					cnt--;
					break;
				}
		}
		break;
		}
	}
	break;

	case WM_DESTROY:
	{
		PostQuitMessage(0);
		shutdown(listenSock, SD_BOTH);
		closesocket(listenSock);
		WSACleanup();
		return 0;
	}
	break;

	case WM_CLOSE:
	{
		DestroyWindow(hWnd);
		shutdown(listenSock, SD_BOTH);
		closesocket(listenSock);
		WSACleanup();
		return 0;
	}
	break;
	}
	return DefWindowProc(hWnd, message, wParam, lParam);
}


/* my protocol like this:
LOGIN		10: Login successed
			11: User does not exit
			12: User has been blocked
			13: User has been logged in from another device
			14: You have not been logged out
----------------------------------------------------
UPLOAD		20: Upload successed
			21: You have not logged in
----------------------------------------------------
DOWNLOAD	30: Download successed
			31: You have not logged in
----------------------------------------------------
LOGOUT		40: Log out successed
			41: You have not logged in
----------------------------------------------------
LIST		60: List files successed
			61: You have not logged in
----------------------------------------------------
OTHERWISE
			51: Your request format incorrected!
			52: Data is lost during transmission
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

	if (sizeData != strlen(in + 3)) {
		sprintf(out, "%d", 42);
		return;
	}

	char c = in[2];
	switch (c)
	{
	case 1:	// login
		code_error = loginSession(client, in + 3);
		writeLog(1, client, code_error);
		break;
	case 2: // post
		code_error = UploadSession(client, in + 3);
		writeLog(2, client, code_error);
		break;
	case 3: // post
		code_error = DownloadSession(client, in + 3);
		writeLog(2, client, code_error);
		break;
	case 4: // logout
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

	for (int i = 0; i < cnt; i++) {
		if (!strcmp(nclients[i]->user, buff))
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
int UploadSession(SocketInfo* client, char* buff)
{
	if (client->stt_login == 0)	// client have not login, so they cant post anything in PostRoom
		return 21;
	else {
		memcpy(client->filename, buff, sizeof(client->filename)); // stored post in client's struct 
		return 20;
	}
}

int DownloadSession(SocketInfo* client, char* buff)
{
	if (client->stt_login == 0)	// client have not login, so they cant post anything in PostRoom
		return 21;
	else {
		memcpy(client->filename, buff, sizeof(client->filename)); // stored post in client's struct 
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
	case 2:	// upload
		fprintf(hlog, "%s:%d [%s] $ UPLOAD %s $ %d\n", client->ip, client->port, getTime(), client->filename, code_error);
		break;
	case 3:	// download
		fprintf(hlog, "%s:%d [%s] $ DOWNLOAD %s $ %d\n", client->ip, client->port, getTime(), client->filename, code_error);
		break;
	case 4: // logout
		fprintf(hlog, "%s:%d [%s] $ LOGOUT $ %d\n", client->ip, client->port, getTime(), code_error);
		break;
	default: // exception	
		break;
	}
	fclose(hlog);
}


/* pseudo random number generator with 128 bit internal state... probably not suited for cryptographical usage */
typedef struct
{
	uint32_t a;
	uint32_t b;
	uint32_t c;
	uint32_t d;
} prng_t;

static prng_t prng_ctx;

static uint32_t prng_rotate(uint32_t x, uint32_t k)
{
	return (x << k) | (x >> (32 - k));
}

static uint32_t prng_next(void)
{
	uint32_t e = prng_ctx.a - prng_rotate(prng_ctx.b, 27);
	prng_ctx.a = prng_ctx.b ^ prng_rotate(prng_ctx.c, 17);
	prng_ctx.b = prng_ctx.c + prng_ctx.d;
	prng_ctx.c = prng_ctx.d + e;
	prng_ctx.d = e + prng_ctx.a;
	return prng_ctx.d;
}

static void prng_init(uint32_t seed)
{
	uint32_t i;
	prng_ctx.a = 0xf1ea5eed;
	prng_ctx.b = prng_ctx.c = prng_ctx.d = seed;

	for (i = 0; i < 31; ++i)
	{
		(void)prng_next();
	}
}

uint8_t* gen_Key_ECDH(SOCKET conn)
{
	static uint8_t puba[ECC_PUB_KEY_SIZE];
	static uint8_t prva[ECC_PRV_KEY_SIZE];
	static uint8_t seca[ECC_PUB_KEY_SIZE];
	static uint8_t pubb[ECC_PUB_KEY_SIZE];
	static uint8_t prvb[ECC_PRV_KEY_SIZE];
	static uint8_t secb[ECC_PUB_KEY_SIZE];
	uint32_t i;
	int ret;

	/* 0. Initialize and seed random number generator */
	static int initialized = 0;
	if (!initialized)
	{
		srand(time(0));
		// srand(42);
		// prng_init((0xbad ^ 0xc0ffee ^ 42) | 0xcafebabe | 666);
		prng_init(rand());
		initialized = 1;
	}

	/* 1. Alice picks a (secret) random natural number 'a', calculates P = a * g and sends P to Bob. */
	for (i = 0; i < ECC_PRV_KEY_SIZE; ++i)
	{
		prva[i] = prng_next();
	}
	assert(ecdh_generate_keys(puba, prva));

	printf("private key of Alice: ");
	for (int i = 0; i < ECC_PRV_KEY_SIZE; i++) printf("%2X", prva[i]);
	printf("\n");

	printf("public key of Alice: ");
	for (int i = 0; i < ECC_PRV_KEY_SIZE; i++) printf("%2X", puba[i]);
	printf("\n");

	// send pubKey
	ret = send(conn, (char*)puba, ECC_PUB_KEY_SIZE, NULL);
	if (ret == SOCKET_ERROR) {
		printf("Error %d: cannot send pubKey to Bob\,", WSAGetLastError());
		return 0;
	}

	// receive pubKey
	ret = recv(conn, (char*)pubb, ECC_PUB_KEY_SIZE, NULL);
	if (ret == SOCKET_ERROR) {
		printf("Error %d: cannot receive pubKey from Bob\n", WSAGetLastError());
	}

	/* 3. Alice calculates S = a * Q = a * (b * g). */
	ecdh_shared_secret(prva, pubb, seca);

	printf("Shared secret: ");
	for (i = 0; i < ECC_PUB_KEY_SIZE; i++) printf("%2X", seca[i]);
	printf("\n");

	printf("Size of shared secret: %d\n", ECC_PUB_KEY_SIZE);

	return seca;
}

// use AES_ECB to encrypt data 
int send_data_encrypt(uint8_t keyAES[32], SOCKET conn, char* msg, int lenMsg)
{
	struct AES_ctx ctx;
	int pad_size, ret;

	printf("Plaintext: ");
	for (int i = 0; i < lenMsg; i++) printf("%c", msg[i]);
	printf("\n");

	if (lenMsg % 16 != 0) {
		pad_size = lenMsg + 16 - (lenMsg % 16);
	}
	else pad_size = lenMsg;
	printf("Pad size: %d\n", pad_size);

	// convert data
	uint8_t ct[BUFF_SIZE];
	memset(ct, 0, BUFF_SIZE);
	memcpy(ct, msg, lenMsg);

	AES_init_ctx(&ctx, keyAES);
	AES_ECB_encrypt(&ctx, ct);

	printf("ECB Encrypt: ");
	for (int i = 0; i < pad_size; i++) printf("%2X", ct[i]);
	printf("\n------------------------------------------------------\n");

	ret = send(conn, (char*)&ct, pad_size, NULL);

	return ret;
}

// use AES_
char* recv_data_decrypt(uint8_t keyAES[32], SOCKET conn)
{
	struct AES_ctx ctx;

	char ct[BUFF_SIZE];
	int ret;

	memset(ct, 0, BUFF_SIZE);
	ret = recv(conn, ct, BUFF_SIZE, NULL);
	if (ret == SOCKET_ERROR) {
		printf("Error %d: cannot receive data\n", WSAGetLastError());
		return NULL;
	}

	uint8_t pt[BUFF_SIZE];
	memset(pt, 0, BUFF_SIZE);

	printf("Ciphertext: ");
	for (int i = 0; i < ret; i++) printf("%2X", ct[i]);
	printf("\n");

	memset(pt, 0, ret);
	memcpy(pt, ct, ret);

	AES_init_ctx(&ctx, keyAES);
	AES_ECB_decrypt(&ctx, pt);

	printf("ECB decrypt: ");
	for (int i = 0; i < ret; i++) printf("%2X", pt[i]);
	printf("\n------------------------------------------------------\n");

	return (char*)pt;
}
void send_cmd(SOCKET sock, char* cmd) {

}

void upload_file(SOCKET sock, char* filename, char* sendBuff)
{
	char data[BUFF_SIZE] = { 0 };

	while (fgets(data, BUFF_SIZE, fp) != NULL)
	{
		if (send_data_encrypt(key, sock, data, sizeof(data)) == -1)
		{
			perror("[-] Error in sendung data");
			exit(1);
		}
		ZeroMemory(data, BUFF_SIZE);
	}
}

void download_file(SOCKET sock, char* filenme) {
	int n;
	FILE* fp;
}