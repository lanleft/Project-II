// client 
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <WinSock2.h>
#include <WS2tcpip.h>

#define BUFF_SIZE 2048
#pragma comment(lib, "Ws2_32.lib")
#pragma warning(disable:4996)

/* The printInfo function prints information and all options to client choice
* @param no parameter
* @return No return value
*/
void printInfo()
{
	puts("--------------------------------------");
	puts("               PostRoom               ");
	puts("--------------------------------------");
	puts(" 1. Login                             ");
	puts(" 2. Post status                       ");
	puts(" 3. Log out                           ");
	puts(" 4. Exit                              ");
	puts("--------------------------------------");
	printf("Your choice: ");

}

/* The parser_error function parsers code error for each recv's message follow like this
list error code

LOGIN		10: Login successed
			11: User does not exit
			12: User has been blocked
			13: User has been logged in from another device
			14: You have not been logged out
----------------------------------------------------
POST		20: Post successed
			21: You have not logged in
----------------------------------------------------
LOGOUT		30: Log out successed
			31: You have not logged in
----------------------------------------------------
OTHERWISE
			41: Your request format incorrected!
			42: Data is lost during transmission

@param1 string message code
@return No return value

*/
void parser_error(char* msg)
{
	int code_error = atoi(msg);
	// code error of login action
	switch (code_error)
	{
	case 10:
		puts("Login successed");
		break;
	case 11:
		puts("User does not exit");
		break;
	case 12:
		puts("User has been blocked");
		break;
	case 13:
		puts("User has been logged in from another device");
		break;
	case 14:
		puts("You have not been logged out");
		break;

		// code error of post message action
	case 20:
		puts("Post successed");
		break;
	case 21:
		puts("You have not logged in");
		break;
	case 30:  // code error of logout action
		puts("Log out successed");
		break;
	case 31:
		puts("You have not logged in");
		break;
	case 41:
		puts("Your request format incorrected!");
		break;
	case 42:
		puts("Data is lost during transmission");
		break;
	default:  // others can not parser
		printf("Cannot parser code error %s\n", msg);
		break;
	}
}

/* The main function of project
* @param1: count of argument of main
* @param2: list argument of main
* @return: return number
*/
int main(int argc, char* argv[])
{
	// define value 
	char SERVER_ADDR[256];
	int SERVER_PORT = 0;

	// check
	if (argc != 3) {
		printf("Usage: client.exe [server_addr] [number_port]\n");
		return 0;
	}
	// parser argument
	memset(SERVER_ADDR, 0, 256);
	memcpy(SERVER_ADDR, argv[1], strlen(argv[1]));
	SERVER_PORT = atoi(argv[2]);

	// initiate winsock
	WSADATA wsaData;
	WORD wVersion = MAKEWORD(2, 2);
	if (WSAStartup(wVersion, &wsaData)) {
		printf("Winsock 2.2 not supported\n");
		return 0;
	}

	// construct socket
	SOCKET client;
	client = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
	if (client == INVALID_SOCKET) {
		printf("Error %d: cannot create server socket\n", WSAGetLastError());
		return 0;
	}

	// specify server address
	sockaddr_in serverAddr;
	serverAddr.sin_family = AF_INET;
	serverAddr.sin_port = htons(SERVER_PORT);
	inet_pton(AF_INET, SERVER_ADDR, &serverAddr.sin_addr);

	// request to connect server
	if (connect(client, (sockaddr*)&serverAddr, sizeof(serverAddr))) {
		printf("Error %d: cannot connect server\n", WSAGetLastError());
		return 0;
	}

	// communicate with server
	char sendBuff[BUFF_SIZE], rcvBuff[BUFF_SIZE], name[256], status[BUFF_SIZE - 1], str_num[256];
	int ret, num;
	WORD sizeBuff;

	while (1) {
		// clean data before start of session 
		memset(sendBuff, 0, BUFF_SIZE);
		memset(name, 0, 256);
		memset(status, 0, BUFF_SIZE - 1);

		// send client's choice and data to server
		printInfo();
		gets_s(str_num, 256);
		num = atoi(str_num);

		//	| 2 bytes         |  1byte prefix | n bytes data  | 
		//	| sizeofpacket->n | 1, 2 or 3     |   data        |
		switch (num)
		{
		case 1:
			sendBuff[2] = 1;
			printf("Enter your username: ");
			gets_s(name, sizeof(name));
			memcpy(sendBuff + 3, name, strlen(name));
			break;
		case 2:
			sendBuff[2] = 2;
			printf("Enter your status: ");
			gets_s(status, sizeof(status));
			memcpy(sendBuff + 3, status, strlen(status));
			break;
		case 3:
			sendBuff[2] = 3;
			break;
		case 4:
			puts("Breaking of application...");
			return 0;
		default:
			puts("Invalid choice");
			break;
		}

		if (sendBuff[2]) {
			// get size of buffer
			sizeBuff = strlen(sendBuff + 3) + 3;		// add 2 bytes of begin data
			memcpy(sendBuff, &sizeBuff, 2);
			printf("Size of sendbuff: %d\n", sizeBuff);
			// send data to server 
			ret = send(client, sendBuff, sizeBuff, 0);
			if (ret == SOCKET_ERROR) {
				printf("Error %d: cannot send data\n", WSAGetLastError());
			}

			// receive from server
			memset(rcvBuff, 0, BUFF_SIZE);
			ret = recv(client, rcvBuff, BUFF_SIZE, 0);
			if (ret == SOCKET_ERROR) {
				printf("Error %d: cannot receive data\n", WSAGetLastError());
			}
			else if (strlen(rcvBuff) > 0) {
				parser_error(rcvBuff);	// parser code error 
			}
		}
	}

	closesocket(client);

	WSACleanup();

	return 0;
}