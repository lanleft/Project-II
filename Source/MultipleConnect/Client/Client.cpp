// client 
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <WinSock2.h>
#include <WS2tcpip.h>
#include "aes.h"
#include "ecdh.h"
#include <assert.h>
#include <time.h>

#define BUFF_SIZE 10240
#pragma comment(lib, "Ws2_32.lib")
#pragma warning(disable:4996)

uint8_t* gen_Key_ECDH(SOCKET conn);
void printInfo();
void parser_error(char* msg);
static uint32_t prng_rotate(uint32_t x, uint32_t k);
static uint32_t prng_next(void);
static void prng_init(uint32_t seed);
uint8_t* gen_Key_ECDH(SOCKET conn);
int send_data_encrypt(uint8_t keyAES[32], SOCKET conn, char* msg, int lenMsg);
char* recv_data_decrypt(uint8_t keyAES[32], SOCKET conn);

// key AES
uint8_t key[32];
uint8_t* pKey;

/* The printInfo function prints information and all options to client choice
* @param no parameter
* @return No return value
*/
void printInfo()
{
	puts("--------------------------------------");
	puts("       File Transfer Protocol         ");
	puts("--------------------------------------");
	puts(" 1. Login                             ");
	puts(" 2. Upload                            ");
	puts(" 3. Download                          ");
	puts(" 4. Log out                           ");
	puts(" 5. Exit                              ");
	puts(" 6. List                              ");
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
UPLOAD		20: Upload successed
			21: You have not logged in
----------------------------------------------------
DOWNLOAD	30: Download successed
			31: You have not logged in
----------------------------------------------------
LOGOUT		40: Log out successed
			41: You have not logged in
----------------------------------------------------
OTHERWISE
			51: Your request format incorrected!
			52: Data is lost during transmission

@param1 string message code
@return No return value

*/
void parser_error(char* msg)
{
	char err[2];
	strncpy(err, msg, 2);
	int code_error = atoi(err);
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

		// code error of upload file action
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
	char sendBuff[BUFF_SIZE], rcvBuff[BUFF_SIZE], name[256], filename[256], str_num[256];
	int ret, num;
	WORD sizeBuff;

	
	char* recv_data;

	// generate key ECDH 
	pKey = gen_Key_ECDH(client);
	if (pKey == NULL) {
		printf("Create key fron ECDH faild\n");
	}
	else {
		memcpy(key, pKey, 32);
		printf("Key use for AES: ");
		for (int i = 0; i < 32; i++) printf("%2X", key[i]);
		printf("\n------------------------------------------------------\n");
	}

	while (1) {
		// clean data before start of session 
		memset(sendBuff, 0, BUFF_SIZE);
		memset(name, 0, 256);
		memset(filename, 0, 256);

		// send client's choice and data to server
		printInfo();
		gets_s(str_num, 256);
		num = atoi(str_num);

		//	| 2 bytes         |  1byte prefix | n bytes data  | 
		//	| sizeofpacket->n | 1, 2 or 3     |   data        |
		switch (num)
		{
		case 1:// login
			sendBuff[2] = 1;
			printf("Enter your username: ");
			gets_s(name, sizeof(name));
			memcpy(sendBuff + 3, name, strlen(name));
			sizeBuff = strlen(sendBuff + 3) + 3;		// add 2 bytes of begin data
			memcpy(sendBuff, &sizeBuff, 2);
			send_cmd(client, sendBuff);
			break;
		case 2:// upload
			sendBuff[2] = 2;
			printf("Upload filename: ");
			gets_s(filename, sizeof(filename));
			memcpy(sendBuff + 3, filename, strlen(filename));
			sizeBuff = strlen(sendBuff + 3) + 3;		// add 2 bytes of begin data
			memcpy(sendBuff, &sizeBuff, 2);
			upload_file(client, filename, sendBuff);
			break;
		case 3:// download
			sendBuff[2] = 2;
			printf("Download filename: ");
			gets_s(filename, sizeof(filename));
			memcpy(sendBuff + 3, filename, strlen(filename));
			break;
		case 6:// list
			sendBuff[2] = 6;
			break;
		case 4: // logout
			sendBuff[2] = 3;
			break;
		case 5:
			puts("Breaking of application...");
			return 0;
		default:
			puts("Invalid choice");
			break;
		}

		if (sendBuff[2]) {
			// get size of buffer
			
			printf("Size of sendbuff: %d\n", sizeBuff);
			// send data to server 
			
			if (ret == SOCKET_ERROR) {
				printf("Error %d: cannot send data\n", WSAGetLastError());
			}

			// receive from server
			memset(rcvBuff, 0, BUFF_SIZE);
			recv_data = recv_data_decrypt(key, client);
			if (recv_data == NULL) {
				printf("Receive data faild");
			}
			else {
				printf("Receive from server: %s\n", recv_data);
			}
		}
	}

	closesocket(client);

	WSACleanup();

	return 0;
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
	parser_error((char*)pt);

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