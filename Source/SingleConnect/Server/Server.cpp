/*
  Diffie-Hellman key exchange (without HMAC) aka ECDH_anon in RFC4492
  1. Alice picks a (secret) random natural number 'a', calculates P = a * G and sends P to Bob.
     'a' is Alice's private key.
     'P' is Alice's public key.
  2. Bob picks a (secret) random natural number 'b', calculates Q = b * G and sends Q to Alice.
     'b' is Bob's private key.
     'Q' is Bob's public key.
  3. Alice calculates S = a * Q = a * (b * G).
  4. Bob calculates T = b * P = b * (a * G).
  .. which are the same two values since multiplication in the field is commutative and associative.
  T = S = the new shared secret.
  Pseudo-random number generator inspired / stolen from: http://burtleburtle.net/bob/rand/smallprng.html
*/

// aes
#include "aes.h"
#include <string.h>
#include <stdint.h>

// ecdh
#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <time.h>
#include "ecdh.h"

// client-server
#include <stdio.h>
#include <WinSock2.h>
#include <WS2tcpip.h>

#define SERVER_PORT 8080
#define SERVER_ADDR "127.0.0.1"
#define BUFF_SIZE 2048

#pragma comment(lib, "Ws2_32.lib")

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

    /* 2. Bob picks a (secret) random natural number 'b', calculates Q = b * g and sends Q to Alice. */
    for (i = 0; i < ECC_PRV_KEY_SIZE; ++i)
    {
        prvb[i] = prng_next();
    }
    ecdh_generate_keys(pubb, prvb);

    printf("private key of Bob: ");
    for (int i = 0; i < ECC_PRV_KEY_SIZE; i++) printf("%2X", prvb[i]);
    printf("\n");

    printf("public key of Bob: ");
    for (int i = 0; i < ECC_PRV_KEY_SIZE; i++) printf("%2X", pubb[i]);
    printf("\n");

    // receive pubKey from Alice
    ret = recv(conn, (char*)puba, ECC_PUB_KEY_SIZE, NULL);
    if (ret == SOCKET_ERROR) {
        printf("Error %d: cannot receive pubKey from Alice\n", WSAGetLastError());
        return NULL;
    }
    
    // send pubkey to Alice
    ret = send(conn, (char*)pubb, ECC_PUB_KEY_SIZE, NULL);
    if (ret == SOCKET_ERROR) {
        printf("Error %d: cannot send pubKey to Bob\n", WSAGetLastError());
        return NULL;
    }

    /* 4. Bob calculates T = b * P = b * (a * g). */
    ecdh_shared_secret(prvb, puba, secb);

    printf("Shared secret: ");
    for (i = 0; i < ECC_PUB_KEY_SIZE; i++) printf("%2X", secb[i]);
    printf("\n");

    printf("Size of shared secret: %d\n", ECC_PUB_KEY_SIZE);
    return secb;
}


/* WARNING: This is not working correctly. ECDSA is not working... */
void ecdsa_broken()
{
    static uint8_t  prv[ECC_PRV_KEY_SIZE];
    static uint8_t  pub[ECC_PUB_KEY_SIZE];
    static uint8_t  msg[ECC_PRV_KEY_SIZE];
    static uint8_t  signature[ECC_PUB_KEY_SIZE];
    static uint8_t  k[ECC_PRV_KEY_SIZE];
    uint32_t i;

    srand(time(0));
    srand(42);

    for (i = 0; i < ECC_PRV_KEY_SIZE; ++i)
    {
        prv[i] = rand();
        msg[i] = prv[i] ^ rand();
        k[i] = rand();
    }

    /* int ecdsa_sign(const uint8_t* private, const uint8_t* hash, uint8_t* random_k, uint8_t* signature);
       int ecdsa_verify(const uint8_t* public, const uint8_t* hash, uint8_t* signature);                          */

    ecdh_generate_keys(pub, prv);
    /* No asserts - ECDSA functionality is broken... */
    ecdsa_sign((const uint8_t*)prv, msg, k, signature);
    ecdsa_verify((const uint8_t*)pub, msg, (const uint8_t*)signature); /* fails... */
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
        // printf("Error %d: cannot receive data\n", WSAGetLastError());
        return NULL;
    }
    else if (ret == 0) {
        char result[22] = "Client disconnected!\n";
        return result;
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

int main(int argc, char* argv[])
{
    // initiate winsock
    WSADATA wsaData;
    WORD wVersion = MAKEWORD(2, 2);
    if (WSAStartup(wVersion, &wsaData)) {
        printf("winsock 2.2 not supported!\n");
        return 0;
    }

    // construct socket
    SOCKET listenSock;
    listenSock = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (listenSock == INVALID_SOCKET) {
        printf("Error %d: cannot create server socket\n", WSAGetLastError());
        return 0;
    }

    // bind address to socket
    sockaddr_in serverAddr;
    serverAddr.sin_family = AF_INET;
    serverAddr.sin_port = htons(SERVER_PORT);
    inet_pton(AF_INET, SERVER_ADDR, &serverAddr.sin_addr);

    if (bind(listenSock, (sockaddr*)&serverAddr, sizeof(serverAddr))) {
        printf("Error: %d cannot associate a local address with server socket\n", WSAGetLastError());
        return 0;
    }

    // communicate with client
    sockaddr_in clientAddr;
    char buff[BUFF_SIZE], clientIP[INET_ADDRSTRLEN];
    int ret, clientAddrLen = sizeof(clientAddr), clientPort;
    SOCKET connSock;

    while (1) {
        // listen request from client
        if (listen(listenSock, 10)) {
            printf("Error %d cannot place server socket in state listen\n", WSAGetLastError());
            return 0;
        }

        printf("Server started!\n");

        // accept request
        connSock = accept(listenSock, (sockaddr*)&clientAddr, &clientAddrLen);
        if (connSock == SOCKET_ERROR) {
            printf("Error %d: Cannot permit incoming connection\n", WSAGetLastError());
            return 0;
        }
        else {
            inet_ntop(AF_INET, &clientAddr.sin_addr, clientIP, sizeof(clientIP));
            clientPort = ntohs(clientAddr.sin_port);
            printf("Accept incoming connection from %s:%d\n", clientIP, clientPort);
        }
        uint8_t key[32];
        uint8_t* pKey;
        char* recv_data;

        // gen key in curve
        pKey = gen_Key_ECDH(connSock);
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

            // receive message from client 
            recv_data = recv_data_decrypt(key, connSock);
            if (recv_data == NULL) {
                printf("Error %d: cannot receive data\n", WSAGetLastError());
                break;
            }
            else if (memcmp(recv_data, "Client disconnected!\n", 22) == 0) {
                printf("Client [%s:%d] disconnected!\n", clientIP, clientPort);
                break;
            }
            else {
                printf("receive from client [%s:%d] %s\n", clientIP, clientPort, recv_data);

                // echo to client
                ret = send_data_encrypt(key, connSock, recv_data, strlen(recv_data));
                if (ret == SOCKET_ERROR) {
                    printf("Error %d: cannot send data\n", WSAGetLastError());
                    break;
                }
            }

        }
    }
    // end communicating

    // close socket
    closesocket(connSock);
    closesocket(listenSock);

    WSACleanup();

    return 0;
}