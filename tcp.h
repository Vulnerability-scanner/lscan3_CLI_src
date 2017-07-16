/* -------------------------------------------------------------------------- */

#ifndef __tcp_h__
#define __tcp_h__

/* -------------------------------------------------------------------------- */

#include <winsock.h>

/* -------------------------------------------------------------------------- */

#define SOCKS4_ID				"MOZ"
#define SOCKS4_MODE_CONNECT		0x01
#define SOCKS4_STATUS_OK		0x5a

#define SOCKS5_METHOD_NONE		0
#define SOCKS5_METHOD_USERNAME	2
#define SOCKS5_MODE_CONNECT		1
#define SOCKS5_TYPE_IPV4		1
#define SOCKS5_STATUS_OK		0x00

/* -------------------------------------------------------------------------- */

#pragma pack(push)
#pragma pack(1)
typedef struct __socks4_request
{
	unsigned char ver;
	unsigned char mode;
	unsigned short port;
	unsigned int addr;
	char id[0];
} socks4_request;
#pragma pack(pop)

/* -------------------------------------------------------------------------- */

#pragma pack(push)
#pragma pack(1)
typedef struct __socks4_reply
{
	unsigned char zero;
	unsigned char status;
	unsigned short sock_port;
	unsigned int sock_addr;
} socks4_reply;
#pragma pack(pop)

/* -------------------------------------------------------------------------- */

#pragma pack(push)
#pragma pack(1)
typedef struct __socks5_client_hello
{
	unsigned char ver;
	unsigned char count;
	unsigned char methods[0];
} socks5_client_hello;
#pragma pack(pop)

/* -------------------------------------------------------------------------- */

#pragma pack(push)
#pragma pack(1)
typedef struct __socks5_server_hello
{
	unsigned char ver;
	unsigned char status;
} socks5_server_hello;
#pragma pack(pop)

/* -------------------------------------------------------------------------- */

#pragma pack(push)
#pragma pack(1)
typedef struct __socks5_request
{
	unsigned char ver;
	unsigned char mode;
	unsigned char zero;
	unsigned char type;
	unsigned int addr;
	unsigned short port;
} socks5_request;
#pragma pack(pop)

/* -------------------------------------------------------------------------- */

#pragma pack(push)
#pragma pack(1)
typedef struct __socks5_reply
{
	unsigned char ver;
	unsigned char status;
	unsigned char zero;
	unsigned char type;
	unsigned int sock_addr;
	unsigned short sock_port;
} socks5_reply;
#pragma pack(pop)

/* -------------------------------------------------------------------------- */

#pragma pack(push)
#pragma pack(1)
typedef struct __socks5_auth_reply
{
	unsigned char ver;
	unsigned char status;
} socks5_auth_reply;
#pragma pack(pop)

/* -------------------------------------------------------------------------- */

typedef struct __tcp_open_struc
{
	int proxy_type;
	unsigned int host;
	int port;
	unsigned int proxy_host;
	int proxy_port;
	char *proxy_username;
	char *proxy_password;
} tcp_open_struc;

/* -------------------------------------------------------------------------- */

int wsa_init();
void wsa_final();
unsigned int tcp_addr(char *ip);
int tcp_open_indirect(tcp_open_struc *open_struc);
int tcp_open(unsigned int host, int port);
int tcp_open_socks4(unsigned int host, int port, unsigned int proxy_host, int proxy_port);
int tcp_open_socks5(unsigned int host, int port, unsigned int proxy_host, int proxy_port, char *proxy_username, char *proxy_password);
void tcp_close(int conn);
int tcp_read(int conn, void *buf, int length);
int tcp_write(int conn, void *buf, int length);
int tcp_read_ex(int conn, void *buf, int length, int timeout);
int tcp_write_ex(int conn, void *buf, int length, int timeout);

/* -------------------------------------------------------------------------- */

#endif

/* -------------------------------------------------------------------------- */
