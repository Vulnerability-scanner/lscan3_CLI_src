/* -------------------------------------------------------------------------- */

#ifndef __radmin_h__
#define __radmin_h__

/* -------------------------------------------------------------------------- */

#include <windows.h>
#include <winsock.h>
#include <openssl/md5.h>
#include <twofish/aes.h>
#include <srp.h>
#include "tcp.h"

/* -------------------------------------------------------------------------- */

#define RADMIN_MAX_DATA_BLOCK		1048576

/* -------------------------------------------------------------------------- */

#define RADMIN2_MIN_PASSLEN				8
#define RADMIN3_MIN_PASSLEN				6

/* -------------------------------------------------------------------------- */

#define RADMIN_AUTH_UNKNOWN			0
#define RADMIN_AUTH_NATIVE_2		1
#define RADMIN_AUTH_NTLM_2			2
#define RADMIN_AUTH_NONE_2			3
#define RADMIN_AUTH_NATIVE_3		4
#define RADMIN_AUTH_NTLM_3			5
#define RADMIN_AUTH_NONE_3			6

/* -------------------------------------------------------------------------- */

#define RADMIN_STATUS_ERROR			0
#define RADMIN_STATUS_SUCCESS		1
#define RADMIN_STATUS_PROTOERR		2
#define RADMIN_STATUS_PASSERR		3
#define RADMIN_STATUS_NAMEERR		4
#define RADMIN_STATUS_ALGOERR		5

/* -------------------------------------------------------------------------- */

#pragma pack(push)
#pragma pack(1)
typedef struct __radmin_packet_header_ver1
{
	char one;
	int datalen;
	int datacrc;
} radmin_packet_header_ver1;
#pragma pack(pop)

/* -------------------------------------------------------------------------- */

#pragma pack(push)
#pragma pack(1)
typedef struct __radmin_packet_data_ver1
{
	char code;
	char data[0];
} radmin_packet_data_ver1;
#pragma pack(pop)

/* -------------------------------------------------------------------------- */

typedef struct __radmin_packet_ver1
{
	int code;
	int datalen;
	void *data;
} radmin_packet_ver1;

/* -------------------------------------------------------------------------- */

#pragma pack(push)
#pragma pack(1)
typedef struct __radmin_packet_header_ver2
{
	int flags;
	int seq;
} radmin_packet_header_ver2;
#pragma pack(pop)

/* -------------------------------------------------------------------------- */

#pragma pack(push)
#pragma pack(1)
typedef struct __radmin_packet_data_ver2
{
	short id;
	short size;
} radmin_packet_data_ver2;
#pragma pack(pop)

/* -------------------------------------------------------------------------- */

typedef struct __radmin_subpacket_ver2
{
	int id;
	int size;
	void *data;
} radmin_subpacket_ver2;

/* -------------------------------------------------------------------------- */

typedef struct __radmin_packet_ver2
{
	int flags;
	int seq;
	int count;
	radmin_subpacket_ver2 *data;
} radmin_packet_ver2;

/* -------------------------------------------------------------------------- */

int radmin_check_version(tcp_open_struc *host, char **ver, int *auth, int timeout);
int radmin_auth2(tcp_open_struc *host, char *password, int timeout, int byhash);
int radmin_auth3(tcp_open_struc *host, char *username, char *password, int timeout);

/* -------------------------------------------------------------------------- */

#endif

/* -------------------------------------------------------------------------- */
