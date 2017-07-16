/* -------------------------------------------------------------------------- */

#ifndef __conf_h__
#define __conf_h__

/* -------------------------------------------------------------------------- */

#include <malloc.h>
#include <string.h>
#include "util.h"

/* -------------------------------------------------------------------------- */

#define PROXY_DEF_PORT			2323
#define PROXY_MAX_USERNAME		32
#define PROXY_MAX_PASSWORD		32

/* -------------------------------------------------------------------------- */

typedef struct __HOSTRANGE
{
	unsigned long start;
	unsigned long end;
} HOSTRANGE;

/* -------------------------------------------------------------------------- */

typedef struct __PORTRANGE
{
	int start;
	int end;
} PORTRANGE;

/* -------------------------------------------------------------------------- */

typedef struct __PROXY
{
	unsigned long host;
	int port;
	char username[PROXY_MAX_USERNAME];
	char password[PROXY_MAX_PASSWORD];
} PROXY;

/* -------------------------------------------------------------------------- */

HOSTRANGE *hostrangeparse(char *str);
PORTRANGE *portrangeparse(char *str);
PROXY *proxyparse(char *str);

/* -------------------------------------------------------------------------- */

#endif

/* -------------------------------------------------------------------------- */
