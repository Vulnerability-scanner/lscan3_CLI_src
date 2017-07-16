/* -------------------------------------------------------------------------- */

#ifndef __cmdln_h__
#define __cmdln_h__

/* -------------------------------------------------------------------------- */

#include <stdio.h>
#include "util.h"
#include "conf.h"

/* -------------------------------------------------------------------------- */

#define CONF_DEF_PORT				4899

#define CONF_DEF_SOCKS				5
#define CONF_DEF_NOPING				0
#define CONF_DEF_USEHASH			0
#define CONF_DEF_COUNT				32
#define CONF_MIN_COUNT				1
#define CONF_MAX_COUNT				32768
#define CONF_DEF_PACKETS			2
#define CONF_MIN_PACKETS			1
#define CONF_MAX_PACKETS			256
#define CONF_DEF_MAXHOSTS			8
#define CONF_MIN_MAXHOSTS			1
#define CONF_MAX_MAXHOSTS			4096
#define CONF_DEF_TIMEOUT			1000
#define CONF_MIN_TIMEOUT			100
#define CONF_MAX_TIMEOUT			60000
#define CONF_DEF_DELAY				500
#define CONF_MIN_DELAY				0
#define CONF_MAX_DELAY				3600000
#define CONF_DEF_IOTIMEOUT			60000
#define CONF_MIN_IOTIMEOUT			100
#define CONF_MAX_IOTIMEOUT			3600000
#define CONF_DEF_RETRYCOUNT			4
#define CONF_MIN_RETRYCOUNT			0
#define CONF_MAX_RETRYCOUNT			1000
#define CONF_DEF_FAILDELAY			120
#define CONF_MIN_FAILDELAY			0
#define CONF_MAX_FAILDELAY			86400
#define CONF_DEFAULT_ALL			0
#define CONF_DEF_OUTPUT				"lscan3.log"

/* -------------------------------------------------------------------------- */

typedef struct
{
	VECTOR hosts;
	VECTOR ports;
	VECTOR proxies;
	VECTOR usernames;
	VECTOR passwords;

	int showhelp;

	int socks;

	int count;

	int noping;
	int packets;
	int maxhosts;
	int timeout;

	int iotimeout;
	int usehash;

	int delay;
	int retrycount;
	int faildelay;
	
	int all;
	char *output;

} LSCANCONF;

/* -------------------------------------------------------------------------- */

int conf_init(LSCANCONF *conf);
int conf_free(LSCANCONF *conf);
int conf_setup(LSCANCONF *conf, int argc, char **argv);
int conf_check(LSCANCONF *conf);
void conf_banner();
void conf_bottom_banner();
void conf_help();

/* -------------------------------------------------------------------------- */

#endif

/* -------------------------------------------------------------------------- */
