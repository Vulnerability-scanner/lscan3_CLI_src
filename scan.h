/* -------------------------------------------------------------------------- */

#ifndef __scan_h__
#define __scan_h__

/* -------------------------------------------------------------------------- */

#include <stdio.h>
#include <stdlib.h>
#include <time.h>
#include "conf.h"
#include "cmdln.h"
#include "platf.h"
#include "ping.h"
#include "radmin.h"

/* -------------------------------------------------------------------------- */

typedef struct
{
	LSCANCONF *conf;
	FILE *logstream;
	void *lock;
	void *printlock;
	void *loglock;
	void *pinglock;
	int regthreads;
	int currange;
	unsigned long curhost;
	int morehosts;
} LSCANCX;

/* -------------------------------------------------------------------------- */

void scan(LSCANCONF *conf);

/* -------------------------------------------------------------------------- */

#endif

/* -------------------------------------------------------------------------- */
