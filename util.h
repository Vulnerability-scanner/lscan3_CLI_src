/* -------------------------------------------------------------------------- */

#ifndef __util_h__
#define __util_h__

/* -------------------------------------------------------------------------- */

#include <malloc.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>

/* -------------------------------------------------------------------------- */

#define VECTORADDFILE_MAXLINE		256

/* -------------------------------------------------------------------------- */

typedef struct
{
	int capacity;
	int length;
	void **items;
} VECTOR;

/* -------------------------------------------------------------------------- */

int iswhite(char c);
char *trim(char *str);
int tokenize(char *str, char *delimiter, char **tokens, int maxtokens);
unsigned long ip(char *str);
char *iptext(char *buff, unsigned long host);

int vectoradd(VECTOR *v, void *item);
int vectorfree(VECTOR *v);
int vectoraddfile(VECTOR *v, char *path);

/* -------------------------------------------------------------------------- */

#endif

/* -------------------------------------------------------------------------- */
