/* -------------------------------------------------------------------------- */

#include "util.h"

/* -------------------------------------------------------------------------- */

int vectoradd(VECTOR *v, void *item)
{
	if( v && item )
	{
		if(v->length == v->capacity)
		{
			int capacity = v->capacity + 32;
			void **items;
			if(!(items = realloc(v->items, 
				capacity * sizeof(void*))))
			{
				return 0;
			}
			v->capacity = capacity;
			v->items = items;
		}
		v->items[v->length++] = item;
		return 1;
	}
	return 0;
}

/* -------------------------------------------------------------------------- */

int vectoraddfile(VECTOR *v, char *path)
{
	int status = 0;
	if( v && path)
	{
		FILE *stream;
		if((stream = fopen(path, "rt")))
		{
			char *temp;
			if((temp = malloc(VECTORADDFILE_MAXLINE)))
			{
				while(fgets(temp, VECTORADDFILE_MAXLINE, stream))
				{
					char *p;
					if((p = strchr(temp, '\n')))
						*p = 0;
					if(*temp)
						vectoradd(v, strdup(temp));
				}
				free(temp);
			}
			fclose(stream);
			status = 1;
		}
	}
	return status;
}

/* -------------------------------------------------------------------------- */

int vectorfree(VECTOR *v)
{
	if(v)
	{
		int i;
		for(i = 0; i < v->length; ++i)
			free(v->items[i]);
		free(v->items);
	}
	return 0;
}

/* -------------------------------------------------------------------------- */

int iswhite(char c)
{
	return (c == ' ') || 
		(c == '\t') || 
		(c == '\v') || 
		(c == '\r') || 
		(c == '\n');
}

/* -------------------------------------------------------------------------- */

char *trim(char *str)
{
	if(str)
	{
		char *temp;
		while(iswhite(*str)) 
			str++;
		temp = str + strlen(str) - 1;
		while( (temp > str) && (iswhite(*temp)) )
			*(temp--) = 0;
	}
	return str;
}

/* -------------------------------------------------------------------------- */

int tokenize(char *str, char *delimiter, char **tokens, int maxtokens)
{
	char *context;
	char *item;
	int count = 0;
	if( (str) && (delimiter) && (tokens) && (maxtokens) )
	{
		if((item = strtok_s(str, delimiter, &context)))
		{
			do {
				tokens[count++] = item;
				if(count == maxtokens)
					break;
			} while((item = strtok_s(NULL, delimiter, &context)));
		}
	}
	return count;
}

/* -------------------------------------------------------------------------- */

unsigned long ip(char *str)
{
	unsigned long val = 0;
	if((str = strdup(str)))
	{
		char *tok[4];
		if(tokenize(str, ".", tok, 4) == 4)
		{
			int i;
			for(i = 0; i < 4; ++i)
			{
				unsigned long elem;
				elem = atoi(tok[i]);
				if(elem > 255)
				{
					val = 0;
					break;
				}
				val <<= 8;
				val |= elem;
			}
		}
		free(str);
	}
	return val;
}

/* -------------------------------------------------------------------------- */

char *iptext(char *buff, unsigned long host)
{
	if(buff)
	{
		unsigned char *temp = (void*)&host;
		sprintf(buff,
			"%d.%d.%d.%d",
			temp[3], temp[2], temp[1], temp[0]);
	}
	return buff;
}

/* -------------------------------------------------------------------------- */
