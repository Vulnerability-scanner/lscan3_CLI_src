/* -------------------------------------------------------------------------- */

#include "conf.h"

/* -------------------------------------------------------------------------- */

HOSTRANGE *hostrangeparse(char *str)
{
	HOSTRANGE *host = NULL;
	
	if((str = strdup(str)))
	{
		char *sep;
		
		/* диапазон хостов */
		if( (sep = strchr(str, '-')) ||
			(sep = strchr(str, ':')) ||
			(sep = strchr(str, ';')) )
		{
			unsigned long start, end;
			*sep = 0;
			start = ip(trim(str));
			end = ip(trim(sep+1));
			if((start) && (end >= start))
			{
				if((host = malloc(sizeof(HOSTRANGE))))
				{
					host->start = start;
					host->end = end;
				}
			}
		}

		/* CIDR-нотация */
		else if( (sep = strchr(str, '/')) )
		{
			unsigned long addr;
			int n;
			*sep = 0;
			addr = ip(trim(str));
			n = atoi(trim(sep+1));
			if( (addr) && (n >= 0) && (n <= 32) )
			{
				if((host = malloc(sizeof(HOSTRANGE))))
				{
					if(n == 0)
					{
						host->start = 1;
						host->end = 0xfffffffful;
					}
					else
					{
						unsigned long mask = 0xfffffffful << (32-n);
						host->start = addr & mask;
						host->end = addr | ~mask;
					}
				}
			}
		}

		/* одиночный хост */
		else
		{
			unsigned long addr;
			addr = ip(trim(str));
			if(addr)
			{
				if((host = malloc(sizeof(HOSTRANGE))))
					host->start = host->end = addr;
			}
		}
		
		free(str);
	}

	return host;
}

/* -------------------------------------------------------------------------- */

PORTRANGE *portrangeparse(char *str)
{
	PORTRANGE *port = NULL;

	if((str = strdup(str)))
	{
		char *sep;

		/* диапазон портов */
		if((sep = strchr(str, '-')))
		{
			int start, end;
			*sep = 0;
			start = atoi(trim(str));
			end = atoi(trim(sep+1));
			if((start >= 1) && (end >= start) && (end <= 65535))
			{
				if((port = malloc(sizeof(PORTRANGE))))
				{
					port->start = start;
					port->end = end;
				}
			}
		}

		/* одиночный порт */
		else
		{
			int n = atoi(trim(str));
			if((n >= 1) && (n <= 65535))
			{
				if((port = malloc(sizeof(PORTRANGE))))
					port->start = port->end = n;
			}
		}

		free(str);
	}

	return port;
}

/* -------------------------------------------------------------------------- */

/* [user[:pass]@]host[:port] */

PROXY *proxyparse(char *str)
{
	PROXY *proxy = NULL;

	if((str = strdup(str)))
	{
		char *sep;
		
		char *host = str;
		int port = PROXY_DEF_PORT;
		char *username = "";
		char *password = "";
		unsigned long addr;

		/* имеется логин/пароль */
		if((sep = strchr(str, '@')))
		{
			*sep = 0;

			host = sep + 1;
			username = str;

			/* имеется пароль */
			if((sep = strchr(username, ':')))
			{
				*sep = 0;
				password = sep + 1;
			}
		}

		/* имеется порт */
		if((sep = strchr(host, ':')))
		{
			*sep = 0;
			port = atoi(trim(sep+1));
		}

		/* хост валидный */
		if((addr = ip(trim(host))))
		{
			if((proxy = malloc(sizeof(PROXY))))
			{
				proxy->host = addr;
				proxy->port = port;
				strncpy(proxy->username, trim(username), PROXY_MAX_USERNAME);
				strncpy(proxy->password, trim(password), PROXY_MAX_PASSWORD);
				proxy->username[PROXY_MAX_USERNAME-1] = 0;
				proxy->password[PROXY_MAX_PASSWORD-1] = 0;
			}
		}

		free(str);
	}
	return proxy;
}

/* -------------------------------------------------------------------------- */
