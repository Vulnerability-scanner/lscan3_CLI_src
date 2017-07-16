/* -------------------------------------------------------------------------- */

#include "cmdln.h"

/* -------------------------------------------------------------------------- */

int conf_init(LSCANCONF *conf)
{
	if(conf)
	{
		memset(conf, 0, sizeof(LSCANCONF));
		conf->socks = CONF_DEF_SOCKS;
		conf->noping = CONF_DEF_NOPING;
		conf->usehash = CONF_DEF_USEHASH;
		conf->count = CONF_DEF_COUNT;
		conf->packets = CONF_DEF_PACKETS;
		conf->maxhosts = CONF_DEF_MAXHOSTS;
		conf->timeout = CONF_DEF_TIMEOUT;
		conf->delay = CONF_DEF_DELAY;
		conf->iotimeout = CONF_DEF_IOTIMEOUT;
		conf->retrycount = CONF_DEF_RETRYCOUNT;
		conf->faildelay = CONF_DEF_FAILDELAY;
		conf->all = CONF_DEFAULT_ALL;
		conf->output = CONF_DEF_OUTPUT;
		return 1;
	}
	return 0;
}

/* -------------------------------------------------------------------------- */

int conf_free(LSCANCONF *conf)
{
	if(conf)
	{
		vectorfree(&(conf->hosts));
		vectorfree(&(conf->ports));
		vectorfree(&(conf->proxies));
		vectorfree(&(conf->usernames));
		vectorfree(&(conf->passwords));
		return 1;
	}
	return 0;
}

/* -------------------------------------------------------------------------- */

int sw_test(char *str, char *refsmall, char *refbig)
{
	return (strcmpi(str, refsmall) == 0) ||
		(strcmpi(str, refbig) == 0);
}

/* -------------------------------------------------------------------------- */

int conf_on_switch(LSCANCONF *conf, char *sw)
{
	if(sw_test(sw, "?", "-help"))
	{
		conf->showhelp = 1;
	}
	
	else if(sw_test(sw, "i", "-noping"))
	{
		conf->noping = 1;
	}
	
	else if(sw_test(sw, "e", "-usehash"))
	{
		conf->usehash = 1;
	}

	else if(sw_test(sw, "a", "all"))
	{
		conf->all = 1;
	}

	else if((!sw_test(sw, "h", "-host")) &&
		(!sw_test(sw, "p", "-port")) &&
		(!sw_test(sw, "t", "-proxy")) &&
		(!sw_test(sw, "u", "-username")) &&
		(!sw_test(sw, "pw", "-password")) &&
		(!sw_test(sw, "ul", "-usernamelist")) &&
		(!sw_test(sw, "pwl", "-passwordlist")) &&
		(!sw_test(sw, "hl", "-hostlist")) &&
		(!sw_test(sw, "c", "-count")) &&
		(!sw_test(sw, "n", "-packets")) &&
		(!sw_test(sw, "m", "-maxhosts")) &&
		(!sw_test(sw, "w", "-timeout")) &&
		(!sw_test(sw, "d", "-delay")) &&
		(!sw_test(sw, "io", "-iotimeout")) &&
		(!sw_test(sw, "r", "-retrycount")) &&
		(!sw_test(sw, "f", "-faildelay")) &&
		(!sw_test(sw, "s", "-socks")) &&
		(!sw_test(sw, "o", "-output")) )
	{
		printf("[!] ��������� ����: %s\n", sw);
	}

	return 1;
}

/* -------------------------------------------------------------------------- */

int conf_on_value(LSCANCONF *conf, char *sw, char *val)
{
	int status = 0;

	if(sw_test(sw, "h", "-host"))
	{
		HOSTRANGE *temp;
		if(!(temp = hostrangeparse(val)))
		{
			printf("[-] �����४�� ���/��������: %s\n", val);
			return 0;
		}
		vectoradd(&(conf->hosts), temp);
	}

	else if(sw_test(sw, "p", "-port"))
	{
		PORTRANGE *temp;
		if(!(temp = portrangeparse(val)))
		{
			printf("[-] �����४�� ����/��������: %s\n", val);
			return 0;
		}
		vectoradd(&(conf->ports), temp);
	}
	
	else if(sw_test(sw, "t", "-proxy"))
	{
		PROXY *temp;
		if(!(temp = proxyparse(val)))
		{
			printf("[-] �����४�� �ப�: %s\n", val);
			return 0;
		}
		vectoradd(&(conf->proxies), temp);
	}

	else if(sw_test(sw, "hl", "-hostlist"))
	{
		FILE *stream;
		if((stream = fopen(val, "rt")))
		{
			char temp[256];
			while((fgets(temp, sizeof(temp), stream)))
			{
				char *p;
				HOSTRANGE *hr;
				if((p = strchr(temp, '\n')))
					*p = 0;
				if((hr = hostrangeparse(temp)))
					vectoradd(&(conf->hosts), hr);
			}
			fclose(stream);
		}
		else
		{
			printf("[-] �訡�� ������ \"%s\"\n", val);
		}
	}
	
	else if(sw_test(sw, "ul", "-usernamelist"))
	{
		if(!(vectoraddfile(&(conf->usernames), val)))
		{
			printf("[-] �訡�� ������ \"%s\"\n", val);
			return 0;
		}
	}
	
	else if(sw_test(sw, "pwl", "-passwordlist"))
	{
		if(!(vectoraddfile(&(conf->passwords), val)))
		{
			printf("[-] �訡�� ������ \"%s\"\n", val);
			return 0;
		}
	}
	
	else if(sw_test(sw, "u", "-username"))
	{
		vectoradd(&(conf->usernames), strdup(val));
	}
	
	else if(sw_test(sw, "pw", "-password"))
	{
		vectoradd(&(conf->passwords), strdup(val));
	}

	else if(sw_test(sw, "c", "-count"))
	{
		conf->count = atoi(val);
	}
	
	else if(sw_test(sw, "n", "-packets"))
	{
		conf->packets = atoi(val);
	}
	
	else if(sw_test(sw, "m", "-maxhosts"))
	{
		conf->maxhosts = atoi(val);
	}
	
	else if(sw_test(sw, "w", "-timeout"))
	{
		conf->timeout = atoi(val);
	}
	
	else if(sw_test(sw, "d", "-delay"))
	{
		conf->delay = atoi(val);
	}
	
	else if(sw_test(sw, "io", "-iotimeout"))
	{
		conf->iotimeout = atoi(val);
	}
	
	else if(sw_test(sw, "r", "-retrycount"))
	{
		conf->retrycount = atoi(val);
	}
	
	else if(sw_test(sw, "f", "-faildelay"))
	{
		conf->faildelay = atoi(val);
	}
	
	else if(sw_test(sw, "s", "-socks"))
	{
		conf->faildelay = atoi(val);
	}
	
	else if(sw_test(sw, "o", "-output"))
	{
		conf->output = val;
	}

	else
	{
		printf("[!] �ந����஢���: %s\n", val);
	}
	
	return 1;
}

/* -------------------------------------------------------------------------- */

int conf_setup(LSCANCONF *conf, int argc, char **argv)
{
	if(conf && argv)
	{
		int status = 1;
		int arg;
		char *sw = "-host";

		puts("[*] ���ᨬ ��������� ��ப�");

		for(arg = 1; arg < argc; ++arg)
		{
			if( (argv[arg][0] == '-') ||
				(argv[arg][0] == '/') )
			{
				sw = argv[arg] + 1;
				if(!conf_on_switch(conf, sw))
					status = 0;
			}
			else
			{
				char *val = argv[arg];
				if(!conf_on_value(conf, sw, val))
					status = 0;
			}
		}

		if(argc == 1)
		{
			conf->showhelp = 1;
		}

		if(status)
		{
			puts("[*] ��������� ��ப� �ᯥ譮 �ᯠ�ᥭ�");
		}
		else
		{
			puts("[-] �� 㤠���� �ᯠ���� ��������� ��ப�");
		}

		puts("");

		return status;
	}
	return 0;
}

/* -------------------------------------------------------------------------- */

int conf_check(LSCANCONF *conf)
{
	if(conf)
	{
		int status = 1;

		puts("[*] �஢��塞 㪠����� ��ࠬ���� �� ����������");

		if(!conf->hosts.length)
		{
			puts("[-] �� ������ �� ������ ���");
			status = 0;
		}

		if((conf->count < CONF_MIN_COUNT) || (conf->count > CONF_MAX_COUNT))
		{
			puts("[-] ���㬭�� ������⢮ ��⮪�� ᪠��஢����!");
			status = 0;
		}

		if((conf->packets < CONF_MIN_PACKETS) || (conf->packets > CONF_MAX_PACKETS))
		{
			puts("[-] ���㬭�� ������⢮ ���������� ����⮢!");
			status = 0;
		}

		if((conf->maxhosts < CONF_MIN_MAXHOSTS) || (conf->maxhosts > CONF_MAX_MAXHOSTS))
		{
			puts("[-] ���㬭�� ������⢮ �����६���� ����㥬�� ��⮢!");
			status = 0;
		}

		if((conf->timeout < CONF_MIN_TIMEOUT) || (conf->timeout > CONF_MAX_TIMEOUT))
		{
			puts("[-] ���㬭� ⠩���� �����!");
			status = 0;
		}

		if((conf->delay < CONF_MIN_DELAY) || (conf->delay > CONF_MAX_DELAY))
		{
			puts("[-] ���㬭�� ����প� ����� ������祭�ﬨ � ����!");
			status = 0;
		}

		if((conf->iotimeout < CONF_MIN_IOTIMEOUT) || (conf->delay > CONF_MAX_IOTIMEOUT))
		{
			puts("[-] ���㬭� ⠩���� �����-�뢮��!");
			status = 0;
		}

		if((conf->retrycount < CONF_MIN_RETRYCOUNT) || (conf->retrycount > CONF_MAX_RETRYCOUNT))
		{
			puts("[-] ���㬭�� ���ᨬ��쭮� ������⢮ ����⮪ ᮥ�������!");
			status = 0;
		}

		if((conf->faildelay < CONF_MIN_FAILDELAY) || (conf->faildelay > CONF_MAX_FAILDELAY))
		{
			puts("[-] ���㬭�� ����প� �� ᡮ� ᮥ�������!");
			status = 0;
		}

		if((conf->socks != 4) && (conf->socks != 5))
		{
			puts("[-] ���㬭� ⨯ �ப�!");
			status = 0;
		}

		if(!conf->usernames.length)
		{
			puts("[!] �� 㪠���� �� ������ ������");
		}

		if(!conf->passwords.length)
		{
			puts("[!] �� 㪠���� �� ������ ��஫�");
		}

		if(status)
		{
			if(!conf->ports.length)
			{
				PORTRANGE *pr;
				if((pr = malloc(sizeof(PORTRANGE))))
				{
					pr->start = pr->end = CONF_DEF_PORT;
					vectoradd(&(conf->ports), pr);
					//puts("[*] �� 㪧��� �� ������ ����, �ᯮ��㥬 ���祭�� �� 㬮�砭��");
				}
			}
		}

		if(!status)
		{
			puts("[-] �������� ��ࠬ��� �� ���४��");
		}
		else
		{
			puts("[*] �������� ��ࠬ���� ����� ��");
		}

		puts("");


		return status;
	}
	return 0;
}

/* -------------------------------------------------------------------------- */

void conf_banner()
{
	puts("");
	puts("--- Lamescan 3 CLi �� redsh");
	puts("--- ����⮢���� � ����");
	puts("");
}

/* -------------------------------------------------------------------------- */

void conf_bottom_banner()
{
	puts("--- ����!");
}

/* -------------------------------------------------------------------------- */

void conf_help()
{
	puts("�ᯮ�짮�����:");
	puts("lscan3 [���� [���祭��1 [���祭��2 [...]]] [...]]");
	puts("");
	puts("����                  ���祭��                                       �� 㬮��.");
	puts("~~~~                  ~~~~~~~~                                       ~~~~~~~~~");
	puts("-?, --help            �뢥�� �� ᮮ�饭��");
	puts("-h, --host            ���� ���, �������� ��� �������� � CIDR-���樨 *");
	puts("-hl, --hostlist       ����㧨�� ���� �� 䠩��");
	puts("-p, --port            ���� ��� �������� ���⮢                       4899 **");
	puts("-t, --proxy           SOCKS-�ப�, � ���� [username[:password]@]host[:port]");
	puts("-u, --username        �������� �����");
	puts("-ul, --usernamelist   �������� ᫮���� �������");
	puts("-pw, --password       �������� ��஫�");
	puts("-pwl, --passwordlist  �������� ᫮���� ��஫��");
	puts("-i, --noping          �� ��������� ���� ��। ᪠��஢�����");
	puts("-e, --usehash         ��।����� � �ᯮ�짮���� ��� � ᫮��� ��஫��");
	puts("-a, --all             ��������� � ��� ���� � �訡���� ᪠��஢����");
	puts("-c, --count           ������⢮ ��⮪��                              32");
	puts("-n, --packets         ������⢮ ���������� ����⮢                  2");
	puts("-m, --maxhosts        ������⢮ �����६���� ����㥬�� ��⮢        8");
	puts("-w, --timeout         ������� �����                                   1000 ��");
	puts("-d, --delay           ����প� ����� ᮥ������ﬨ � ��⮬            500 ��");
	puts("-io, --iotimeout      ������� �������� �⢥� �ࢥ�                 60000 ��");
	puts("-r, --retrycount      ������⢮ ����⮪ ����୮�� ᮥ�������        4");
	puts("-f, --faildelay       ����প� (� ᥪ㭤��) ��᫥ ࠧ�뢠 ᮥ�������  120 �");
	puts("-o, --output          ���� ��� ��࠭���� १���⮢                 lscan3.log");
	puts("");
	puts(" * ���� �� 㬮�砭��");
	puts("** ���祭�� �� 㬮�砭�� �ᯮ������, �᫨ �� ������ ���� �� ��࠭� ������");
	puts("");
}

/* -------------------------------------------------------------------------- */
