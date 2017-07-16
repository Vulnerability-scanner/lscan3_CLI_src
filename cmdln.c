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
		printf("[!] Неизвестный ключ: %s\n", sw);
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
			printf("[-] Некорректный хост/диапазон: %s\n", val);
			return 0;
		}
		vectoradd(&(conf->hosts), temp);
	}

	else if(sw_test(sw, "p", "-port"))
	{
		PORTRANGE *temp;
		if(!(temp = portrangeparse(val)))
		{
			printf("[-] Некорректный порт/диапазон: %s\n", val);
			return 0;
		}
		vectoradd(&(conf->ports), temp);
	}
	
	else if(sw_test(sw, "t", "-proxy"))
	{
		PROXY *temp;
		if(!(temp = proxyparse(val)))
		{
			printf("[-] Некорректный прокси: %s\n", val);
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
			printf("[-] Ошибка импорта \"%s\"\n", val);
		}
	}
	
	else if(sw_test(sw, "ul", "-usernamelist"))
	{
		if(!(vectoraddfile(&(conf->usernames), val)))
		{
			printf("[-] Ошибка импорта \"%s\"\n", val);
			return 0;
		}
	}
	
	else if(sw_test(sw, "pwl", "-passwordlist"))
	{
		if(!(vectoraddfile(&(conf->passwords), val)))
		{
			printf("[-] Ошибка импорта \"%s\"\n", val);
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
		printf("[!] Проигнорировано: %s\n", val);
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

		puts("[*] Парсим командную строку");

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
			puts("[*] Командная строка успешно распарсена");
		}
		else
		{
			puts("[-] Не удалось распарсить командную строку");
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

		puts("[*] Проверяем указанные параметры на валидность");

		if(!conf->hosts.length)
		{
			puts("[-] Не задано ни одного хоста");
			status = 0;
		}

		if((conf->count < CONF_MIN_COUNT) || (conf->count > CONF_MAX_COUNT))
		{
			puts("[-] Безумное количество потоков сканирования!");
			status = 0;
		}

		if((conf->packets < CONF_MIN_PACKETS) || (conf->packets > CONF_MAX_PACKETS))
		{
			puts("[-] Безумное количество пинговочных пакетов!");
			status = 0;
		}

		if((conf->maxhosts < CONF_MIN_MAXHOSTS) || (conf->maxhosts > CONF_MAX_MAXHOSTS))
		{
			puts("[-] Безумное количество одновременно пингуемых хостов!");
			status = 0;
		}

		if((conf->timeout < CONF_MIN_TIMEOUT) || (conf->timeout > CONF_MAX_TIMEOUT))
		{
			puts("[-] Безумный таймаут пинга!");
			status = 0;
		}

		if((conf->delay < CONF_MIN_DELAY) || (conf->delay > CONF_MAX_DELAY))
		{
			puts("[-] Безумная задержка между подключениями к хосту!");
			status = 0;
		}

		if((conf->iotimeout < CONF_MIN_IOTIMEOUT) || (conf->delay > CONF_MAX_IOTIMEOUT))
		{
			puts("[-] Безумный таймаут ввода-вывода!");
			status = 0;
		}

		if((conf->retrycount < CONF_MIN_RETRYCOUNT) || (conf->retrycount > CONF_MAX_RETRYCOUNT))
		{
			puts("[-] Безумное максимальное количество попыток соединения!");
			status = 0;
		}

		if((conf->faildelay < CONF_MIN_FAILDELAY) || (conf->faildelay > CONF_MAX_FAILDELAY))
		{
			puts("[-] Безумная задержка при сбое соединения!");
			status = 0;
		}

		if((conf->socks != 4) && (conf->socks != 5))
		{
			puts("[-] Безумный тип прокси!");
			status = 0;
		}

		if(!conf->usernames.length)
		{
			puts("[!] Не указано ни одного логина");
		}

		if(!conf->passwords.length)
		{
			puts("[!] Не указано ни одного пароля");
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
					//puts("[*] Не укзано ни одного порта, используем значение по умолчанию");
				}
			}
		}

		if(!status)
		{
			puts("[-] Указанные параметны не корректны");
		}
		else
		{
			puts("[*] Указанные параметры можно юзать");
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
	puts("--- Lamescan 3 CLi от redsh");
	puts("--- Изготовлено в СССР");
	puts("");
}

/* -------------------------------------------------------------------------- */

void conf_bottom_banner()
{
	puts("--- Удачи!");
}

/* -------------------------------------------------------------------------- */

void conf_help()
{
	puts("Использование:");
	puts("lscan3 [ключ [значение1 [значение2 [...]]] [...]]");
	puts("");
	puts("Ключ                  Значение                                       По умолч.");
	puts("~~~~                  ~~~~~~~~                                       ~~~~~~~~~");
	puts("-?, --help            Вывести это сообщение");
	puts("-h, --host            Один хост, диапазон или диапазон в CIDR-нотации *");
	puts("-hl, --hostlist       Загрузить хосты из файла");
	puts("-p, --port            Порт или диапазон портов                       4899 **");
	puts("-t, --proxy           SOCKS-прокси, в виде [username[:password]@]host[:port]");
	puts("-u, --username        Добавить логин");
	puts("-ul, --usernamelist   Добавить словарь логинов");
	puts("-pw, --password       Добавить пароль");
	puts("-pwl, --passwordlist  Добавить словарь паролей");
	puts("-i, --noping          Не пинговать хосты перед сканированием");
	puts("-e, --usehash         Определять и использовать хэши в словаре паролей");
	puts("-a, --all             Добавлять в лог хосты с ошибками сканирования");
	puts("-c, --count           Количество потоков                              32");
	puts("-n, --packets         Количество пинговочных пакетов                  2");
	puts("-m, --maxhosts        Количество одновременно пингуемых хостов        8");
	puts("-w, --timeout         Таймаут пинга                                   1000 мс");
	puts("-d, --delay           Задержка между соединениями с хостом            500 мс");
	puts("-io, --iotimeout      Таймаут ожидания ответа сервера                 60000 мс");
	puts("-r, --retrycount      Количество попыток повторного соединения        4");
	puts("-f, --faildelay       Задержка (в секундах) после разрыва соединения  120 с");
	puts("-o, --output          Файл для сохранения результатов                 lscan3.log");
	puts("");
	puts(" * Ключ по умолчанию");
	puts("** Значение по умолчанию используется, если ни одного порта не выбрано вручную");
	puts("");
}

/* -------------------------------------------------------------------------- */
