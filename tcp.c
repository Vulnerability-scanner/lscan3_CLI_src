/* -------------------------------------------------------------------------- */

#include "tcp.h"

/* -------------------------------------------------------------------------- */

WSADATA wsa;

/* -------------------------------------------------------------------------- */

int tcp_open_indirect(tcp_open_struc *open_struc)
{
	if(open_struc->proxy_type == 0)
	{
		return tcp_open(open_struc->host, open_struc->port);
	}
	if(open_struc->proxy_type == 4)
	{
		return tcp_open_socks4(open_struc->host, open_struc->port,
			open_struc->proxy_host, open_struc->proxy_port);
	}
	else if(open_struc->proxy_type == 5)
	{
		return tcp_open_socks5(open_struc->host, open_struc->port,
			open_struc->proxy_host, open_struc->proxy_port,
			open_struc->proxy_username, open_struc->proxy_password);
	}
	else
	{
		return 0;
	}
}

/* -------------------------------------------------------------------------- */

int tcp_open(unsigned int host, int port)
{
	SOCKET sock;
	struct sockaddr_in addr;
	if((sock = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP)) != SOCKET_ERROR)
	{
		memset(&addr, 0, sizeof(addr));
		addr.sin_family = AF_INET;
		addr.sin_addr.S_un.S_addr = htonl(host);
		addr.sin_port = htons(port);
		if(connect(sock, (struct sockaddr*)&addr, sizeof(addr)) != SOCKET_ERROR)
		{
			return (int)sock;
		}
		closesocket(sock);
	}
	return 0;
}

/* -------------------------------------------------------------------------- */

int tcp_open_socks4(unsigned int host, int port, unsigned int proxy_host, int proxy_port)
{
	int conn, requestlen;
	socks4_request *request;
	socks4_reply reply;
	if((conn = tcp_open(proxy_host, proxy_port)))
	{
		requestlen = sizeof(socks4_request) + strlen(SOCKS4_ID) + 1;
		if((request = malloc(requestlen)))
		{
			request->ver = 4;
			request->mode = SOCKS4_MODE_CONNECT;
			request->port = htons(port);
			request->addr = htonl(host);
			strcpy(request->id, SOCKS4_ID);
			if(tcp_write(conn, request, requestlen))
			{
				if(tcp_read(conn, &reply, sizeof(reply)))
				{
					if( (reply.zero == 0) &&
						(reply.status == SOCKS4_STATUS_OK) )
					{
						free(request);
						return conn;
					}
				}
			}
			free(request);
		}
		tcp_close(conn);
	}
	return 0;
}

/* -------------------------------------------------------------------------- */

int tcp_open_socks5(unsigned int host, int port, unsigned int proxy_host, int proxy_port, char *proxy_username, char *proxy_password)
{
	int status = 0;
	int conn;
	int username_len, password_len, buff_len;
	char *buff, *p;
	socks5_client_hello *client_hello;
	int client_hello_len;
	socks5_server_hello server_hello;
	socks5_request request;
	socks5_reply reply;
	socks5_auth_reply auth_reply;
	if((conn = tcp_open(proxy_host, proxy_port)))
	{

		//handshake
		status = 0;
		if(proxy_username && proxy_password)
		{
			client_hello_len = sizeof(socks5_client_hello) + 2;
			if((client_hello = malloc(client_hello_len)))
			{
				client_hello->ver = 5;
				client_hello->count = 2;
				client_hello->methods[0] = SOCKS5_METHOD_NONE;
				client_hello->methods[1] = SOCKS5_METHOD_USERNAME;
				status = 1;
			}
		}
		else
		{
			client_hello_len = sizeof(socks5_client_hello) + 1;
			if((client_hello = malloc(client_hello_len)))
			{
				client_hello->ver = 5;
				client_hello->count = 1;
				client_hello->methods[0] = SOCKS5_METHOD_NONE;
				status = 1;
			}
		}
		if(status)
		{
			status = 0;
			if(tcp_write(conn, client_hello, client_hello_len))
				status = 1;
			free(client_hello);
		}
		if(status)
		{
			status = 0;
			if(tcp_read(conn, &server_hello, sizeof(server_hello)))
			{
				if(server_hello.ver == 5)
				{
					if(server_hello.status == SOCKS5_METHOD_NONE)
					{
						status = 1;
					}
					else if(server_hello.status == SOCKS5_METHOD_USERNAME)
					{
						if(proxy_username && proxy_password)
							status = 1;
					}
				}
			}
		}

		//authorize if needed
		if(status)
		{
			if(server_hello.status == SOCKS5_METHOD_USERNAME)
			{
				status = 0;
				username_len = (int)strlen(proxy_username);
				password_len = (int)strlen(proxy_password);
				buff_len = username_len + password_len + 3;
				if((buff = malloc(buff_len)))
				{
					p = buff;
					*(p++) = 1;
					*(p++) = username_len;
					memcpy(p, proxy_username, username_len);
					p += username_len;
					*(p++) = password_len;
					memcpy(p, proxy_password, password_len);
					p += password_len;
					if(tcp_write(conn, buff, buff_len))
						status = 1;
					free(buff);
				}
				if(status)
				{
					status = 0;
					if(tcp_read(conn, &auth_reply, sizeof(auth_reply)))
					{
						if( (auth_reply.ver == 1) &&
							(auth_reply.status == SOCKS5_STATUS_OK) )
						{
							status = 1;
						}
					}
				}
			}
		}

		//connect
		if(status)
		{
			status = 0;
			request.ver = 5;
			request.mode = SOCKS5_MODE_CONNECT;
			request.zero = 0;
			request.type = SOCKS5_TYPE_IPV4;
			request.addr = htonl(host);
			request.port = htons(port);
			if(tcp_write(conn, &request, sizeof(request)))
				status = 1;
		}
		if(status)
		{
			status = 0;
			if(tcp_read(conn, &reply, sizeof(reply)))
			{
				if( (reply.ver == 5) &&
					(reply.status == SOCKS5_STATUS_OK) )
				{
					status = 1;
				}
			}
		}

		//connected
		if(status)
		{
			return conn;
		}

		tcp_close(conn);
	}
	return 0;
}

/* -------------------------------------------------------------------------- */

void tcp_close(int conn)
{
	if(conn)
	{
		shutdown((SOCKET)conn, 1);
		closesocket((SOCKET)conn);
	}
}

/* -------------------------------------------------------------------------- */

int tcp_wait_read(int conn, int timeout)
{
	int timeout_us;
	struct timeval tv;
	FD_SET set;
	timeout_us = timeout*1000;
	tv.tv_sec = timeout_us / 1000000;
	tv.tv_usec = timeout_us % 1000000;
	FD_ZERO(&set);
	FD_SET((SOCKET)conn, &set);
	if(select(0, &set, NULL, NULL, &tv) == 1)
		return 1;
	return 0;
}

/* -------------------------------------------------------------------------- */

int tcp_wait_write(int conn, int timeout)
{
	int timeout_us;
	struct timeval tv;
	FD_SET set;
	timeout_us = timeout*1000;
	tv.tv_sec = timeout_us / 1000000;
	tv.tv_usec = timeout_us % 1000000;
	FD_ZERO(&set);
	FD_SET((SOCKET)conn, &set);
	if(select(0, NULL, &set, NULL, &tv) == 1)
		return 1;
	return 0;
}

/* -------------------------------------------------------------------------- */

int tcp_read(int conn, void *buf, int length)
{
	int pos, temp;
	for(pos = 0; pos < length; pos += temp)
	{
		if((temp = recv((SOCKET)conn, (char*)buf+pos, length-pos, 0)) <= 0)
			return 0;
	}
	return 1;
}

/* -------------------------------------------------------------------------- */

int tcp_write(int conn, void *buf, int length)
{
	int pos, temp;
	for(pos = 0; pos < length; pos += temp)
	{
		if((temp = send((SOCKET)conn, (char*)buf+pos, length-pos, 0)) <= 0)
			return 0;
	}
	return 1;
}

/* -------------------------------------------------------------------------- */

int tcp_read_ex(int conn, void *buf, int length, int timeout)
{
	int pos, temp;
	for(pos = 0; pos < length; pos += temp)
	{
		if(!tcp_wait_read(conn, timeout))
			return 0;
		if((temp = recv((SOCKET)conn, (char*)buf+pos, length-pos, 0)) <= 0)
			return 0;
	}
	return 1;
}

/* -------------------------------------------------------------------------- */

int tcp_write_ex(int conn, void *buf, int length, int timeout)
{
	int pos, temp;
	for(pos = 0; pos < length; pos += temp)
	{
		if(!tcp_wait_write(conn, timeout))
			return 0;
		if((temp = send((SOCKET)conn, (char*)buf+pos, length-pos, 0)) <= 0)
			return 0;
	}
	return 1;
}

/* -------------------------------------------------------------------------- */

unsigned int tcp_addr(char *ip)
{
	unsigned int addr;
	if((addr = inet_addr(ip)) != INADDR_NONE)
	{
		return ntohl(addr);
	}
	return 0;
}

/* -------------------------------------------------------------------------- */

int wsa_init()
{
	if(!WSAStartup(MAKEWORD(1, 1), &wsa))
		return 1;
	return 0;
}

/* -------------------------------------------------------------------------- */

void wsa_final()
{
	WSACleanup();
}

/* -------------------------------------------------------------------------- */
