/* -------------------------------------------------------------------------- */

#include "radmin.h"

/* -------------------------------------------------------------------------- */

char radmin_reply_challenge_iv[16] = 
	"\xFE\xDC\xBA\x98\x76\x54\x32\x10\xA3\x9D\x4A\x18\xF8\x5B\x4A\x52";

/* -------------------------------------------------------------------------- */

int radmin_crc(void *data, int datalen)
{
	int crc = 0, temp;
	int *p = (int*)data;
	while(datalen > 0)
	{
		temp = *(p++);
		if(datalen == 3) temp &= 0x00ffffff;
		if(datalen == 2) temp &= 0x0000ffff;
		if(datalen == 1) temp &= 0x000000ff;
		crc += temp;
		datalen -= 4;
	}
	return crc;
}

/* -------------------------------------------------------------------------- */

unsigned char radmin_hexdigit(char c)
{
	if((c >= '0') && (c <= '9'))
		return c - '0';
	else if((c >= 'a') && (c <= 'f'))
		return c - 'a' + 10;
	else if((c >= 'A') && (c <= 'F'))
		return c - 'A' + 10;
	return 0xff;
}

/* -------------------------------------------------------------------------- */

char *radmin_hexdecode(char *hex, char *buff, size_t *buflen)
{
	size_t len, i, tmp;
	unsigned char a, b;
	len = strlen(hex);
	tmp = 0;
	i = 0;
	while(len >= 2)
	{
		if(tmp >= *buflen)
		{
			return NULL;
		}
		if( ((b = radmin_hexdigit(hex[i])) == 0xff) ||
			((a = radmin_hexdigit(hex[i+1])) == 0xff) )
		{
			return NULL;
		}
		*(buff++) = a | (b << 4);
		tmp++;
		len -= 2;
		i += 2;
	}
	if(len != 0)
	{
		return NULL;
	}
	*buflen = tmp;
	return buff;
}

/* -------------------------------------------------------------------------- */

int radmin_twofish_encrypt(void *dst, void *src, void *iv, void *key, int datalen)
{
	keyInstance ki;
	cipherInstance ci;

	if(!makeKey(&ki, DIR_ENCRYPT, 128, NULL))
		return 0;
	if(!cipherInit(&ci, MODE_CBC, NULL))
		return 0;

	memcpy(ki.key32, key, 16);
	if(!reKey(&ki))
		return 0;
	
	memcpy(ci.iv32, iv, 16);
	
	if(!blockEncrypt(&ci, &ki, src, datalen*8, dst))
		return 0;

	return 1;
}

/* -------------------------------------------------------------------------- */

int radmin_reply_challenge(void *dst, void *src, char *pass, int byhash)
{
	int i;
	char *p;
	char hash[16];
	char passbuf[100];
	size_t buflen;

	if(!byhash)
	{
		memset(passbuf, 0, 100);
		strncpy(passbuf, pass, 100);
		if(!MD5(passbuf, 100, hash))
			return 0;
	}
	else
	{
		buflen = sizeof(hash);
		if(!radmin_hexdecode(pass, hash, &buflen))
			return 0;
		if(buflen != 16)
			return 0;
	}

	if(!radmin_twofish_encrypt(dst, src, radmin_reply_challenge_iv, hash, 32))
		return 0;

	p = (char*)dst;
	for(i = 0; i < 16; ++i)
	{
		p[i] += p[i+16];
		p[i+16] = 0;
	}

	return 1;
}

/* -------------------------------------------------------------------------- */

int radmin_send_packet_ver1(int conn, radmin_packet_ver1 *packet, int timeout)
{
	int status = 0;
	radmin_packet_header_ver1 header;
	radmin_packet_data_ver1 *block;
	int blocklen;
	if(packet)
	{
		blocklen = sizeof(radmin_packet_data_ver1) + packet->datalen;
		if((block = malloc(blocklen)))
		{
			block->code = packet->code;
			memcpy(block->data, packet->data, packet->datalen);
			header.one = 1;
			header.datalen = htonl(blocklen);
			header.datacrc = htonl(radmin_crc(block, blocklen));
			if(tcp_write_ex(conn, &header, sizeof(header), timeout))
			{
				if(tcp_write_ex(conn, block, blocklen, timeout))
					status = 1;
			}
			free(block);
		}
	}
	return status;
}

/* -------------------------------------------------------------------------- */

int radmin_recv_packet_ver1(int conn, radmin_packet_ver1 *packet, int timeout)
{
	int status = 0;
	int blocklen;
	int datalen;
	radmin_packet_header_ver1 header;
	radmin_packet_data_ver1 *block;
	if(packet)
	{
		packet->code = 0;
		packet->datalen = 0;
		packet->data = NULL;
		if(tcp_read_ex(conn, &header, sizeof(header), timeout))
		{
			blocklen = ntohl(header.datalen);
			if(blocklen <= RADMIN_MAX_DATA_BLOCK)
			{
				if((block = malloc(blocklen)))
				{
					if(tcp_read_ex(conn, block, blocklen, timeout))
					{
						if(radmin_crc(block, blocklen) == ntohl(header.datacrc))
						{
							datalen = blocklen - sizeof(radmin_packet_data_ver1);
							if((packet->data = malloc(datalen)))
							{
								packet->code = block->code;
								packet->datalen = datalen;
								memcpy(packet->data, block->data, datalen);
								status = 1;
							}
						}
					}
					free(block);
				}
			}
		}
	}
	return status;
}

/* -------------------------------------------------------------------------- */

int radmin_send_packet_ver2(int conn, radmin_packet_ver2 *packet, int timeout)
{
	int i;
	int length;
	int status = 0;
	radmin_packet_header_ver2 header;
	radmin_packet_data_ver2 dataheader;
	if(packet)
	{
		length = sizeof(radmin_packet_header_ver2);
		for(i = 0; i < packet->count; ++i)
		{
			length += sizeof(radmin_packet_data_ver2) +
				packet->data[i].size;
		}
		length = htonl(length);
		if(tcp_write_ex(conn, &length, sizeof(length), timeout))
		{
			header.flags = htonl(packet->flags);
			header.seq = htonl(packet->seq);
			if(tcp_write_ex(conn, &header, sizeof(header), timeout))
			{
				for(i = 0; i < packet->count; ++i)
				{
					dataheader.id = htons(packet->data[i].id);
					dataheader.size = htons(packet->data[i].size);
					if(!tcp_write_ex(conn, &dataheader, sizeof(dataheader), timeout))
						break;
					if(!tcp_write_ex(conn, packet->data[i].data, packet->data[i].size, timeout))
						break;
				}
				if(i == packet->count)
				{
					status = 1;
				}
			}
		}
	}
	return status;
}

/* -------------------------------------------------------------------------- */

int radmin_recv_packet_ver2(int conn, radmin_packet_ver2 *packet, int timeout)
{
	int status = 0;
	int length;
	char *buffer;
	char *dataptr;
	int blocklen;
	int limit = 0, count = 0;
	radmin_subpacket_ver2 *temp = NULL;
	radmin_packet_header_ver2 *header;
	radmin_packet_data_ver2 *dataheader;
	if(packet)
	{
		memset(packet, 0, sizeof(radmin_packet_ver2));
		if(tcp_read_ex(conn, &length, sizeof(length), timeout))
		{
			length = ntohl(length);
			if(length <= RADMIN_MAX_DATA_BLOCK)
			{
				if((buffer = malloc(length)))
				{
					if(tcp_read_ex(conn, buffer, length, timeout))
					{
						dataptr = buffer;
						if(length >= sizeof(radmin_packet_header_ver2))
						{
							status = 1;
							header = (void*)dataptr;
							packet->flags = ntohl(header->flags);
							packet->seq = ntohl(header->seq);
							dataptr += sizeof(radmin_packet_header_ver2);
							length -= sizeof(radmin_packet_header_ver2);
							while(length >= sizeof(radmin_packet_data_ver2))
							{
								dataheader = (void*)dataptr;
								dataptr += sizeof(radmin_packet_data_ver2);
								length -= sizeof(radmin_packet_data_ver2);
								blocklen = ntohs(dataheader->size);
								if(blocklen > length)
									blocklen = length;
								if(count == limit)
								{
									limit += 4;
									if(!(temp = realloc(temp, 
										limit*sizeof(radmin_subpacket_ver2))))
									{
										status = 0;
										break;
									}
								}
								if(!(temp[count].data = malloc(blocklen)))
								{
									status = 0;
									break;
								}
								temp[count].id = ntohs(dataheader->id);
								temp[count].size = blocklen;
								memcpy(temp[count].data, dataptr, blocklen);
								count++;
								dataptr += blocklen;
								length -= blocklen;
							}
							if(status)
							{
								packet->count = count;
								packet->data = temp;
							}
						}
					}
					free(buffer);
				}
			}
		}
	}
	return status;
}

/* -------------------------------------------------------------------------- */

void radmin_free_packet_ver2(radmin_packet_ver2 *packet)
{
	int i;
	if(packet)
	{
		if(packet->data)
		{
			for(i = 0; i < packet->count; ++i)
				free(packet->data[i].data);
			free(packet->data);
		}
		//free(packet);
	}
}

/* -------------------------------------------------------------------------- */

radmin_subpacket_ver2 *radmin_search_packet_ver2(radmin_packet_ver2 *packet, int code)
{
	int i;
	if(packet)
	{
		if(packet->data)
		{
			for(i = 0; i < packet->count; ++i)
			{
				if(packet->data[i].id == code)
					return packet->data + i;
			}
		}
	}
	return NULL;
}

/* -------------------------------------------------------------------------- */

wchar_t *to_unicode(char *str)
{
	int length;
	wchar_t *buff = NULL;
	if((length = MultiByteToWideChar(CP_ACP, 0, str, -1, NULL, 0)))
	{
		if((buff = malloc(length * sizeof(wchar_t))))
		{
			if(MultiByteToWideChar(CP_ACP, 0, str, -1, buff, length))
			{
				return buff;
			}
			free(buff);
		}
	}
	return NULL;
}

/* -------------------------------------------------------------------------- */

void unicode_to_be(wchar_t *buff)
{
	wchar_t *p;
	for(p = buff; *p; ++p)
		*p = htons(*p);
}

/* -------------------------------------------------------------------------- */

/*
 * пробует подключиться к серверу и запросить версию
 */

int radmin_check_version(tcp_open_struc *host, char **ver, int *auth, int timeout)
{
	int status = 0;
	int conn, flags;
	radmin_packet_ver1 request, response;

	if( host && ver && auth )
	{
		*ver = "N/A";
		*auth = RADMIN_AUTH_UNKNOWN;

		if((conn = tcp_open_indirect(host)))
		{
			request.code = 0x08;
			request.datalen = 0;
			request.data = NULL;
			if(radmin_send_packet_ver1(conn, &request, timeout))
			{
				if(radmin_recv_packet_ver1(conn, &response, timeout))
				{
					if( (response.code == 0x08) &&
						(response.datalen >= 4) )
					{
						flags = *((int*)(response.data));

						switch(flags & 0x0A000003)
						{
						case 0x08000000:
						case 0x08000001:
							switch(flags & 0x00080001)
							{
							case 0x00000000: *ver = "2.0"; break;
							case 0x00080001: *ver = "2.1"; break;
							case 0x00000001: *ver = "2.2"; break;
							}
							switch(flags & 0x00030000)
							{
							case 0x00000000: *auth = RADMIN_AUTH_NATIVE_2; break;
							case 0x00010000: *auth = RADMIN_AUTH_NTLM_2; break;
							case 0x00020000: *auth = RADMIN_AUTH_NONE_2; break;
							}
							break;
						case 0x0A000002:
							*ver = "3";
							switch(flags & 0x00030000)
							{
							case 0x00000000: *auth = RADMIN_AUTH_NATIVE_3; break;
							case 0x00010000: *auth = RADMIN_AUTH_NTLM_3; break;
							case 0x00020000: *auth = RADMIN_AUTH_NONE_3; break;
							}
							break;
						}

						status = 1;

					}
					free(response.data);
				}
			}
			tcp_close(conn);
		}
	}
	return status;
}

/* -------------------------------------------------------------------------- */

/*
 * авторизация радмин2
 */

int radmin_auth2(tcp_open_struc *host, char *password, int timeout, int byhash)
{
	radmin_packet_ver1 request, challenge, response, acknowledge;
	int status = RADMIN_STATUS_ERROR;
	int conn;
	char resp[32];
	if((conn = tcp_open_indirect(host)))
	{
		request.code = 0x1b;
		request.datalen = 0;
		request.data = NULL;
		if(radmin_send_packet_ver1(conn, &request, timeout))
		{
			if(radmin_recv_packet_ver1(conn, &challenge, timeout))
			{
				if((challenge.code == 0x1b) && (challenge.datalen == 32))
				{
					if(radmin_reply_challenge(resp, challenge.data, password, byhash))
					{
						response.code = 0x09;
						response.data = resp;
						response.datalen = 32;
						if(radmin_send_packet_ver1(conn, &response, timeout))
						{
							if(radmin_recv_packet_ver1(conn, &acknowledge, timeout))
							{
								if(acknowledge.code == 0x0a)
									status = RADMIN_STATUS_SUCCESS;
								else if(acknowledge.code == 0x0b)
									status = RADMIN_STATUS_PASSERR;
								else
									status = RADMIN_STATUS_PROTOERR;
								free(acknowledge.data);
							}
						}
					}
				}
				else
				{
					status = RADMIN_STATUS_PROTOERR;
				}
				free(challenge.data);
			}
		}
		tcp_close(conn);
	}
	return status;
}

/* -------------------------------------------------------------------------- */

/*
 * авторизация радмин3
 */

int radmin_auth3(tcp_open_struc *host, char *username, char *password, int timeout)
{
	SRP *srp;

	int status = RADMIN_STATUS_ERROR;
	int conn;
	wchar_t *user = NULL, *pass = NULL, *user_be;
	int userlen, passlen;

	radmin_packet_ver1 hello;
	radmin_packet_ver1 hello_ack;

	radmin_subpacket_ver2 name_data[1];
	radmin_packet_ver2 name;

	radmin_packet_ver2 srp1;
	radmin_subpacket_ver2 *n, *g, *s;

	radmin_packet_ver2 srp2;
	radmin_subpacket_ver2 srp2_data[1];

	radmin_packet_ver2 srp3;
	radmin_subpacket_ver2 *p;

	radmin_packet_ver2 srp4;
	radmin_subpacket_ver2 srp4_data[1];
	
	radmin_packet_ver2 srp5;
	radmin_subpacket_ver2 *v;

	cstr *skey, *resp, *pub;

	if( (user = to_unicode(username)) &&
		(pass = to_unicode(password)) )
	{
		userlen = wcslen(user) * sizeof(wchar_t);
		passlen = wcslen(pass) * sizeof(wchar_t);

		if((user_be = wcsdup(user)))
		{
			unicode_to_be(user_be);

			if((conn = tcp_open_indirect(host)))
			{
				hello.code = 0x27;
				hello.datalen = 4;
				hello.data = "\x02\x00\x00\x00";
				if(radmin_send_packet_ver1(conn, &hello, timeout))
				{
					if(radmin_recv_packet_ver1(conn, &hello_ack, timeout))
					{
						if(hello_ack.code == 0x27)
						{
							if((srp = SRP_new(SRP6a_client_method())))
							{
								name_data[0].id = 0x2000;
								name_data[0].data = user_be;
								name_data[0].size = userlen;
								name.flags = 0x10000004;
								name.seq = 1;
								name.count = 1;
								name.data = name_data;
								if(radmin_send_packet_ver2(conn, &name, timeout))
								{
									if(!SRP_set_user_raw(srp, user, userlen))
									{
										if(radmin_recv_packet_ver2(conn, &srp1, timeout))
										{
											if(srp1.seq == 0)
											{
												status = RADMIN_STATUS_NAMEERR;
											}
											else if(srp1.seq == 2)
											{
												if((n = radmin_search_packet_ver2(&srp1, 0x3000)) &&
													(g = radmin_search_packet_ver2(&srp1, 0x4000)) &&
													(s = radmin_search_packet_ver2(&srp1, 0x5000)) )
												{
													if( (!SRP_set_params(srp, n->data, n->size, 
														g->data, g->size, s->data, s->size)) &&
														(!SRP_set_auth_password_raw(srp, pass, passlen)) )
													{
														if( (pub = cstr_new()))
														{
															if(!SRP_gen_pub(srp, &pub))
															{
																srp2_data[0].id = 0x6000;
																srp2_data[0].data = pub->data;
																srp2_data[0].size = pub->length;
																srp2.flags = 0x10000004;
																srp2.seq = 3;
																srp2.count = 1;
																srp2.data = srp2_data;
																if(radmin_send_packet_ver2(conn, &srp2, timeout))
																{
																	if(radmin_recv_packet_ver2(conn, &srp3, timeout))
																	{
																		if(srp3.seq == 4)
																		{
																			if( (p = radmin_search_packet_ver2(&srp3, 0x6000)) )
																			{
																				if((skey = cstr_new()))
																				{
																					if(!SRP_compute_key(srp, &skey, p->data, p->size))
																					{
																						if((resp = cstr_new()))
																						{
																							if(!SRP_respond(srp, &resp))
																							{
																								srp4_data[0].id = 0x7000;
																								srp4_data[0].size = resp->length;
																								srp4_data[0].data = resp->data;
																								srp4.flags = 0x10000004;
																								srp4.seq = 5;
																								srp4.count = 1;
																								srp4.data = srp4_data;
																								if(radmin_send_packet_ver2(conn, &srp4, timeout))
																								{
																									if(radmin_recv_packet_ver2(conn, &srp5, timeout))
																									{
																										if(srp5.seq == 0)
																										{
																											status = RADMIN_STATUS_PASSERR;
																										}
																										else if(srp5.seq == 6)
																										{
																											if( (v = radmin_search_packet_ver2(&srp5, 0x7000)) )
																											{
																												if(!SRP_verify(srp, v->data, v->size))
																												{
																													status = RADMIN_STATUS_SUCCESS;
																												}
																												else
																												{
																													status = RADMIN_STATUS_PASSERR;
																												}
																											}
																											else
																											{
																												status = RADMIN_STATUS_PROTOERR;
																											}
																										}
																										else
																										{
																											status = RADMIN_STATUS_PROTOERR;
																										}
																									}
																									radmin_free_packet_ver2(&srp5);
																								}
																							}
																							else
																							{
																								status = RADMIN_STATUS_ALGOERR;
																							}
																							cstr_free(resp);
																						}
																					}
																					else
																					{
																						status = RADMIN_STATUS_ALGOERR;
																					}
																					cstr_free(skey);
																				}
																			}
																			else
																			{
																				status = RADMIN_STATUS_PROTOERR;
																			}
																		}
																		else
																		{
																			status = RADMIN_STATUS_PROTOERR;
																		}
																		radmin_free_packet_ver2(&srp3);
																	}
																}
															}
															else
															{
																status = RADMIN_STATUS_ALGOERR;
															}
															cstr_free(pub);
														}
													}
													else
													{
														status = RADMIN_STATUS_ALGOERR;
													}
												}
												else
												{
													status = RADMIN_STATUS_PROTOERR;
												}
											}
											else
											{
												status = RADMIN_STATUS_PROTOERR;
											}
											radmin_free_packet_ver2(&srp1);
										}
									}
									else
									{
										status = RADMIN_STATUS_ALGOERR;
									}
								}
								SRP_free(srp);
							}
							else
							{
								status = RADMIN_STATUS_ALGOERR;
							}
						}
						else
						{
							status = RADMIN_STATUS_PROTOERR;
						}
					}
				}
				tcp_close(conn);
			}
		}
	}
	free(user);
	free(pass);
	return status;
}

/* -------------------------------------------------------------------------- */
