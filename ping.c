/* -------------------------------------------------------------------------- */

#include "ping.h"

/* -------------------------------------------------------------------------- */

int ping(unsigned int host, int *timeout, int *err, int packetcount)
{
	HANDLE icmp;
	int status = 0;
	ICMP_ECHO_REPLY *reply;
	int replylen;
	int i;

	*err = 1;

	if((icmp = IcmpCreateFile()) != INVALID_HANDLE_VALUE)
	{
		replylen = sizeof(ICMP_ECHO_REPLY) + 32;
		
		if((reply = malloc(replylen)))
		{
			for(i = 0; i < packetcount; ++i)
			{
				if(IcmpSendEcho(
					icmp,
					(IPAddr)htonl(host),
					NULL,
					0,
					NULL,
					reply,
					(DWORD)replylen,
					(DWORD)*timeout))
				{
					if(reply->Status == IP_SUCCESS)
					{
						*timeout = reply->RoundTripTime;
						status = 1;
					}
				}

				if(status)
				{
					break;
				}
			}
			free(reply);

			*err = 0;
		}

		IcmpCloseHandle(icmp);
	}


	return status;
}

/* -------------------------------------------------------------------------- */
