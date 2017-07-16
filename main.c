/* -------------------------------------------------------------------------- */

#include <stdio.h>
#include <stdlib.h>
#include "cmdln.h"
#include "scan.h"
#include "tcp.h"

/* -------------------------------------------------------------------------- */

int main(int argc, char **argv)
{
	LSCANCONF conf;

	conf_banner();

	if(wsa_init())
	{
		if(conf_init(&conf))
		{
			if(conf_setup(&conf, argc, argv))
			{
				if(conf.showhelp)
				{
					conf_help();
				}
				else
				{
					if(conf_check(&conf))
					{
						scan(&conf);
					}
				}
			}
			conf_free(&conf);
		}
		wsa_final();
	}

	conf_bottom_banner();

	return 0;
}

/* -------------------------------------------------------------------------- */
