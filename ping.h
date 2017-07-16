/* -------------------------------------------------------------------------- */

#ifndef __ping_h__
#define __ping_h__

/* -------------------------------------------------------------------------- */

#include <windows.h>
#include <ipexport.h>
#include <icmpapi.h>

/* -------------------------------------------------------------------------- */

int ping(unsigned int host, int *timeout, int *err, int packetcount);

/* -------------------------------------------------------------------------- */

#endif

/* -------------------------------------------------------------------------- */