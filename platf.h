/* -------------------------------------------------------------------------- */

#ifndef __platf_h__
#define __platf_h__

/* -------------------------------------------------------------------------- */

#include <windows.h>

/* -------------------------------------------------------------------------- */

typedef void (*thread_proc)(void *param);

/* -------------------------------------------------------------------------- */

typedef struct
{
	thread_proc proc;
	void *param;
} THREADPROCPARAM;

/* -------------------------------------------------------------------------- */

int threadstart(thread_proc proc, void *param);

void *mutexnew();
void mutexfree(void *m);
int mutexlock(void *m);
void mutexrelease(void *m);

void *semaphorenew(int count);
void semaphorefree(void *s);
int semaphorelock(void *s);
void semaphorerelease(void *s);

/* -------------------------------------------------------------------------- */

#endif

/* -------------------------------------------------------------------------- */
