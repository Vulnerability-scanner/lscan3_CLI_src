/* -------------------------------------------------------------------------- */

#include "platf.h"

/* -------------------------------------------------------------------------- */

void *mutexnew()
{
	return CreateMutex(NULL, 
		FALSE, NULL);
}

/* -------------------------------------------------------------------------- */

void mutexfree(void *m)
{
	if(m)
	{
		CloseHandle(m);
	}
}

/* -------------------------------------------------------------------------- */

int mutexlock(void *m)
{
	if(m)
	{
		if(WaitForSingleObject(m, 
			INFINITE) == WAIT_OBJECT_0)
		{
			return 1;
		}
	}
	return 0;
}

/* -------------------------------------------------------------------------- */

void mutexrelease(void *m)
{
	if(m)
	{
		ReleaseMutex(m);
	}
}

/* -------------------------------------------------------------------------- */

void *semaphorenew(int count)
{
	return CreateSemaphore(NULL, count, count, NULL);
}

/* -------------------------------------------------------------------------- */

void semaphorefree(void *s)
{
	if(s)
	{
		CloseHandle(s);
	}
}

/* -------------------------------------------------------------------------- */

int semaphorelock(void *s)
{
	if(s)
	{
		if(WaitForSingleObject(s, INFINITE) == WAIT_OBJECT_0)
			return 1;
	}
	return 0;
}

/* -------------------------------------------------------------------------- */

void semaphorerelease(void *s)
{
	if(s)
	{
		ReleaseSemaphore(s, 1, NULL);
	}
}

/* -------------------------------------------------------------------------- */

DWORD WINAPI threadproc(THREADPROCPARAM *temp)
{
	temp->proc(temp->param);
	free(temp);
	return 0;
}

/* -------------------------------------------------------------------------- */

int threadstart(thread_proc proc, void *param)
{
	if(proc)
	{
		THREADPROCPARAM *temp;
		if((temp = malloc(sizeof(THREADPROCPARAM))))
		{
			HANDLE thread;
			temp->proc = proc;
			temp->param = param;
			if((thread = CreateThread(NULL, 0, 
				threadproc, temp, 0, NULL)))
			{
				CloseHandle(thread);
				return 1;
			}
			free(temp);
		}
	}
	return 0;
}

/* -------------------------------------------------------------------------- */
