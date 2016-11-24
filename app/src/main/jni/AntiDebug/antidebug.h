#ifndef _ANTIDEBUG
#define _ANTIDEBUG

#include <stdio.h>
#include <sys/ptrace.h>
#include <stdlib.h>
#include <unistd.h>


extern void readStatus();

extern void AntiDebug();

extern void CalcTime(int, int);



#endif