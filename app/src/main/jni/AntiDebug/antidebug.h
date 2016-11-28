#ifndef _ANTIDEBUG
#define _ANTIDEBUG

#include <stdio.h>
#include <sys/ptrace.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/types.h>

extern void readStatus();

extern void AntiDebug();

extern void CalcTime(int, int);

void safe_attach(pid_t pid);

void handle_events();

extern int checkDebugger();

void checkAndroidServer();

#endif