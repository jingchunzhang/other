#ifndef __SPIDER_LOG_H
#define __SPIDER_LOG_H
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <stdarg.h>
#include <time.h>

extern int rlog;
extern int loglevel;

#define LOG_TRACE  0
#define LOG_DEBUG  1
#define LOG_NORMAL 2
#define LOG_ERROR  3
#define LOG_FAULT  4

void wlog(int fd, int level, const char* fmt, ...); 

#endif
