#ifndef _DANE_APP_H_
#define _DANE_APP_H_

#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <stdarg.h>
#include <time.h>
#include "list.h"

typedef struct {
	char appname[64];
	char appname1[64];
	char author[128];
	char desc[512];
	char version[64];

	char downurl[512];
	char imgurl[512];
}apphead_t;

typedef struct
{
	list_head_t applist;
	apphead_t apphead;
}appinfo_t;

#endif

