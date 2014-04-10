#ifndef _DANE_COMMON_H_
#define _DANE_COMMON_H_

#include <errno.h>
#include <string.h>
#include "app.h"

char* getval(char *key, char *s, char *f, char *b, char *v);

int out_put_appinfo(apphead_t *appinfo);

int get_int(char *src, int s, char sep);


#endif

