#ifndef __SPLIT_H_
#define __SPLIT_H_
#include <scws.h>
#include <stdlib.h>
#include "myhash.h"
#include "myshm.h"

int init_split(char *dict, char *rule);

int split_app(char *app, int index);

int search_sub(char *app, int *s, int *l);

int split_apptext(char *app, char *dst);

int split_keyword_index(char *keyword, char buf[][32], int max, int submax);

#endif
