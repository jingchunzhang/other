#include"common.h"
#include <stdio.h>
#include "myhash.h"
#include "split.h"

#define ID __FILE__
#define LN __LINE__

const char *appcss = "<div>\n<img alt=\"%s\" src=\"%s\"/>\n<a href=\"%s\">%s</a>\n<span>%s</span>\n<span>%s</span>\n<a href=\"%s\">обть</a>\n<p>%s</p>\n</div>\n";

char* getval(char *key, char *s, char *f, char *b, char *v)
{
	char *t = strstr(s, key);
	if (t == NULL)
		return NULL;
	s = t + strlen(key);
	char *vs = strstr(s, f);
	if (vs == NULL)
		return NULL;

	vs += strlen(f);
	s = vs;
	char *ve = strstr(s, b);
	if (ve == NULL)
		return NULL;
	*ve = 0x0;
	strcpy(v, vs);
	*ve = *b;
	s = ve + strlen(b);
	return s;
}

int out_put_appinfo(apphead_t *appinfo)
{
	char buf[2048] = {0x0};

	int index = add_app_node(appinfo->appname1);
	if (index < 0)
	{
		fprintf(stderr, "add_app_node ERROR\n");
		exit(1);
	}

	int len = snprintf(buf, sizeof(buf), appcss, appinfo->appname, appinfo->imgurl, appinfo->downurl, appinfo->appname1, appinfo->version, appinfo->author, appinfo->downurl, appinfo->desc);

	if (out_data_file(index, buf, len))
		return -1;
	if (split_app(appinfo->appname1, index))
		return -1;
	return 0;
}

int get_int(char *src, int s, char sep)
{
	int i = 0;
	char *t = src;
	char *tmp = NULL;
	for (i = 0; i < s; i++)
	{
		tmp = strchr(t, sep);
		if (tmp == NULL)
			return -1;
		t = tmp + 1;
	}
	i = atoi(t);
	return i;
}



