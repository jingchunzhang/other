#include "mm.h"
#include "common.h"
#include <stdio.h>

#define MAXBUF 1024000

static char *baseline = "class=\"result\"";
static char *appbaseline = "\"goodsImg \" title=\"";
static char *appendline = " alt=";

char *baseurl = "/game/gameResult.html";
char *mmdomain = "mm.10086.cn";
//char *mmdomain = "read.newbooks.com.cn";
static int dump(char *data)
{
	FILE *fp = fopen("outfile_mm", "w");
	if (fp == NULL)
		return -1;
	fprintf(fp, "[%s]\n", data);
	fclose(fp);
}

static int parse_data(char *data)
{
	dump(data);
	return 0;
	char *b = strstr(data, baseline);
	if (b == NULL)
	{
		fprintf(stderr, "no %s\n", baseline);
		return -1;
	}

	char *a = strstr(b, appbaseline);
	if (a == NULL)
	{
		fprintf(stderr, "no %s\n", appbaseline);
		return -1;
	}
	a += strlen(appbaseline);

	char *e = strstr(a, appendline);
	if (e == NULL)
	{
		fprintf(stderr, "no %s\n", appendline);
		return -1;
	}
	e -= 2;

	char in[128] = {0x0};
	strncpy(in, a, e -a);
	char buf[128] = {0x0};
	convert("utf-8", "GB2312", in, e-a, buf, sizeof(buf));
	fprintf(stdout, "[%s][%s]\n", buf, in);
}

static int createurl(char *url, char *querystr)
{
	sprintf(url, "%s%s", baseurl, querystr);
	return 0;
}

int query_mm(char *querystr)
{
	char srcurl[512] = {0x0};
	char dsturl[1024] = {0x0};

	char outdata[MAXBUF] = {0x0};
	if (getdata(mmdomain, baseurl, outdata))
	{
		fprintf(stderr, "getdata error %s\n", strerror(errno));
		return -1;
	}
	parse_data(outdata);
	return 0;
}
