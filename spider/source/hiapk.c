#include "hiapk.h"
#include "common.h"
#include <stdio.h>

#define MAXBUF 1024000

static char *baseline = "m_ptype";
static char *appnamebase = "tilte";
static char *appimgurlbase = "img src=";
static char *appauthorbase = "em ";
static char *appdetailbase = "intro";
static char *commonurl= "a href=";

static char *baseurl = "/apps_0_1_1";
static char *domain = "apk.hiapk.com";
//char *mmdomain = "read.newbooks.com.cn";

static int dump(char *data)
{
	FILE *fp = fopen("outfile_hiapk", "w");
	if (fp == NULL)
		return -1;
	fprintf(fp, "[%s]\n", data);
	fclose(fp);
}

static int parse_data(char *data)
{
	dump(data);
	char *t = NULL;;
	char *s = data;
	char val[1024] = {0x0};
	t = strstr(s, baseline);
	if (t == NULL)
		return -1;
	s = t;  /*start of a app */
	while (1)
	{
		memset(val, 0, sizeof(val));
		t = getval(commonurl, s, '"', '"', val);
		if (!t)
			break;
		fprintf(stdout, "downloadurl [%s]\n", val);
		s = t;

		memset(val, 0, sizeof(val));
		t = getval(appnamebase, s, '>', '<', val);
		if (!t)
			break;
		fprintf(stdout, "appname [%s]\n", val);
		s = t;

		memset(val, 0, sizeof(val));
		t = getval(appauthorbase, s, '>', '<', val);
		if (!t)
			break;
		fprintf(stdout, "author [%s]\n", val);
		s = t;

		memset(val, 0, sizeof(val));
		t = getval(appimgurlbase, s, '"', '"', val);
		if (!t)
			break;
		fprintf(stdout, "srcurl [%s]\n", val);
		s = t;
		fprintf(stdout, "\n\n");
	}
	return 0;
}

static int createurl(char *url, char *querystr)
{
	sprintf(url, "%s%s", baseurl, querystr);
	return 0;
}

int query_hiapk()
{
	char srcurl[512] = {0x0};
	char dsturl[1024] = {0x0};

	char outdata[MAXBUF] = {0x0};
	if (getdata(domain, baseurl, outdata))
	{
		fprintf(stderr, "getdata error %s\n", strerror(errno));
		return -1;
	}
//	convert("utf-8", "GB2312", data, strlen(data), tmpdata, 1024000);  //°Ñgb2312×ª»»³Ébig5
	parse_data(outdata);
	return 0;
}
