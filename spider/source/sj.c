#include "sj.h"
#include "common.h"
#include <stdio.h>

#define MAXBUF 1024000

static char *baseline = "class=\"result\"";
static char *appbaseline = "\"goodsImg \" title=\"";
static char *appendline = " alt=";

static char *baseurl = "/soft/iPhone/search/1_5_0_0_%E7%90%86%E8%B4%A2";
static char *domain = "mobile.91.com";
//char *mmdomain = "read.newbooks.com.cn";

static int dump(char *data)
{
	FILE *fp = fopen("outfile_sj", "w");
	if (fp == NULL)
		return -1;
	fprintf(fp, "[%s]\n", data);
	fclose(fp);
}

static int parse_data(char *data)
{
	dump(data);
	return 0;
}

static int createurl(char *url, char *querystr)
{
	sprintf(url, "%s%s", baseurl, querystr);
	return 0;
}

int query_sj(char *querystr)
{
	char srcurl[512] = {0x0};
	char dsturl[1024] = {0x0};

	createurl(srcurl, querystr);
	url_encode(srcurl, dsturl);
	char outdata[MAXBUF] = {0x0};
	char *dsturl1 = "/soft/iPhone/search/1_5_0_0_%E7%90%86%E8%B4%A2";
	if (getdata(domain, dsturl1, outdata))
	{
		fprintf(stderr, "getdata error %s\n", strerror(errno));
		return -1;
	}
//	convert("utf-8", "GB2312", data, strlen(data), tmpdata, 1024000);  //°Ñgb2312×ª»»³Ébig5
	parse_data(outdata);
	return 0;
}
