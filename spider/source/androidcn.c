#include "androidcn.h"
#include "common.h"
#include <stdio.h>

#define MAXBUF 1024000

static char *baseline = "class=\"result\"";
static char *appbaseline = "\"goodsImg \" title=\"";
static char *appendline = " alt=";

static char *baseurl = "/search?keyword=%u7406%u8D22";
static char *domain = "down.androidcn.com";
//char *mmdomain = "read.newbooks.com.cn";

static int dump(char *data)
{
	FILE *fp = fopen("outfile_androidcn", "w");
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

int query_androidcn(char *querystr)
{
	char srcurl[512] = {0x0};
	char dsturl[1024] = {0x0};

	createurl(srcurl, querystr);
	url_encode(srcurl, dsturl);
	char outdata[MAXBUF] = {0x0};
	char *dsturl1 = "/search/q/game";
	if (getdata(domain, dsturl1, outdata))
	{
		fprintf(stderr, "getdata error %s\n", strerror(errno));
		return -1;
	}
//	convert("utf-8", "GB2312", data, strlen(data), tmpdata, 1024000);  //��gb2312ת����big5
	parse_data(outdata);
	return 0;
}
