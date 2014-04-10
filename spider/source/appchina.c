#include "appchina.h"
#include "common.h"
#include "myhash.h"
#include <stdio.h>
#include "log.h"
#include "myconv.h"
#include "netdata.h"

#define MAXBUF 1024000

#define ID __FILE__
#define LN __LINE__

static char *baseline = "app-block";
static char *appnamebase = "img alt=";
static char *appimgurlbase = "src=";
static char *appauthorbase = "app-author";
static char *appdetailbase = "app-title";
static char *commonurl= "a href=";
static char *appversion = "version";
static char *appdesc = "/span>";

static char *lastpage = "class=\"last\"";

static char *domain = "www.appchina.com";

static int app_num[] = {15, 7};
static int app_start = 1;
static char * app_pre[] = {"/soft_list_3", "/soft_list_4"};
static char * app_suf = "_10_0.html";
const char * app_mid = "%02d_%d";

static int dump(char *data)
{
	FILE *fp = fopen("outfile_appchina", "w");
	if (fp == NULL)
		return -1;
	fprintf(fp, "[%s]\n", data);
	fclose(fp);
}

static int parse_data(char *data)
{
	char cvt[1024] = {0x0};  /*gb2312*/
	char *t = NULL;;
	char *s = data;
	apphead_t app;
	app_data * adata;
	char val[1024] = {0x0};
	char *dst;
	while (1)
	{
		t = strstr(s, baseline);
		if (t == NULL)
			break;
		s = t;  /*start of a app */
		memset(val, 0, sizeof(val));
		t = getval(appnamebase, s, "\"", "\"", val);
		if (!t)
			break;
//		fprintf(stdout, "appname [%s]\n", val);
		s = t;

		memset(cvt, 0, sizeof(cvt));
		if (convert("UTF-8", "GB2312", val, strlen(val), cvt, sizeof(cvt)))
		{
			wlog(rlog, LOG_DEBUG, "[%s]:[%d] [%s][%s] error\n", ID, LN, val, cvt);
			dst = val;
		}
		else
			dst = cvt;

		adata = find_app_node(dst);
		if (adata)
		{
			wlog(rlog, LOG_DEBUG, "[%s]:[%d] %s exist\n", ID, LN, dst);
			continue;
		}
		wlog(rlog, LOG_DEBUG, "[%s]:[%d] %s add\n", ID, LN, dst);

		memset(&app, 0, sizeof(app));
		snprintf(app.appname, sizeof(app.appname), "%s", dst);

		memset(val, 0, sizeof(val));
		t = getval(appimgurlbase, s, "\"", "\"", val);
		if (!t)
			break;
//		fprintf(stdout, "srcurl [%s]\n", val);
		s = t;

		memset(cvt, 0, sizeof(cvt));
		if (convert("UTF-8", "GB2312", val, strlen(val), cvt, sizeof(cvt)))
		{
			wlog(rlog, LOG_DEBUG, "[%s]:[%d] %s error\n", ID, LN, val);
			dst = val;
		}
		else
			dst = cvt;
		snprintf(app.imgurl, sizeof(app.imgurl), "%s", dst);

		memset(val, 0, sizeof(val));
		t = getval(appdetailbase, s, ">", "<", val);
		if (!t)
			break;
//		fprintf(stdout, "appname1 [%s]\n", val);
		s = t;

		memset(cvt, 0, sizeof(cvt));
		if (convert("UTF-8", "GB2312", val, strlen(val), cvt, sizeof(cvt)))
		{
			wlog(rlog, LOG_DEBUG, "[%s]:[%d] %s error\n", ID, LN, val);
			dst = val;
		}
		else
			dst = cvt;
		snprintf(app.appname1, sizeof(app.appname1), "%s", dst);

		memset(val, 0, sizeof(val));
		t = getval(appversion, s, ">", "<", val);
		if (!t)
			break;
//		fprintf(stdout, "version [%s]\n", val);
		s = t;

		memset(cvt, 0, sizeof(cvt));
		if (convert("UTF-8", "GB2312", val, strlen(val), cvt, sizeof(cvt)))
		{
			wlog(rlog, LOG_DEBUG, "[%s]:[%d] %s error\n", ID, LN, val);
			dst = val;
		}
		else
			dst = cvt;
		snprintf(app.version, sizeof(app.version), "%s", dst);

		memset(val, 0, sizeof(val));
		t = getval(appauthorbase, s, ">", "<", val);
		if (!t)
			break;
//		fprintf(stdout, "author [%s]\n", val);
		s = t;

		memset(cvt, 0, sizeof(cvt));
		if (convert("UTF-8", "GB2312", val, strlen(val), cvt, sizeof(cvt)))
		{
			wlog(rlog, LOG_DEBUG, "[%s]:[%d] %s error\n", ID, LN, val);
			dst = val;
		}
		else
			dst = cvt;
		snprintf(app.author, sizeof(app.author), "%s", dst);

		memset(val, 0, sizeof(val));
		t = getval(appdesc, s, "<p>", "</p>", val);
		if (!t)
			break;
//		fprintf(stdout, "desc [%s]\n", val);
		s = t;

		memset(cvt, 0, sizeof(cvt));
		if (convert("UTF-8", "GB2312", val, strlen(val), cvt, sizeof(cvt)))
		{
			wlog(rlog, LOG_DEBUG, "[%s]:[%d] %s error\n", ID, LN, val);
			dst = val;
		}
		else
			dst = cvt;
		snprintf(app.desc, sizeof(app.desc), "%s", dst);

		memset(val, 0, sizeof(val));
		t = getval(commonurl, s, "\"", "\"", val);
		if (!t)
			break;
//		fprintf(stdout, "downloadurl [%s%s]\n", domain, val);
		s = t;

		snprintf(app.downurl, sizeof(app.downurl), "%s", val);
		out_put_appinfo(&app);
//		fprintf(stdout, "\n\n");
	}
	return 0;
}

static void geturl(int o, int in, int num, char *url)
{
	char suburl[16] = {0x0};
	snprintf(suburl, sizeof(suburl), app_mid, in, num); 
	sprintf(url, "%s%s%s", app_pre[o], suburl, app_suf);
}
					
int get_total_page(char *data)
{
	char val[1024] = {0x0};
	getval(lastpage, data, "\"", "\"", val);
	fprintf(stderr, "val = [%s]\n", val);

	return get_int(val, 3, '_');
}

int query_appchina()
{
	char outdata[MAXBUF] = {0x0};
	char url[128]  = {0x0};

	int o1 = 0;
	while (o1 < 2)
	{
		int in1 = app_start;
		while (in1 <= app_num[o1])
		{
			int num = 0;
			int total_page = 0;
			while (num <= total_page)
			{
				geturl(o1, in1, num, url);
				if (getdata(domain, url, outdata) < 0)
				{
					fprintf(stderr, "getdata error %s\n", strerror(errno));
					return -1;
				}
				if (num == 0)
				{
					total_page = get_total_page(outdata);
					fprintf(stderr, "total_page = %d\n", total_page);
				}
				parse_data(outdata);
				num += 10;  /*magic num */
			}
			in1++;
		}
		o1++;
	}
	return 0;
}
