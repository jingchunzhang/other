#include "app.h"
#include "appchina.h"
#include "common.h"
#include "sj.h"
#include "hiapk.h"
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include "log.h"
#include "myconfig.h"

#include <stdio.h>
#include <string.h>
#include "split.h"
#include "uselist.h"
#include "myhash.h"

#define ID __FILE__
#define LN __LINE__

int rlog = -1;  /*runlog fd */
int loglevel = -1; /*log level */

int openlog()
{
	char *logdir = myconfig_get_value("main_logdir");
	if (!logdir)
		return -1;
	char buf[128] = {0x0};
    struct tm tmm; 
	time_t now = time(NULL);
	localtime_r(&now, &tmm);  
	snprintf(buf, sizeof(buf), "%s/spiderlog.%d-%d-%d:%d", logdir, tmm.tm_year + 1900, tmm.tm_mon + 1, tmm.tm_mday, tmm.tm_hour);

	rlog = open (buf, O_CREAT | O_RDWR | O_APPEND | O_LARGEFILE, 0644);
	if (rlog <= 0)
		return -1;
	loglevel = myconfig_get_intval("main_loglevel", -1);
	return 0;
}

int init_spider()
{
	char *rindexkeyfile = myconfig_get_value("main_rindexkey");
	if (!rindexkeyfile)
	{
		wlog(rlog, LOG_ERROR, "[%s]:[%d] no rindexkey error\n", ID, LN);
		return -1;
	}
	key_t rindexkey = ftok(rindexkeyfile, 8);
	char *datakeyfile = myconfig_get_value("main_datakey");
	if (!datakeyfile)
	{
		wlog(rlog, LOG_ERROR, "[%s]:[%d] no datakey error\n", ID, LN);
		return -1;
	}
	key_t datakey = ftok(datakeyfile, 8);

	int ret = 0;
	int listsize = myconfig_get_intval("main_listsize", 100000);
	ret = init_list_data(listsize);
	if (ret)
	{
		wlog(rlog, LOG_ERROR, "[%s]:[%d] init_list_data error\n", ID, LN);
		return -1;
	}
	int rindexsize = myconfig_get_intval("main_rindexsize", 80000);
	ret = init_rindex_hash(rindexkey, rindexsize, 0644);
	if (ret)
	{
		wlog(rlog, LOG_ERROR, "[%s]:[%d] init_rindex_hash error\n", ID, LN);
		return -1;
	}
	int datasize = myconfig_get_intval("main_datasize", 80000);
	ret = init_app_hash(datakey, datasize, 0644);
	if (ret)
	{
		wlog(rlog, LOG_ERROR, "[%s]:[%d] init_app_hash error\n", ID, LN);
		return -1;
	}

	char *dictfile= myconfig_get_value("main_dictfile");
	if (!dictfile)
	{
		wlog(rlog, LOG_ERROR, "[%s]:[%d] no dictfile error\n", ID, LN);
		return -1;
	}
	char *rulefile= myconfig_get_value("main_rulefile");
	if (!rulefile)
	{
		wlog(rlog, LOG_ERROR, "[%s]:[%d] no rulefile error\n", ID, LN);
		return -1;
	}
	ret = init_split(dictfile, rulefile);
	if (ret)
	{
		wlog(rlog, LOG_ERROR, "[%s]:[%d] init_split error\n", ID, LN);
		return -1;
	}
	return 0;
}

int main(int argc, char **argv)
{
	if(myconfig_init(argc, argv) < 0) 
	{
		printf("myconfig_init fail %m\n");
		return -1;
	}

	if (openlog())
	{
		fprintf(stderr, "log init ERROR %s\n", strerror(errno));
		return -1;
	}

	if (init_spider())
	{
		fprintf(stderr, "init_spider ERROR %s\n", strerror(errno));
		return -1;
	}

	query_appchina();
	dump_rindex();
	close_data_file();
	return 0;
}
