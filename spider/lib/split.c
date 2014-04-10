#include <scws.h>
#include <stdlib.h>
#include "split.h"
#include "myhash.h"
#include "uselist.h"
#include "common.h"
#include "log.h"
#include <string.h>
#include <stddef.h>
#include "myconv.h"

#define ID __FILE__
#define LN __LINE__

static scws_t s;
static scws_t ss;
int init_split(char *dict, char *rule)
{
	if (!(s = scws_new())) 
	{
		wlog(rlog, LOG_ERROR, "[%s]:[%d] scws_new failed [%s]\n", ID, LN, strerror(errno));
		return -1;
	}
	if (!(ss = scws_new())) 
	{
		wlog(rlog, LOG_ERROR, "[%s]:[%d] scws_new failed [%s]\n", ID, LN, strerror(errno));
		return -1;
	}
	scws_set_charset(s, "gbk");
	scws_set_charset(ss, "gbk");
	scws_set_dict(s, dict, SCWS_XDICT_XDB);
	scws_set_rule(s, rule);
	wlog(rlog, LOG_DEBUG, "[%s]:[%d] scws_new ok\n", ID, LN);
	return 0;
}

static int checkdump(list_head_t *addlist, int index) 
{
	list_head_t *l, *ltmp;
	listbody_t *tmp;
	list_for_each_safe(l, ltmp, addlist)
	{
		tmp = list_entry(l, listbody_t, listapp);
		if (tmp->index == index)
			return 0;
	}
	return -1;
}

int split_app(char *app, int index)
{
	wlog(rlog, LOG_DEBUG, "[%s]:[%d] split [%s]\n", ID, LN, app);
	scws_res_t res, cur;
	scws_send_text(s, app, strlen(app));
	char val[1024] = {0x0};
	list_head_t * addlist = NULL;
	rindex_data * findlist = NULL;
	while (res = cur = scws_get_result(s))
	{
		while (cur != NULL)
		{
			snprintf(val, sizeof(val), "%.*s", cur->len, app+cur->off);
			wlog(rlog, LOG_DEBUG, "[%s]:[%d] sub split [%s]\n", ID, LN, val);
			findlist = find_rindex_node(val);
			if (findlist == NULL)
			{
				findlist = add_rindex_node(val);
				if (!findlist)
				{
					fprintf(stderr, "add_rindex_node ERROR!\n");
					exit(0);
				}
			}

			addlist = &(findlist->rootlist);
			memset(val, 0, sizeof(val));
			cur = cur->next;
			if (checkdump(addlist, index) == 0)
				continue;
			if (addlist)
				add_to_list(index, addlist);
		}
		scws_free_result(res);
	}
	return 0;
}

int search_sub(char *app, int *s, int *l)
{
	rindex_data * findlist = find_rindex_node(app);
	if (findlist)
	{
		*s = findlist->start;
		*l = findlist->len;
		return 0;
	}
	return -1;
}

int split_apptext(char *app, char *dst)
{
	char *tmp = dst;
	scws_res_t res, cur;
	scws_send_text(s, app, strlen(app));
	while (res = cur = scws_get_result(s))
	{
		while (cur != NULL)
		{
			int tlen = sprintf(tmp, "%.*s|", cur->len, app+cur->off);
			tmp += tlen;
			cur = cur->next;
		}
		scws_free_result(res);
	}
	return 0;
}

int split_keyword_index(char *app, char sub[][32], int max, int submax)
{
	wlog(rlog, LOG_DEBUG, "[%s]:[%d] split [%s]\n", ID, LN, app);
	scws_res_t res, cur;
	scws_send_text(s, app, strlen(app));
	int ok = 0;
	int i = 0;
	while (res = cur = scws_get_result(s))
	{
		while (cur != NULL)
		{
			snprintf(sub[i], submax, "%.*s", cur->len, app+cur->off);
			wlog(rlog, LOG_DEBUG, "[%s]:[%d] split [%s]\n", ID, LN, sub[i]);
			cur = cur->next;
			i++;
			if (max <= i)
			{
				ok = 1;
				break;
			}
		}
		scws_free_result(res);
		if (ok)
			return i;
	}
	return i;
}

