#include "uselist.h"
#include <string.h>
#include <stddef.h>
#include "common.h"

#define ID __FILE__
#define LN __LINE__

static list_head_t *listhead = NULL; 
static listbody_t *listbody = NULL; 

int init_list_data(size_t size)
{
	size_t bigsize = size * sizeof(listbody_t) + sizeof(list_head_t);
	listhead = (list_head_t*) malloc(bigsize);
	if (listhead == NULL)
		return -1;

	memset(listhead, 0, bigsize);
	INIT_LIST_HEAD(listhead);

	listbody = (listbody_t *) ((char *)listhead + sizeof(list_head_t));
	listbody_t * body = listbody;
	int i = 0;
	while (i < size)
	{
		INIT_LIST_HEAD(&(body->listapp));
		list_add_tail(&(body->listapp), listhead);
		i++;
		body++;
	}
	return 0;
}

listbody_t* get_free_list()
{
	list_head_t *l, *ltmp;
	listbody_t *tmp;
	list_for_each_safe(l, ltmp, listhead)
	{
		tmp = list_entry(l, listbody_t, listapp);
		list_del_init(&(tmp->listapp));
		return tmp;
	}
	return NULL;
}

void add_to_free_list(list_head_t *tmp)  
{
	list_add_tail(tmp, listhead);
}

int add_to_list(unsigned int index, list_head_t *baselist)
{
	listbody_t * body = get_free_list();
	if (!body)
		return -1;

	body->index = index;
	list_add_tail(&(body->listapp), baselist);
	return 0;
}

