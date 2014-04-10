#ifndef __USELIST_H_
#define __USELIST_H_
#include "list.h"
#include "myshm.h"

/* list 连接了rindex块和数据块*/

typedef struct
{
	list_head_t listapp;
	int index;
}listbody_t;

int init_list_data(size_t size);

listbody_t * get_free_list();  /*返回给调用者一个list，调用者负责处理，不能悬空*/

void add_to_free_list(list_head_t *tmp);  

int add_to_list(unsigned int index, list_head_t *baselist);  /* insertdata->split->rindex->here */

#endif
