#ifndef MY_HASH_H_
#define MY_HASH_H_
#include <stdio.h>
#include "list.h"
#include "myshm.h"

extern char * rindexfile;
extern char * datafile ;

typedef struct
{
	char *base;
	int  datasize;
	int  hashsize;
	int  usedsize;
}shmhead;

typedef struct
{
	int hash1;
	int hash2;
	int hash3;

	int used;
	/* match above three hash */
//	char data[128];  /*for test, will be delete after release */
	list_head_t rootlist;  /* root for all matched */
	list_head_t desclist;  /* root for all matched */
	int start;
	int len;
	int  next;
}rindex_data;

int init_rindex_hash(key_t key, size_t size, int mode);

rindex_data * find_rindex_node(char *text);  /*find it, maybe need amend it*/

rindex_data * add_rindex_node(char *text);

void scan_rindex();

int dump_rindex();

typedef struct
{
	int hash1;
	int hash2;
	int hash3;

	int used;
//	char app[128];  /*appname fullpath*/
	unsigned int start;
	unsigned int len;
	time_t uptime;
	int  next;
}app_data;

int init_app_hash(key_t key, size_t size, int mode);

app_data * find_app_node(char *text);  /*find it, maybe need amend it*/

int add_app_node(char *text);

app_data * get_app_path(unsigned int index);

unsigned int get_data_len();

int get_file_pos_len(int index, unsigned int *pos, unsigned int *len);

int out_data_file(int index, char *buf, int len);

void close_data_file();

void scan_app();

#endif
