/*
 * 
 *	This is free software. You can redistribute it and/or modify under
 *	the terms of the GNU General Public License version 2.
 *
 * 	Copyright (C) 1998 by kra
 * 
 */
#ifndef __LIST_H
#define __LIST_H

#include <time.h>

#ifdef _REENTRANT
#include <pthread.h>
#endif

struct list_iterator;

struct list {
	void *l_first;
	void *l_last;
	int  l_off;
	int  l_produce_done;
	struct list_iterator *l_iter;
#ifdef _REENTRANT
	int  l_locked;
	pthread_mutex_t l_mutex;
	pthread_cond_t  l_notempty;
	pthread_t	l_locked_thr;
#endif
};

struct list_iterator {
	struct list *i_list;
	void *i_cur;
	struct list_iterator *i_next;
};

#define offset_of(str, next)	((char *)(&((str *)0)->next) - (char *)0)
#ifdef _REENTRANT
#define LIST_INIT(str, next)	{ NULL, NULL, offset_of(str, next), 0, NULL, \
				  0, \
				  PTHREAD_MUTEX_INITIALIZER, \
				  PTHREAD_COND_INITIALIZER, \
				  (pthread_t) 0 }
#else
#define LIST_INIT(str, next)	{ NULL, NULL, offset_of(str, next), 0, NULL }
#endif

#ifdef _REENTRANT
#define LIST_MAKE(str, next, first, last) { first, last, \
					    offset_of((str, (next)), 0, NULL, \
					    0, \
					    PTHREAD_MUTEX_INITIALIZER, \
					    PTHREAD_COND_INITIALIZER, \
					    (pthread_t) 0 }
#else
#define LIST_MAKE(str, next, first, last) { first, last, \
					    offset_of((str, (next)), 0, NULL }
#endif

#define LIST_NEXT_PTR(list, member) ((void **)((char *)(member) + (list)->l_off))
#define LIST_THIS_PTR(list, member) ((void *)((char *)(member) - (list)->l_off))

void list_init(struct list *l, int next_offset);
void list_flush(struct list *l);	
	
void list_push(struct list *l, void *m);
void list_enqueue(struct list *l, void *m);
void list_produce(struct list *l, void *m);
void list_produce_start(struct list *l);
void list_produce_done(struct list *l);
void list_insert_at(struct list *l, int nr, void *m);
	
void *list_pop(struct list *l);
void *list_consume(struct list *l, const struct timespec *absts);
void *list_consume_rel(struct list *l, const struct timespec *relts);
void *list_peek(struct list *l);
void *list_at(struct list *l, int nr);
void *list_remove(struct list *l, void *m);
void *list_remove_at(struct list *l, int nr);
void *list_remove_func(struct list *l, int (*func)(int nr, void *, void *m), void *m);
int list_count(struct list *l);

void list_lock(struct list *l);
void list_unlock(struct list *l);

void list_iter_set(struct list_iterator *i, struct list *l);
void *list_iter_get(struct list_iterator *i);
void list_iter_end(struct list_iterator *i);
	
#endif
