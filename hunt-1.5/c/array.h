/*
 * 
 *	This is free software. You can redistribute it and/or modify under
 *	the terms of the GNU General Public License version 2.
 *
 * 	Copyright (C) 1998 by kra
 * 
 */
#ifndef __ARRAY_H
#define __ARRAY_H

#ifdef _REENTRANT
#include <pthread.h>
#endif

struct array_item {
	void *ai_data;
};

struct array {
	struct array_item *a_arr;
	int a_size;
	int a_items;
#ifdef _REENTRANT
	int a_locked;
	pthread_t a_locked_thr;
	pthread_mutex_t a_mutex;
#endif
};

#define ARRAY_SPACE_PCT_INC	50

void array_init(struct array *a, int size);
void array_free(struct array *a);

void *array_at(struct array *a, int nr);
void *array_remove(struct array *a, void *m);
void *array_remove_at(struct array *a, int nr);

int array_put(struct array *a, void *m);
void *array_put_at(struct array *a, int nr, void *m);

void *array_pop(struct array *a);

int array_count(struct array *a);

struct array_iterator {
	struct array *i_array;
	int i_pos;
};

void array_iter_set(struct array_iterator *ai, struct array *a);
void *array_iter_get(struct array_iterator *ai);
void array_iter_end(struct array_iterator *ai);

void array_iter_lock(struct array_iterator *ai);
void array_iter_unlock(struct array_iterator *ai);

#endif
