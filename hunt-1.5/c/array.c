/*
 * 
 *	This is free software. You can redistribute it and/or modify under
 *	the terms of the GNU General Public License version 2.
 *
 * 	Copyright (C) 1998 by kra
 * 
 */
#include <stdlib.h>
#include <assert.h>
#include <string.h>
#include "array.h"

static inline void update_a_items(struct array *a, int nr, void *m)
{
	if (a->a_arr[nr].ai_data) {
		if (!m)
			a->a_items--;
	} else {
		if (m)
			a->a_items++;
	}	
}

void array_init(struct array *a, int size)
{
	assert(a->a_arr = malloc(size * sizeof(struct array_item)));
	memset(a->a_arr, 0, size * sizeof(struct array_item));
	a->a_size = size;
	a->a_items = 0;
#ifdef _REENTRANT
	a->a_locked = 0;
	pthread_mutex_init(&a->a_mutex, NULL);
#endif
}

static inline void __lock(struct array *a)
{
#ifdef _REENTRANT
	if (!a->a_locked || a->a_locked_thr != pthread_self())
		pthread_mutex_lock(&a->a_mutex);
#endif
}

static inline void __unlock(struct array *a)
{
#ifdef _REENTRANT
	if (!a->a_locked || a->a_locked_thr != pthread_self())
		pthread_mutex_unlock(&a->a_mutex);
#endif
}

void array_free(struct array *a)
{
	__lock(a);
	if (a->a_arr)
		free(a->a_arr);
	a->a_arr = NULL;
	a->a_size = 0;
	a->a_items = 0;
	__unlock(a);
}

void *array_at(struct array *a, int nr)
{
	void *retval;
	
	__lock(a);
	if (nr < 0 || nr >= a->a_size)
		retval = NULL;
	else
		retval = a->a_arr[nr].ai_data;
	__unlock(a);
	return retval;
}

void *array_remove_at(struct array *a, int nr)
{
	return array_put_at(a, nr, NULL);
}

void *array_put_at(struct array *a, int nr, void *m)
{
	void *retval;
	
	__lock(a);
	if (nr < 0 || nr >= a->a_size)
		retval = NULL;
	else {
		update_a_items(a, nr, m);
		retval = a->a_arr[nr].ai_data;
		a->a_arr[nr].ai_data = m;
	}
	__unlock(a);
	return retval;
}

void *array_remove(struct array *a, void *m)
{
	struct array_item *ai;
	void *retval;
	
	__lock(a);
	if (!m)
		retval = NULL;
	else {
		retval = NULL;
		for (ai = a->a_arr; ai < a->a_arr + a->a_size; ai++)
			if (ai->ai_data == m) {
				ai->ai_data = NULL;
				a->a_items--;
				retval = m;
				break;
			}
	}
	__unlock(a);
	return retval;
}

static void need_space(struct array *a)
{
	int new_size;
	struct array_item *new_arr;
	
	if (a->a_items == a->a_size) {
		new_size = a->a_size + (ARRAY_SPACE_PCT_INC * a->a_size) / 100;
		new_arr = realloc(a->a_arr, new_size * sizeof(struct array_item));
		assert(new_arr);
		memset(a->a_arr + a->a_size, 0, (new_size - a->a_size) * sizeof(struct array_item));
		a->a_arr = new_arr;
		a->a_size = new_size;
	}
}

int array_put(struct array *a, void *m)
{
	struct array_item *ai;
	int retval;
	
	__lock(a);
	need_space(a);
	for (ai = a->a_arr; ai < a->a_arr + a->a_size; ai++) {
		if (ai->ai_data == NULL) {
			ai->ai_data = m;
			a->a_items++;
			break;
		}
	}
	retval = ai - a->a_arr;
	__unlock(a);
	return retval;
}

void *array_pop(struct array *a)
{
	struct array_item *ai;
	void *retval = NULL;
	
	__lock(a);
	for (ai = a->a_arr; ai < a->a_arr + a->a_size; ai++) {
		if (ai->ai_data) {
			retval = ai->ai_data;
			ai->ai_data = NULL;
			a->a_items--;
			break;
		}
	}
	__unlock(a);
	return retval;
}

int array_count(struct array *a)
{
	int retval;
	
	__lock(a);
	retval = a->a_items;
	__unlock(a);
	return retval;
}

void array_lock(struct array *a)
{
#ifdef _REENTRANT
	if (!a->a_locked || a->a_locked_thr != pthread_self()) {
		pthread_mutex_lock(&a->a_mutex);
		a->a_locked_thr = pthread_self();
		a->a_locked = 1;
	} else
		a->a_locked++;
#endif
}

void array_unlock(struct array *a) 
{
#ifdef _REENTRANT
	if (--a->a_locked == 0)
		pthread_mutex_unlock(&a->a_mutex);
#endif
}

void array_iter_lock(struct array_iterator *ai)
{
	array_lock(ai->i_array);
}

void array_iter_unlock(struct array_iterator *ai)
{
	array_unlock(ai->i_array);
}

void array_iter_set(struct array_iterator *ai, struct array *a)
{
	ai->i_array = a;
	ai->i_pos = -1;
}

void *array_iter_get(struct array_iterator *ai)
{
	struct array *a;
	void *retval;
	
	retval = NULL;
	a = ai->i_array;
	__lock(a);
	while (++ai->i_pos < a->a_size) {
		if (a->a_arr[ai->i_pos].ai_data) {
			retval = a->a_arr[ai->i_pos].ai_data;
			break;
		}
	}
	__unlock(a);
	return retval;
}
				
void array_iter_end(struct array_iterator *ai)
{
	ai->i_array = NULL;
	ai->i_pos = -1;
}



#ifdef TEST
/*
 * 
 * Test
 * 
 */
#include <stdio.h>
#include <stdlib.h>
#include <stdarg.h>
#include <unistd.h>
#include <assert.h>
#include <alloca.h>

int MAX_ITEMS = 1000;

static int verbose = 0;

static int verbose_print(int level, char *format, ...)
{
	va_list ap;
	int retval;
	
	if (verbose >= level) {
		va_start(ap, format);
		retval = vprintf(format, ap);
		va_end(ap);
		return retval;
	}
	return 0;
}

int main(int argc, char *argv[])
{
	struct array a;
	struct array_iterator ai;
	int i;
	int *t, *t_arr;
	
	while ((i = getopt(argc, argv, "vi:")) != -1) {
		switch (i) {
		    case 'v':
			++verbose;
			break;
		    case 'i':
			MAX_ITEMS = atoi(optarg);
			break;
		    default:
			fprintf(stderr, "bad option\n");
			exit(1);
		}
	}
	
	assert(t_arr = malloc(MAX_ITEMS * sizeof(int)));
	array_init(&a, 100);
	
	verbose_print(1, "start\n");
	for (i = 0; i < MAX_ITEMS; i++) {
		t = t_arr + i;
		*t = i;
		assert(array_put(&a, t) == i);
	}
	for (i = 0; i < MAX_ITEMS; i += 2) {
		t = t_arr + i;
		assert(array_remove(&a, t) == t);
	}
	for (i = 1; i < MAX_ITEMS; i += 2) {
		t = t_arr + i;
		assert(array_pop(&a) == t);
	}
	for (i = 0; i < MAX_ITEMS; i += 2) {
		t = t_arr + i;
		assert(array_put_at(&a, i, t) == NULL);
	}
	for (i = 1; i < MAX_ITEMS; i += 2) {
		t = t_arr + i;
		assert(array_put(&a, t) == i);
	}
	for (i = 0; i < MAX_ITEMS; i += 2) {
		t = t_arr + i;
		assert(array_remove_at(&a, i) == t);
	}
	array_iter_set(&ai, &a);
	i = 1;
	while ((t = array_iter_get(&ai))) {
		assert(*t == i);
		i += 2;
		verbose_print(2, "%d ", *t);
	}
	array_iter_end(&ai);
	printf("\n");
	
	array_free(&a);
	
	return 0;
}

#endif
