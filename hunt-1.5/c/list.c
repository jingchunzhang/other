/*
 * 
 *	This is free software. You can redistribute it and/or modify under
 *	the terms of the GNU General Public License version 2.
 *
 * 	Copyright (C) 1998 by kra
 * 
 */
#include <sys/time.h>
#include <unistd.h>
#include <stdlib.h>
#include <errno.h>
#include <pthread.h>
#include "list.h"

void list_init(struct list *l, int next_offset)
{
	l->l_first = l->l_last = NULL;
	l->l_off = next_offset;
	l->l_iter = NULL;
	l->l_produce_done = 0;
#ifdef _REENTRANT
	l->l_locked = 0;
	pthread_mutex_init(&l->l_mutex, NULL);
	pthread_cond_init(&l->l_notempty, NULL);
	l->l_locked_thr = (pthread_t) 0;
#endif
}

static inline void __lock(struct list *l)
{
#ifdef _REENTRANT
	if (!l->l_locked || l->l_locked_thr != pthread_self())
		pthread_mutex_lock(&l->l_mutex);
#endif
}

static inline void __unlock(struct list *l)
{
#ifdef _REENTRANT	
	if (!l->l_locked || l->l_locked_thr != pthread_self())
		pthread_mutex_unlock(&l->l_mutex);
#endif
}

void list_flush(struct list *l)
{
	struct list_iterator *i;
	
	__lock(l);
	l->l_first = l->l_last = NULL;
	for (i = l->l_iter; i; i = i->i_next) {
		i->i_cur = NULL;
	}
	__unlock(l);
}

static inline void __update_iterators(struct list *l, void *old_item, void *new_item)
{
	struct list_iterator *i;
	
	for (i = l->l_iter; i; i = i->i_next) {
		if (i->i_cur == old_item)
			i->i_cur = new_item;
	}
}

void list_push(struct list *l, void *m)
{
	__lock(l);
	if (!(*LIST_NEXT_PTR(l, m) = l->l_first))
		l->l_last = m;
	__update_iterators(l, l->l_first, m);
	l->l_first = m;
	__unlock(l);
}

static inline void __enqueue(struct list *l, void *m)
{
	*LIST_NEXT_PTR(l, m) = NULL;		/* m->next = NULL */
	if (l->l_last)
		*LIST_NEXT_PTR(l, l->l_last) = m; /* l->l_last->next = m */
	else
		l->l_first = m;
	l->l_last = m;
}

void list_insert_at(struct list *l, int nr, void *m)
{
	void **p;
	
	__lock(l);
	p = &l->l_first;
	while (*p && nr--) {
		p = &(*LIST_NEXT_PTR(l, *p));
	}
	*LIST_NEXT_PTR(l, m) = *p;
	if (*p)
		*p = m;
	else
		__enqueue(l, m);
	__update_iterators(l, *LIST_NEXT_PTR(l, m), m);
	__unlock(l);
}

void list_enqueue(struct list *l, void *m)
{
	__lock(l);
	__enqueue(l, m);
	__unlock(l);
}

void list_produce(struct list *l, void *m)
{
	__lock(l);
	__enqueue(l, m);
#ifdef _REENTRANT
	pthread_cond_signal(&l->l_notempty);
#endif
	__unlock(l);
}

void list_produce_start(struct list *l)
{
	__lock(l);
	l->l_produce_done = 0;
	__unlock(l);
}

void list_produce_done(struct list *l)
{
	__lock(l);
	l->l_produce_done = 1;
#ifdef _REENTRANT
	pthread_cond_signal(&l->l_notempty);
#endif
	__unlock(l);
}

static inline void *__pop(struct list *l)
{
	void *retval;
	
	if ((retval = l->l_first)) {
		if (!(l->l_first = *LIST_NEXT_PTR(l, retval)))
			l->l_last = NULL;
		__update_iterators(l, retval, l->l_first);
	}
	return retval;
}

void *list_pop(struct list *l)
{
	void *retval;

	__lock(l);
	retval = __pop(l);
	__unlock(l);
	return retval;
}

static void *__list_consume(struct list *l, const struct timespec *absts)
{
	void *retval;
	int ret;
	struct timespec ts;
	
	__lock(l);
#ifdef _REENTRANT
	while (!l->l_first && !l->l_produce_done)
		if (absts) {
			if ((ret = pthread_cond_timedwait(&l->l_notempty,
			    &l->l_mutex, absts)) == ETIMEDOUT || ret == EINTR)
				break;
		} else {
#if 0
			pthread_cond_wait(&l->l_notempty, &l->l_mutex);
#else
			/*
			 * it can be interrupted through signal
			 */
			ts.tv_sec = 2000000000;
			ts.tv_nsec = 0;
			ret = pthread_cond_timedwait(&l->l_notempty,
				&l->l_mutex, &ts);
			if (ret == ETIMEDOUT || ret == EINTR)
				break;
#endif
		}
#endif
	retval = __pop(l);
	__unlock(l);
	return retval;
}

void *list_consume(struct list *l, const struct timespec *absts)
{
	return __list_consume(l, absts);
}

void *list_consume_rel(struct list *l, const struct timespec *relts)
{
	struct timeval now;
	struct timespec absts;
	
	gettimeofday(&now, NULL);
	absts.tv_sec = now.tv_sec + relts->tv_sec;
	absts.tv_nsec = now.tv_usec * 1000 + relts->tv_nsec;
	if (absts.tv_nsec >= 1000000000) {
		absts.tv_nsec -= 1000000000;
		absts.tv_sec++;
	}
	return __list_consume(l, &absts);
}
	
void *list_peek(struct list *l)
{
	void *retval;

	__lock(l);
	retval = l->l_first;
	__unlock(l);
	return retval;
}

void *list_at(struct list *l, int nr)
{
	void *retval, *p;
	int i;
	
	__lock(l);
	for (p = l->l_first, i = 0; p && i < nr; p = *LIST_NEXT_PTR(l, p), i++)
		;
	if (p)
		retval = p;
	else
		retval = NULL;
	__unlock(l);
	return retval;
}

static inline int __func_remove(int nr, void *p, void *m)
{
	if (p == m)
		return 1;
	else
		return 0;
}

static inline int __func_remove_at(int nr, void *p, void *m)
{
	if (nr == (int) m)
		return 1;
	else
		return 0;
}

static inline void *__list_remove(struct list *l, 
				  int (*func)(int nr, void *, void *m), void *m)
{
	void *retval;
	void **p;
	int nr;
	
	nr = 0;
	__lock(l);
	p = &l->l_first;
	while (*p) {
		if (func(nr, *p, m)) { /*  if (*p == member)  */
			retval = *p;
			
			/*  *p = (*p)->next */
			if (!(*p = *LIST_NEXT_PTR(l, *p))) {
				if (!l->l_first)
					l->l_last = NULL;
				else
					l->l_last = LIST_THIS_PTR(l, p);
			}
			__update_iterators(l, retval, *p);
			__unlock(l);
			return retval;
		}
		p = &(*LIST_NEXT_PTR(l, *p));	/* p = &(*p)->next */
		nr++;
	}
	__unlock(l);
	return *p;	/* NULL */
}

void *list_remove(struct list *l, void *m)
{
	return __list_remove(l, __func_remove, m);
}

void *list_remove_at(struct list *l, int nr)
{
	return __list_remove(l, __func_remove_at, (void *) nr);
}

void *list_remove_func(struct list *l, 
		       int (*func)(int nr, void *, void *m), void *m)
{
	return __list_remove(l, func, m);
}

int list_count(struct list *l)
{
	int i;
	void *p;

	__lock(l);
	for (i = 0, p = l->l_first; p; i++, p = *LIST_NEXT_PTR(l, p)) ; /* p = p->next */
	__unlock(l);
	return i;
}

void list_lock(struct list *l)
{
#ifdef _REENTRANT
	if (!l->l_locked || l->l_locked_thr != pthread_self()) {
		pthread_mutex_lock(&l->l_mutex);
		l->l_locked_thr = pthread_self();
		l->l_locked = 1;
	} else
		l->l_locked++;
#endif
}

void list_unlock(struct list *l)
{
#ifdef _REENTRANT
	if (--l->l_locked == 0)
		pthread_mutex_unlock(&l->l_mutex);
#endif
}

/*
 * list_iter
 */
void list_iter_set(struct list_iterator *i, struct list *l)
{
	__lock(l);
	i->i_list = l;
	i->i_cur = l->l_first;
	i->i_next = l->l_iter;
	l->l_iter = i;
	__unlock(l);
}

void list_iter_end(struct list_iterator *i)
{
	struct list_iterator **p;
	struct list *l;
	
	l = i->i_list;
	__lock(l);
	p = &l->l_iter;
	while (*p) {
		if (*p == i) {
			*p = i->i_next;
			break;
		}
		p = &(*p)->i_next;
	}
	__unlock(l);
	i->i_cur = NULL;
	i->i_next = NULL;
	i->i_list = NULL;
}

void *list_iter_get(struct list_iterator *i)
{
	void *retval;
	struct list *l;
	
	l = i->i_list;
	__lock(l);
	retval = i->i_cur;
	if (retval)
		i->i_cur = *LIST_NEXT_PTR(l, retval);
	__unlock(l);
	return retval;
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

struct test {
	int i;
	struct test *next;
};

static int remove_func(int nr, void *m, void *arg)
{
	if (((struct test *)m)->i == (int)arg)
		return 1;
	return 0;
}

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
	struct list l = LIST_INIT(struct test, next);
	struct list_iterator i1, i2;
	struct test *t, *s;
	int i;

#if 0
	struct test t1, t2, t3, t4, t5;
	
	t1.i = 1; t2.i = 2; t3.i = 3; t4.i = 4; t5.i = 5;
	
	list_enqueue(&l, &t1);
	printf("a %d\n", list_count(&l));
	list_enqueue(&l, &t2);
	printf("b %d\n", list_count(&l));
//	list_enqueue(&l, &t3);
	
//	list_remove(&l, &t3);
	list_remove(&l, &t2);
	printf("c %d\n", list_count(&l));
	list_enqueue(&l, &t4);
//	list_enqueue(&l, &t5);
	
	
	printf("end %d\n", list_count(&l));
	exit(0);
#endif	
	
	
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
	assert(s = malloc(sizeof(int) * MAX_ITEMS));
	verbose_print(1, "start\n");
	for (i = 0; i < MAX_ITEMS; i++) {
		assert(t = malloc(sizeof(struct test)));
		t->i = i;
		verbose_print(2, "%d ", i);
		list_push(&l, t);
	}
	assert(MAX_ITEMS == list_count(&l));
	verbose_print(1, "\nremove even members\n");
	for (i = 0; i < MAX_ITEMS; i += 2) {
		t = list_remove_func(&l, remove_func, (void *) i);
		assert(t);
		assert(t->i == i);
		verbose_print(2, "%d ", i);
		free(t);
	}
	verbose_print(1, "\nremove odd members\n");
	for (i = MAX_ITEMS - 1; i >= 0; i -= 2) {
		t = list_pop(&l);
		assert(t);
		assert(t->i == i);
		verbose_print(2, "%d ", i);
		free(t);
	}
	assert(!list_pop(&l));

	verbose_print(1, "\nengueue members\n");
	for (i = 0; i < MAX_ITEMS; i++) {
		assert(t = malloc(sizeof(struct test)));
		t->i = i;
		verbose_print(2, "%d ", i);
		list_enqueue(&l, t);
	}
	
	verbose_print(1, "\niter_get/list_nr members\n");
	list_iter_set(&i1, &l);
	for (i = 0; i < MAX_ITEMS; i++) {
		t = list_iter_get(&i1);
		assert(t);
		assert(t->i == i);
		verbose_print(2, "%d ", i);
		t = list_at(&l, i);
		assert(t);
		assert(t->i == i);
	}
	assert(!list_iter_get(&i1));
	list_iter_end(&i1);
	
	verbose_print(1, "\n2 iter_get members\n");
	list_iter_set(&i1, &l);
	list_iter_set(&i2, &l);
	while ((t = list_iter_get(&i1))) {
		assert(t);
		verbose_print(2, "%d ", t->i);
		t = list_iter_get(&i2);
		assert(t);
		verbose_print(2, "%d ", t->i);
	}
	assert(!list_iter_get(&i1));
	assert(!list_iter_get(&i2));
	list_iter_end(&i1);
	list_iter_end(&i2);

	verbose_print(1, "\niter push/pop test\n");
	list_iter_set(&i1, &l);
	list_iter_set(&i2, &l);
	t = list_pop(&l);
	verbose_print(2, "pop item %d, ", t->i);
	verbose_print(2, "%d ", ((struct test *) list_iter_get(&i1))->i);
	verbose_print(2, "%d ", ((struct test *) list_iter_get(&i2))->i);
	list_push(&l, t);
	verbose_print(2, "%d ", ((struct test *) list_iter_get(&i1))->i);
	verbose_print(2, "%d ", ((struct test *) list_iter_get(&i2))->i);
	list_iter_end(&i1);
	list_iter_end(&i2);
	
	t = list_pop(&l);
	list_iter_set(&i1, &l);
	list_iter_set(&i2, &l);
	list_push(&l, t);
	verbose_print(2, "%d ", ((struct test *) list_iter_get(&i1))->i);
	verbose_print(2, "%d ", ((struct test *) list_iter_get(&i2))->i);
	list_iter_end(&i1);
	list_iter_end(&i2);

	verbose_print(1, "\npop members\n");
	for (i = 0; i < MAX_ITEMS; i++) {
		t = list_pop(&l);
		assert(t);
		assert(t->i == i);
		verbose_print(2, "%d ", i);
		free(t);
	}
	assert(!list_pop(&l));

	assert(list_count(&l) == 0);
	

	verbose_print(1, "\nenqueue members\n");
	for (i = 0; i < MAX_ITEMS; i++) {
		s[i].i = i;
		verbose_print(2, "%d ", i);
		list_enqueue(&l, &(s[i]));
	}
	assert(list_count(&l) == MAX_ITEMS);

	verbose_print(1, "\nremove members\n");
	for (i = MAX_ITEMS - 1; i >= 0; i--) {
		assert(list_remove(&l, &(s[i])) == &(s[i]));
	};
	verbose_print(1, "\nenqueue members\n");
	for (i = 0; i < MAX_ITEMS; i++) {
		list_enqueue(&l, &(s[i]));
	}
	verbose_print(1, "\nremove 1/2 members\n");
	for (i = MAX_ITEMS - 1; i >= MAX_ITEMS / 2; i--) {
		assert(list_remove(&l, &(s[i])) == &(s[i]));
	}
	verbose_print(1, "\nenqueue 1/2 members\n");
	for (i = MAX_ITEMS / 2; i < MAX_ITEMS; i++) {
		list_enqueue(&l, &(s[i]));
	}
	assert(list_count(&l) == MAX_ITEMS);
	verbose_print(1, "\nOK\n");
	return 0;
}

#endif
