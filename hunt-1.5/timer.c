/*
 *
 *	This is free software. You can redistribute it and/or modify under
 *	the terms of the GNU General Public License version 2.
 *
 * 	Copyright (C) 1998 by kra
 *
 */
#include <stdio.h>
#include <unistd.h>
#include "hunt.h"

struct list timejob_list = LIST_INIT(struct timejob, j_next);

pthread_t timejob_thr;

pthread_mutex_t timejob_mutex = PTHREAD_MUTEX_INITIALIZER;
pthread_cond_t  timejob_cond = PTHREAD_COND_INITIALIZER;
pthread_cond_t  timejob_curr_cond = PTHREAD_COND_INITIALIZER;
pthread_cond_t  timejob_run_cond = PTHREAD_COND_INITIALIZER;

struct timejob *timejob_curr = NULL;
int timejob_run = 1;

static int __register(struct timejob *tj)
{
	struct list_iterator li;
	int i, retval;
	int insert_it;
	struct timejob *p;
	
	retval = 0;
	insert_it = 0;
	i = 0;
	list_iter_set(&li, &timejob_list);
	while ((p = list_iter_get(&li))) {
		if (p->j_ts.tv_sec > tj->j_ts.tv_sec ||
		    (p->j_ts.tv_sec == tj->j_ts.tv_sec && p->j_ts.tv_nsec > tj->j_ts.tv_nsec)) {
			insert_it = 1;
			break;
		}
		i++;
	}
	list_iter_end(&li);
	if (insert_it) {
		list_insert_at(&timejob_list, i, tj);
		if (i == 0)
			retval = 1;	/* reschedule timer */
	} else {
		list_enqueue(&timejob_list, tj);
		if (list_count(&timejob_list) == 1)
			retval = 1;	/* reschedule timer */
	}
#if 0
	printf("registered:\n");
	list_iter_set(&li, &timejob_list);
	while ((p = list_iter_get(&li))) {
		printf("%x - %d\n", p, p->j_arg_sec);
	};
	list_iter_end(&li);
#endif
	return retval;
}

void register_timejob(struct timejob *tj)
{
	pthread_mutex_lock(&timejob_mutex);
	if (__register(tj))
		pthread_cond_signal(&timejob_cond);
	pthread_mutex_unlock(&timejob_mutex);
}

void register_timejob_rel(struct timejob *tj, int relsec)
{
	struct timeval tv;
	
	gettimeofday(&tv, NULL);
	tj->j_ts.tv_sec = tv.tv_sec + relsec;
	tj->j_ts.tv_nsec = tv.tv_usec * 1000;
	register_timejob(tj);
}

void register_timejob_milsec_rel(struct timejob *tj, int milsec)
{
	struct timeval tv;
	int sec, msec;
	
	gettimeofday(&tv, NULL);
	sec = milsec / 1000;
	msec = milsec % 1000;
	tj->j_ts.tv_sec = tv.tv_sec + sec;
	tj->j_ts.tv_nsec = tv.tv_usec * 1000 + msec * 1000000;
	register_timejob(tj);
}

void unregister_timejob(struct timejob *tj)
{
	pthread_mutex_lock(&timejob_mutex);
	while (timejob_curr == tj)
		pthread_cond_wait(&timejob_curr_cond, &timejob_mutex);
	list_remove(&timejob_list, tj);
	pthread_cond_signal(&timejob_cond);
	pthread_mutex_unlock(&timejob_mutex);
}


static void *timejob_thread(void *arg)
{
	struct timejob *tj;
	struct timeval tv;
	struct timespec timeout;
	int sec;
	
	setpriority(PRIO_PROCESS, getpid(), 10);
	pthread_mutex_lock(&timejob_mutex);
	while (timejob_run && pthread_kill(main_thread_id, 0) == 0) {
		tj = list_peek(&timejob_list);
		if (tj) {
			gettimeofday(&tv, NULL);
			if (tv.tv_sec > tj->j_ts.tv_sec ||
			    (tv.tv_sec == tj->j_ts.tv_sec && tv.tv_usec * 1000 >= tj->j_ts.tv_nsec)) {
				timejob_curr = tj;
				list_pop(&timejob_list);
				pthread_mutex_unlock(&timejob_mutex);
				sec = timejob_curr->j_func(timejob_curr->j_arg,
							   timejob_curr->j_arg_sec);
				pthread_mutex_lock(&timejob_mutex);
				if (sec) {
					gettimeofday(&tv, NULL);
					tj->j_ts.tv_sec = tv.tv_sec + sec;
					tj->j_ts.tv_nsec = tv.tv_usec * 1000;
					__register(tj);
				}
				timejob_curr = NULL;
				pthread_cond_signal(&timejob_curr_cond);
			} else {
				/* copy timeout as the struct can be removed from the list */
				timeout = tj->j_ts;
				pthread_cond_timedwait(&timejob_cond, &timejob_mutex, &timeout);
			}
		} else {
			pthread_cond_wait(&timejob_cond, &timejob_mutex);
		}
	}
	timejob_run = 2;
	pthread_cond_signal(&timejob_run_cond);
	pthread_mutex_unlock(&timejob_mutex);
	return NULL;
}

void timer_init(void)
{
	if (pthread_create(&timejob_thr, NULL, timejob_thread, NULL))
		exit(1);
}

void timer_done(void)
{
	pthread_mutex_lock(&timejob_mutex);
	timejob_run = 0;
	pthread_cond_signal(&timejob_cond);
	while (timejob_run != 2 && pthread_kill(timejob_thr, 0) == 0)
		pthread_cond_wait(&timejob_run_cond, &timejob_mutex);
	pthread_mutex_unlock(&timejob_mutex);
}
