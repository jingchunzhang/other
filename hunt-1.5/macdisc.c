/*
 *
 *	This is free software. You can redistribute it and/or modify under
 *	the terms of the GNU General Public License version 2.
 *
 * 	Copyright (C) 1998 by kra
 *
 */
#include "hunt.h"
#include <sys/time.h>
#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>
#include <assert.h>
#include <errno.h>

void mac_discover_range(unsigned int start_ip, unsigned int end_ip, int count)
{
	unsigned int addr, j;
	struct timespec ts;

	for (j = 1; j <= count; j++) {
		for (addr = start_ip;
		     ntohl(addr) <= ntohl(end_ip);
		     addr = htonl(ntohl(addr) + 1)) {
			mac_discover(addr, 1);
		}
		ts.tv_sec = 0;
		ts.tv_nsec = 200000000;
		nanosleep(&ts, NULL);
	}
}

void mac_discover(unsigned int ip, int count)
{
	struct arp_spec as;
	struct timespec ts;
	int i;
	
	as.src_mac = my_eth_mac;
	as.dst_mac = mac_broadcast;
	as.oper = htons(ARPOP_REQUEST);
	as.sender_mac = my_eth_mac;
	as.sender_addr = my_eth_ip;
	as.target_mac = mac_zero;
	as.target_addr = ip;
	
	ts.tv_sec = 0;
	ts.tv_nsec = 100000000;
	for (i = 0; i < count; i++) {
		send_arp_packet(&as);
		if (i < count - 1)
			nanosleep(&ts, NULL);
	}
	/*
	 * reply will be received by hunt
	 */
}


/*
 * arp discovery modul
 */

struct mac_disc_info {
	unsigned int start_addr;
	unsigned int end_addr;
	struct mac_disc_info *next;	
};

static struct list l_mdi = LIST_INIT(struct mac_disc_info, next);

static int  wait_sec = 300;
static volatile int  stop_break = 0;
static int thr_running = 0;
static pthread_t mac_thr;
static volatile int stop = 0;
static pthread_mutex_t mutex_stop = PTHREAD_MUTEX_INITIALIZER;
static pthread_cond_t  cond_stop = PTHREAD_COND_INITIALIZER;

static void *mac_disc_thr(void *arg)
{
	struct list_iterator li;
	struct mac_disc_info *mdi;
	unsigned int addr;
	struct timeval tv;
	struct timespec ts;
	int retval;
	
	pthread_sigmask(SIG_BLOCK, &intr_mask, NULL);
	setpriority(PRIO_PROCESS, getpid(), 10);
	stop_break = 0;
	while (!stop) {
		list_iter_set(&li, &l_mdi);
		while ((mdi = list_iter_get(&li)) && !stop) {
			for (addr = mdi->start_addr; 
			     ntohl(addr) <= ntohl(mdi->end_addr) && !stop; 
			     addr = htonl(ntohl(addr) + 1)) {
				mac_discover(addr, 1);
			}
		}
		list_iter_end(&li);
		pthread_mutex_lock(&mutex_stop);
		retval = 0;
		gettimeofday(&tv, NULL);
		ts.tv_sec = tv.tv_sec + wait_sec;
		ts.tv_nsec = tv.tv_usec * 1000;
		while (!stop && retval != ETIMEDOUT && !stop_break)
			retval = pthread_cond_timedwait(&cond_stop, &mutex_stop, &ts);
		pthread_mutex_unlock(&mutex_stop);
		stop_break = 0;
	}
	return NULL;
}


static int start_mac_discovery(void)
{
	if (thr_running) {
		printf("mac discoverer already running\n");
		return -1;
	}
	pthread_mutex_init(&mutex_stop, NULL);
	pthread_cond_init(&cond_stop, NULL);
	stop = 0;
	pthread_create(&mac_thr, NULL, mac_disc_thr, NULL);
	thr_running = 1;
	return 0;
}

static int stop_mac_discovery(void)
{
	if (!thr_running) {
		printf("mac discoverer isn't running\n");
		return -1;
	}
	stop = 1;
	pthread_mutex_lock(&mutex_stop);
	pthread_cond_signal(&cond_stop);
	pthread_mutex_unlock(&mutex_stop);
	pthread_join(mac_thr, NULL);
	thr_running = 0;
	return 0;
}

void print_mac_daemon()
{
	if (thr_running) {
		if (pthread_kill(mac_thr, 0) != 0) {
			pthread_join(mac_thr, NULL);
			mac_thr = (pthread_t) 0;
			thr_running = 0;
			set_tty_color(COLOR_BRIGHTRED);
			printf("MAC daemon failed - bug\n");
			set_tty_color(COLOR_LIGHTGRAY);
		} else
			printf("M");
	}
}

/*
 * print_mac_table is in hunt.c which will receive arp reply
 */

static void mdi_list(void)
{
	struct list_iterator li;
	struct mac_disc_info *mdi;
	int count = 0;
	
	list_iter_set(&li, &l_mdi);
	while ((mdi = list_iter_get(&li))) {
		printf("%2d) %-24s - %-24s\n", count++,
		       host_lookup(mdi->start_addr, hl_mode),
		       host_lookup(mdi->end_addr, hl_mode));
		if (count % lines_o == 0)
			lines_o_press_key();
	}
	list_iter_end(&li);
}

static void mdi_add(void)
{
	struct mac_disc_info *mdi;
	unsigned int start_ip, end_ip;
	
	if ((start_ip = menu_choose_hostname("start ip addr", NULL)) == -1)
		return;
	if ((end_ip = menu_choose_hostname("end ip addr", NULL)) == -1)
		return;
	mdi = malloc(sizeof(struct mac_disc_info));
	assert(mdi);
	mdi->start_addr = start_ip;
	mdi->end_addr = end_ip;
	list_enqueue(&l_mdi, mdi);
}

static void mdi_mod(void)
{
	struct mac_disc_info *mdi;
	unsigned int start_ip, end_ip;
	int nr;
	
	mdi_list();
	if ((nr = menu_choose_unr("choose item", 0, list_count(&l_mdi) - 1, list_count(&l_mdi) - 1)) == -1)
		return;
	if (!(mdi = list_at(&l_mdi, nr)))
		return;

	if ((start_ip = menu_choose_hostname("start ip addr", host_lookup(mdi->start_addr, hl_mode))) == -1)
		return;
	if ((end_ip = menu_choose_hostname("end ip addr", host_lookup(mdi->end_addr, hl_mode))) == -1)
		return;
	mdi->start_addr = start_ip;
	mdi->end_addr = end_ip;
}

static void mdi_del(void)
{
	int i;
	struct mac_disc_info *mdi;
	
	mdi_list();
	i = menu_choose_unr("item nr. to delete", 0, 
			   list_count(&l_mdi) - 1, -1);
	if (i >= 0) {
		mdi = list_remove_at(&l_mdi, i);
		free(mdi);
	}
}

static void mdi_time_wait(void)
{
	int min, sec;
	
	min = wait_sec / 60;
	sec = wait_sec % 60;
	if ((min = menu_choose_unr("choose time interval min", 0, 1000, min)) == -1)
		return;
	if ((sec = menu_choose_unr("choose time interval sec", 0, 10000, sec)) == -1)
		return;
	wait_sec = min * 60 + sec;
	
	stop_break = 1;
	pthread_mutex_lock(&mutex_stop);
	pthread_cond_signal(&cond_stop);
	pthread_mutex_unlock(&mutex_stop);
}

void mac_disc_menu(void)
{
 	char *m_menu =  "s/k)   start/stop daemon\n"
			"l)     list discoverer setup     h) list HW mac addresses\n"
			"t)     time to sleep\n"
			"a/m/d) add/mod/del entry\n"
			"x)     return\n";
	char *m_keys = "sklhtadmx";
	int run_it;

	run_it = 1;
	while (run_it) {
		switch (menu("mac disc. daemon", m_menu, "macd", m_keys, 0)) {
		    case 's':
			start_mac_discovery();
			break;
		    case 'k':
			stop_mac_discovery();
			break;
		    case 'l':
			mdi_list();
			break;
		    case 'h':
			print_mac_table();
			break;
		    case 't':
			mdi_time_wait();
			break;
		    case 'a':
			mdi_add();
			break;
		    case 'm':
			mdi_mod();
			break;
		    case 'd':
			mdi_del();
			break;
		    case 'x':
			run_it = 0;
			break;
		}
	}
}
