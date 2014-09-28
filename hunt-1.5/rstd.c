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
#include <string.h>
#include <stdlib.h>
#include <unistd.h>

/*
 * reset daemon
 */

struct rst_db_item {
	unsigned int src_addr;
	unsigned int src_mask;
	unsigned int dst_addr;
	unsigned int dst_mask;
	unsigned int src_ports[MAX_PORTS + 1];
	unsigned int dst_ports[MAX_PORTS + 1];
	int rst_mode;
	int rst_only_syn;
	struct rst_db_item *next;
};

static struct list l_rst_packet = LIST_INIT(struct packet, p_next[MODULE_RSTD]);

static struct ifunc_item ifunc_tcp;
static pthread_t rstd_thr;
static int rstd_running = 0;
static struct list l_rst_db = LIST_INIT(struct rst_db_item, next);


static inline int packet_match_db_item(struct packet *p, struct rst_db_item *dbi)
{
	struct iphdr *iph = p->p_iph;
	struct tcphdr *tcph = p->p_hdr.p_tcph;
	
	if ((iph->saddr & dbi->src_mask) == (dbi->src_addr & dbi->src_mask) &&
	    (iph->daddr & dbi->dst_mask) == (dbi->dst_addr & dbi->dst_mask) &&
	     port_match(tcph->source, dbi->src_ports) &&
	     port_match(tcph->dest, dbi->dst_ports)) {
		if (!dbi->rst_only_syn) {
			return 1;
		}
		if (tcph->syn) {
			return 1;
		}
	}

	return 0;
}

static struct rst_db_item *packet_match_db(struct packet *p)
{
	struct list_iterator li;
	struct rst_db_item *dbi;
	
	list_lock(&l_rst_db);
	list_iter_set(&li, &l_rst_db);
	while ((dbi = list_iter_get(&li))) {
		if (packet_match_db_item(p, dbi))
			break;
	}
	list_iter_end(&li);
	list_unlock(&l_rst_db);
	return dbi;
}

/*
 * this function is running in the hunt thread
 */
static void func_tcp_packet(struct packet *p, void *arg)
{
	struct rst_db_item *dbi;
	
	if (/*p->p_hdr.p_tcph->syn || */ p->p_hdr.p_tcph->fin)
		return;
	if ((dbi = packet_match_db(p))) {
		packet_want(p);
		p->p_arg[MODULE_RSTD] = (void *) dbi->rst_mode;
		list_produce(&l_rst_packet, p);
	}
}

static void *rst_daemon_thr(void *arg)
{
	struct iphdr *iph;
	struct tcphdr *tcph;
	struct conn_info *ci, __ci;
	struct conn_info *pci;
	struct user_conn_info uci;
	struct packet *p;
	struct timespec ts;
	int rst_mode;

	pthread_sigmask(SIG_BLOCK, &intr_mask, NULL);
	setpriority(PRIO_PROCESS, getpid(), 0);
	while ((p = list_consume(&l_rst_packet, NULL))) {
		iph = p->p_iph;
		tcph = p->p_hdr.p_tcph;
		uci.src_addr = iph->saddr;
		uci.dst_addr = iph->daddr;
		uci.src_port = tcph->source;
		uci.dst_port = tcph->dest;
		if (!(pci = conn_get(&uci))) { /* try to get current seq numbers from connection */
			__ci.src_addr = iph->saddr;
			__ci.dst_addr = iph->daddr;
			__ci.src_port = tcph->source;
			__ci.dst_port = tcph->dest;
			
			__ci.src.next_seq = htonl(ntohl(tcph->seq) + p->p_data_len);
			__ci.src.next_d_seq = tcph->ack ? tcph->ack_seq : 0;
			memcpy(__ci.src.src_mac, p->p_ethh->h_source, ETH_ALEN);
			memcpy(__ci.src.dst_mac, p->p_ethh->h_dest, ETH_ALEN);
			__ci.src.window = tcph->window;	/* ok, wrong */
			__ci.src.id = iph->id;		/* ok, wrong */
			
			__ci.dst.next_seq = __ci.src.next_d_seq;
			__ci.dst.next_d_seq = __ci.src.next_seq;
#if 0			
			memcpy(__ci.dst.src_mac, right_arp_addr(p->p_ethh->h_dest), ETH_ALEN);
			memcpy(__ci.dst.dst_mac, spoofed_arp_addr(p->p_ethh->h_source), ETH_ALEN);
#else
			memcpy(__ci.dst.src_mac, p->p_ethh->h_dest, ETH_ALEN);
			memcpy(__ci.dst.dst_mac, p->p_ethh->h_source, ETH_ALEN);
#endif
			__ci.dst.window = tcph->window;	/* ok, wrong */
			__ci.dst.id = iph->id;		/* ok, wrong */
			
			ci = &__ci;
		} else
			ci = pci;
		packet_free(p);
		rst_mode = (int) p->p_arg[MODULE_RSTD];
		ts.tv_sec = 0;
		ts.tv_nsec = 100000000;
		switch (rst_mode) {
		    case MODE_SRC:
			rst(ci, 4, 0);
			nanosleep(&ts, NULL);
			rst(ci, 4, 0);
			break;
		    case MODE_DST:
			rst(ci, 4, 1);
			nanosleep(&ts, NULL);
			rst(ci, 4, 1);
			break;
		    case MODE_BOTH:
			rst(ci, 4, 0);
			rst(ci, 4, 1);
			nanosleep(&ts, NULL);
			rst(ci, 4, 0);
			rst(ci, 4, 1);
			break;
		}
		if (pci)
			conn_free(pci);
	}
	return NULL;
}

static void rst_daemon_start(void)
{
	if (rstd_running) {
		printf("daemon already running\n");
		return;
	}
	list_produce_start(&l_rst_packet);
	ifunc_tcp.func = func_tcp_packet;
	ifunc_tcp.arg = NULL;
	list_enqueue(&l_ifunc_tcp, &ifunc_tcp);
	
	pthread_create(&rstd_thr, NULL, rst_daemon_thr, NULL);
	rstd_running = 1;
	printf("rst daemon started\n");
}

static void rst_daemon_stop(void)
{
	if (!rstd_running) {
		printf("daemon isn't running\n");
		return;
	}
	list_remove(&l_ifunc_tcp, &ifunc_tcp);
	packet_flush(&l_rst_packet);
	list_produce_done(&l_rst_packet);
	
	pthread_join(rstd_thr, NULL);
	rstd_running = 0;
	printf("rst daemon stoped\n");
}

void print_rst_daemon(void)
{
	if (rstd_running) {
		if (pthread_kill(rstd_thr, 0) != 0) {
			pthread_join(rstd_thr, NULL);
			rstd_thr = (pthread_t) 0;
			rstd_running = 0;
			set_tty_color(COLOR_BRIGHTRED);
			printf("RST daemon failed - bug\n");
			set_tty_color(COLOR_LIGHTGRAY);
		} else
			printf("R");
	}
}

/*
 * 
 * user interface
 *
 */
static void db_item_print(int i, struct rst_db_item *dbi)
{
	char *str_mode;
	char buf_src_ports[BUFSIZE], buf_dst_ports[BUFSIZE];
	char buf[BUFSIZE];
	
	str_mode = sdbmode_to_char(dbi->rst_mode);
	sprintf_db_ports(dbi->src_ports, buf_src_ports, sizeof(buf_src_ports), 1);
	sprintf_db_ports(dbi->dst_ports, buf_dst_ports, sizeof(buf_dst_ports), 1);
	sprintf(buf, "%s/%d [%s]", host_lookup(dbi->src_addr, hl_mode),
		count_mask(dbi->src_mask), buf_src_ports);
	printf("%2d) %-24s --> %s/%d [%s] rst %s %s\n", i,
	       buf,
	       host_lookup(dbi->dst_addr, hl_mode), count_mask(dbi->dst_mask),
	       buf_dst_ports,
	       str_mode,
	       dbi->rst_only_syn ? "SYN only" : "all");
}

static void rst_list_items(void)
{
	struct list_iterator li;
	struct rst_db_item *dbi;
	int i = 0;
	
	list_iter_set(&li, &l_rst_db);
	while ((dbi = list_iter_get(&li))) {
		db_item_print(i++, dbi);
		if (i % lines_o == 0)
			lines_o_press_key();
	}
	list_iter_end(&li);
}


static void rst_add_item(void)
{
	struct rst_db_item *dbi;
	unsigned int src_ip, dst_ip;
	unsigned int src_mask, dst_mask;
	int src_ports[MAX_PORTS + 1], dst_ports[MAX_PORTS + 1];
	int mode, syn_mode;
	int nr;


	if (menu_choose_host_mask_ports_dfl("src ip addr/mask ports", &src_ip,
				&src_mask, src_ports, 0, 0, NULL) < 0)
		return;
	if (menu_choose_host_mask_ports_dfl("dst ip addr/mask ports", &dst_ip,
				&dst_mask, dst_ports, 0, 0, NULL) < 0)
		return;
	if ((mode = menu_choose_sdb("mode", 'b')) == -1)
		return;
	if ((syn_mode = menu_choose_char("reset only syn y/n", "yn", 'y')) == -1)
		return;
	if ((nr = menu_choose_unr("insert at", 0, list_count(&l_rst_db), list_count(&l_rst_db))) == -1)
		return;
	
	dbi = malloc(sizeof(struct rst_db_item));
	memset(dbi, 0, sizeof(struct rst_db_item));
	dbi->src_addr = src_ip;
	dbi->src_mask = src_mask;
	port_htons(src_ports);
	memcpy(dbi->src_ports, src_ports, sizeof(int) * (MAX_PORTS + 1));
	dbi->dst_addr = dst_ip;
	dbi->dst_mask = dst_mask;
	port_htons(dst_ports);
	memcpy(dbi->dst_ports, dst_ports, sizeof(int) * (MAX_PORTS + 1));
	dbi->rst_mode = sdb_to_int(mode);
	switch (syn_mode) {
	    case 'y':
		dbi->rst_only_syn = 1;
		break;
	    case 'n':
		dbi->rst_only_syn = 0;
		break;
	}
	list_insert_at(&l_rst_db, nr, dbi);
}

static void rst_mod_item(void)
{
	struct rst_db_item *dbi;
	unsigned int src_ip, dst_ip;
	unsigned int src_mask, dst_mask;
	int src_ports[MAX_PORTS + 1], dst_ports[MAX_PORTS + 1];
	int mode, syn_mode;
	int nr;
	
	rst_list_items();
	if ((nr = menu_choose_unr("choose item", 0, list_count(&l_rst_db) - 1, list_count(&l_rst_db) - 1)) == -1)
		return;
	if (!(dbi = list_at(&l_rst_db, nr)))
		return;
	if (menu_choose_host_mask_ports_dfl("src ip addr/mask ports",
			    &src_ip, &src_mask, src_ports,
			    dbi->src_addr, dbi->src_mask, dbi->src_ports) < 0)
		return;
	if (menu_choose_host_mask_ports_dfl("dst ip addr/mask ports", 
			    &dst_ip, &dst_mask, dst_ports,
			    dbi->dst_addr, dbi->dst_mask, dbi->dst_ports) < 0)
		return;
	if ((mode = menu_choose_sdb("mode", int_to_sdb(dbi->rst_mode))) == -1)
		return;
	if ((syn_mode = menu_choose_char("reset only syn y/n", "yn", dbi->rst_only_syn ? 'y' : 'n')) == -1)
		return;
	
	port_htons(src_ports);
	port_htons(dst_ports);

	dbi->src_addr = src_ip;
	dbi->src_mask = src_mask;
	memcpy(dbi->src_ports, src_ports, sizeof(int) * (MAX_PORTS + 1));
	dbi->dst_addr = dst_ip;
	dbi->dst_mask = dst_mask;
	memcpy(dbi->dst_ports, dst_ports, sizeof(int) * (MAX_PORTS + 1));
	dbi->rst_mode = sdb_to_int(mode);
	switch (syn_mode) {
	    case 'y':
		dbi->rst_only_syn = 1;
		break;
	    case 'n':
		dbi->rst_only_syn = 0;
		break;
	}
}

static void rst_del_item(void)
{
	int i;
	struct rst_db_item *dbi;
	
	rst_list_items();
	i = menu_choose_unr("item nr. to delete", 0, 
			   list_count(&l_rst_db) - 1, -1);
	if (i >= 0) {
		dbi = list_remove_at(&l_rst_db, i);
		free(dbi);
	}
}

void rstd_menu(void)
{
	char *r_menu =  "s/k)   start/stop daemon\n"
			"l)     list reset database\n"
			"a/m/d) add/mod/del entry\n"
			"x)     return\n";
	char *r_keys = "skladmx";
	int run_it;
	
	run_it = 1;
	while (run_it) {
		switch (menu("reset daemon", r_menu, "rstd", r_keys, 0)) {
		    case 's':
			rst_daemon_start();
			break;
		    case 'k':
			rst_daemon_stop();
			break;
		    case 'l':
			rst_list_items();
			break;
		    case 'a':
			rst_add_item();
			break;
		    case 'd':
			rst_del_item();
			break;
		    case 'm':
			rst_mod_item();
			break;
		    case 'x':
			run_it = 0;
			break;
		}
	}
}
