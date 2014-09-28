/*
 *
 *	This is free software. You can redistribute it and/or modify under
 *	the terms of the GNU General Public License version 2.
 *
 * 	Copyright (C) 1999 by kra
 *
 */
#include "hunt.h"
#include <sys/types.h>
#include <sys/stat.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <fcntl.h>
#include <assert.h>

/*
 * 
 * This is experimental code, do not expect mutch use of it just now
 * 
 */

/*
 * 
 * this packet relay module is designed for miscellaneous tasks when
 * relaying packets from/to spoofed hosts
 * 
 */

#define RIFL_PKT_DROP		1
#define RIFL_PKT_ETHTAP_RELAY	2

struct relay_item {
	pthread_mutex_t mutex;
	pthread_cond_t  lock_cond;
	int		lock_count;
	
	unsigned int src_addr;
	unsigned int src_mask;
	unsigned int dst_addr;
	unsigned int dst_mask;
	unsigned int src_ports[MAX_PORTS + 1];
	unsigned int dst_ports[MAX_PORTS + 1];
	unsigned int flags;
	int	     ethtap_fd;
	char	    *ethtap_name;
	char	    ethtap_mac[ETH_ALEN];
	struct relay_item *next;
};

static struct list l_relay_db = LIST_INIT(struct relay_item, next);

static void ri_want(struct relay_item *ri)
{
	pthread_mutex_lock(&ri->mutex);
	ri->lock_count++;
	pthread_mutex_unlock(&ri->mutex);
}

static void ri_release(struct relay_item *ri)
{
	pthread_mutex_lock(&ri->mutex);
	if (--(ri->lock_count) == 0)
		pthread_cond_broadcast(&ri->lock_cond);
	pthread_mutex_unlock(&ri->mutex);
}

static void ri_wait_for_release(struct relay_item *ri)
{
	pthread_mutex_lock(&ri->mutex);
	while (ri->lock_count > 0)
		pthread_cond_wait(&ri->lock_cond, &ri->mutex);
	pthread_mutex_unlock(&ri->mutex);
}

static struct relay_item *ri_allocate()
{
	struct relay_item *ri;
	
	ri = malloc(sizeof(struct relay_item));
	assert(ri);
	memset(ri, 0, sizeof(struct relay_item));
	pthread_mutex_init(&ri->mutex, NULL);
	pthread_cond_init(&ri->lock_cond, NULL);
	ri->ethtap_fd = -1;
	return ri;
}

static void ri_free(struct relay_item *ri)
{
	ri_wait_for_release(ri);
	pthread_cond_destroy(&ri->lock_cond);
	pthread_mutex_destroy(&ri->mutex);
	if (ri->ethtap_fd >= 0)
		close(ri->ethtap_fd);
	if (ri->ethtap_name)
		free(ri->ethtap_name);
	free(ri);
}



static inline int packet_match_relay_item(struct packet *p, struct relay_item *ri)
{
	struct iphdr *iph = p->p_iph;
	struct tcphdr *tcph = p->p_hdr.p_tcph;
	
	if ((iph->saddr & ri->src_mask) == (ri->src_addr & ri->src_mask) &&
	    (iph->daddr & ri->dst_mask) == (ri->dst_addr & ri->dst_mask) &&
	     port_match(tcph->source, ri->src_ports) &&
	     port_match(tcph->dest, ri->dst_ports)) {
			return 1;
	}
	return 0;
}

static struct relay_item *packet_match_relay(struct packet *p)
{
	struct list_iterator li;
	struct relay_item *ri;

	list_lock(&l_relay_db);
	list_iter_set(&li, &l_relay_db);
	while ((ri = list_iter_get(&li))) {
		if (packet_match_relay_item(p, ri)) {
			ri_want(ri);	/* lock_count++ on relay_item */
			break;
		}
	}
	list_iter_end(&li);
	list_unlock(&l_relay_db);
	return ri;
}

/*
 * return 0 if not interested,
 * this function is called from arp_relay function that run in 
 * separate thread (relay thread)
 */
void ethtap_relay(struct packet *p, struct relay_item *ri)
{
/*	int eth_hdr_len;*/
	char buf[4096];
	int len;
	struct ethhdr hdr;
	
	if (ri->ethtap_fd < 0) {
		printf("ethtap_relay error: ethtap_fd < 0\n");
		return;
	}
#if 0
	/* write it without eth header */
	printf("relay packet %s:%d to %s:%d\n",
	       host_lookup(p->p_iph->saddr, hl_mode), ntohs(p->p_hdr.p_tcph->source),
	       host_lookup(p->p_iph->daddr, hl_mode), ntohs(p->p_hdr.p_tcph->dest));
	eth_hdr_len = (char *) p->p_iph - (char *) p->p_raw;
	writen(ri->ethtap_fd, (char *) p->p_iph, p->p_raw_len - eth_hdr_len);
#else
#if 0
	struct packet *p_new;
	/* write it with eth header */
	p_new = packet_new();
	packet_copy_data(p_new, p);
	memcpy(p_new->p_ethh->h_dest, ri->ethtap_mac, ETH_ALEN);
/*	memcpy(p_new->p_ethh->h_source, , ETH_ALEN);*/
	printf("relay packet\n");
	writen(ri->ethtap_fd, p_new->p_raw, p_new->p_raw_len);
	packet_free(p_new);

#endif
	/* write it with eth header */
	buf[0] = buf[1] = 0;
	len = 2;
	
	memset(&hdr, 0, sizeof(struct ethhdr));
	hdr.h_proto = p->p_ethh->h_proto;
	memcpy(buf + len, &hdr, sizeof(struct ethhdr));
	len += sizeof(struct ethhdr);
	
	memcpy(buf + len, p->p_raw + sizeof(struct ethhdr), p->p_raw_len - sizeof(struct ethhdr));
	len += p->p_raw_len - sizeof(struct ethhdr);
	
	printf("relay packet %s:%d to %s:%d\n",
	       host_lookup(p->p_iph->saddr, hl_mode), ntohs(p->p_hdr.p_tcph->source),
	       host_lookup(p->p_iph->daddr, hl_mode), ntohs(p->p_hdr.p_tcph->dest));
	writen(ri->ethtap_fd, buf, len);
#endif
}

int process_pktrelay(struct packet *p, struct arp_spoof_info *asi)
{
	struct relay_item *ri;
	int retval;
	
	if (!(ri = packet_match_relay(p)))
		return 0;
	retval = 0;
	if (ri->flags & RIFL_PKT_DROP) {
		retval = 1;
	}
	if (ri->flags & RIFL_PKT_ETHTAP_RELAY) {
		ethtap_relay(p, ri);
		retval = 1;
	}

	ri_release(ri);
	return retval;
}

/*
 * 
 * user interface
 *
 */
static void relay_item_print(int i, struct relay_item *ri)
{
	char buf_src_ports[BUFSIZE], buf_dst_ports[BUFSIZE];
	char buf[BUFSIZE];
	char flags[BUFSIZE];
	
	sprintf_db_ports(ri->src_ports, buf_src_ports, sizeof(buf_src_ports), 1);
	sprintf_db_ports(ri->dst_ports, buf_dst_ports, sizeof(buf_dst_ports), 1);
	sprintf(buf, "%s/%d [%s]", host_lookup(ri->src_addr, hl_mode),
		count_mask(ri->src_mask), buf_src_ports);
	switch (ri->flags) {
	    case RIFL_PKT_DROP:
		sprintf(flags, "DROP");
		break;
	    case RIFL_PKT_ETHTAP_RELAY:
		sprintf(flags, "ETH RELAY to %s", ri->ethtap_name);
		break;
	}
	printf("%2d) %-24s --> %s/%d [%s] flags %s\n", i,
	       buf,
	       host_lookup(ri->dst_addr, hl_mode), count_mask(ri->dst_mask),
	       buf_dst_ports, flags);
}

static void relay_list_items(void)
{
	struct list_iterator li;
	struct relay_item *ri;
	int i = 0;
	
	list_iter_set(&li, &l_relay_db);
	while ((ri = list_iter_get(&li))) {
		relay_item_print(i++, ri);
		if (i % lines_o == 0)
			lines_o_press_key();
	}
	list_iter_end(&li);
}


static void relay_add_item(void)
{
	struct relay_item *ri;
	unsigned int src_ip, dst_ip;
	unsigned int src_mask, dst_mask;
	int src_ports[MAX_PORTS + 1], dst_ports[MAX_PORTS + 1];
	char name_buf[128], name_buf2[256];
	char ethtap_mac[ETH_ALEN];
	int flags_c;
	int nr, ethtap_fd;

	ethtap_fd = -1;
	if (menu_choose_host_mask_ports_dfl("src ip addr/mask ports", &src_ip,
				&src_mask, src_ports, 0, 0, NULL) < 0)
		return;
	if (menu_choose_host_mask_ports_dfl("dst ip addr/mask ports", &dst_ip,
				&dst_mask, dst_ports, 0, 0, NULL) < 0)
		return;
	if ((flags_c = menu_choose_char("flags: [n]one, [d]rop, [e]th_relay", "nde", 'd')) < 0)
		return;
	if (flags_c == 'e') {
		if (menu_choose_string("eth relay device", name_buf, sizeof(name_buf),
				   "tap0") < 0)
			return;
		strcpy(name_buf2, "/dev/");
		strcat(name_buf2, name_buf);
		if ((ethtap_fd = open(name_buf2, O_RDWR)) < 0) {
			printf("cannot open %s for read/write\n", name_buf2);
			return;
		}
		get_ifc_info(name_buf, NULL, ethtap_mac);
	}
	if ((nr = menu_choose_unr("insert at", 0, list_count(&l_relay_db), list_count(&l_relay_db))) == -1)
		return;
	ri = ri_allocate();
	ri->src_addr = src_ip;
	ri->src_mask = src_mask;
	port_htons(src_ports);
	memcpy(ri->src_ports, src_ports, sizeof(int) * (MAX_PORTS + 1));
	ri->dst_addr = dst_ip;
	ri->dst_mask = dst_mask;
	port_htons(dst_ports);
	memcpy(ri->dst_ports, dst_ports, sizeof(int) * (MAX_PORTS + 1));
	switch (flags_c) {
	    case 'd':
		ri->flags = RIFL_PKT_DROP;
		break;
	    case 'e':
		ri->flags = RIFL_PKT_ETHTAP_RELAY;
		ri->ethtap_name = strdup(name_buf);
		ri->ethtap_fd = ethtap_fd;
		memcpy(ri->ethtap_mac, ethtap_mac, ETH_ALEN);
		break;
	    default:
		ri->flags = 0;
	}
	list_insert_at(&l_relay_db, nr, ri);
}

static void relay_mod_item(void)
{
	struct relay_item *ri;
	unsigned int src_ip, dst_ip;
	unsigned int src_mask, dst_mask;
	int src_ports[MAX_PORTS + 1], dst_ports[MAX_PORTS + 1];
	char name_buf[128], name_buf2[256];
	int nr;
	char flags_dfl;
	int flags_c, ethtap_fd;
	
	ethtap_fd = -1;
	relay_list_items();
	if ((nr = menu_choose_unr("choose item", 0, list_count(&l_relay_db) - 1, list_count(&l_relay_db) - 1)) == -1)
		return;
	if (!(ri = list_at(&l_relay_db, nr)))
		return;
	if (menu_choose_host_mask_ports_dfl("src ip addr/mask ports",
			    &src_ip, &src_mask, src_ports,
			    ri->src_addr, ri->src_mask, ri->src_ports) < 0)
		return;
	if (menu_choose_host_mask_ports_dfl("dst ip addr/mask ports", 
			    &dst_ip, &dst_mask, dst_ports,
			    ri->dst_addr, ri->dst_mask, ri->dst_ports) < 0)
		return;
	switch (ri->flags) {
	    case RIFL_PKT_DROP:
		flags_dfl = 'd';
		break;
	    case RIFL_PKT_ETHTAP_RELAY:
		flags_dfl = 'e';
		break;
	    default:
		flags_dfl = 'n';
	}
	if ((flags_c = menu_choose_char("flags: [n]one [d]rop [e]th_relay", "nde", flags_dfl)) < 0)
		return;
	if (flags_c == 'e') {
		if (menu_choose_string("eth relay device", name_buf, sizeof(name_buf),
				       ri->ethtap_name) < 0)
			return;
		if (strcmp(name_buf, ri->ethtap_name) != 0) {
			strcpy(name_buf2, "/dev/");
			strcat(name_buf2, name_buf);
			if ((ethtap_fd = open(name_buf2, O_RDWR)) < 0) {
				printf("cannot open %s for read/write\n", name_buf2);
				return;
			}
		}
	}
	
	port_htons(src_ports);
	port_htons(dst_ports);

	ri->src_addr = src_ip;
	ri->src_mask = src_mask;
	memcpy(ri->src_ports, src_ports, sizeof(int) * (MAX_PORTS + 1));
	ri->dst_addr = dst_ip;
	ri->dst_mask = dst_mask;
	memcpy(ri->dst_ports, dst_ports, sizeof(int) * (MAX_PORTS + 1));
	if (flags_c != 'e' || ethtap_fd >= 0) {
		if (ri->ethtap_fd >= 0) {
			close(ri->ethtap_fd);
			ri->ethtap_fd = -1;
		}
		if (ri->ethtap_name) {
			free(ri->ethtap_name);
			ri->ethtap_name = NULL;
		}
	}
	switch (flags_c) {
	    case 'd':
		ri->flags = RIFL_PKT_DROP;
		break;
	    case 'e':
		ri->flags = RIFL_PKT_ETHTAP_RELAY;
		if (ethtap_fd >= 0) {
			ri->ethtap_fd = ethtap_fd;
			ri->ethtap_name = strdup(name_buf);
		}
		break;
	    default:
		ri->flags = 0;
	}
}

static void relay_del_item(void)
{
	int i;
	struct relay_item *ri;
	
	relay_list_items();
	i = menu_choose_unr("item nr. to delete", 0, 
			   list_count(&l_relay_db) - 1, -1);
	if (i >= 0) {
		ri = list_remove_at(&l_relay_db, i);
		ri_free(ri);
	}
}

void relay_menu(void)
{
	char *r_menu =  "l)     list relay database\n"
			"a/m/d) add/mod/del entry\n"
			"x)     return\n";
	char *r_keys = "ladmx";
	int run_it;
	
	run_it = 1;
	while (run_it) {
		switch (menu("relay database", r_menu, "arps/relay", r_keys, 0)) {
		    case 'l':
			relay_list_items();
			break;
		    case 'a':
			relay_add_item();
			break;
		    case 'd':
			relay_del_item();
			break;
		    case 'm':
			relay_mod_item();
			break;
		    case 'x':
			run_it = 0;
			break;
		}
	}
}

