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
#include <unistd.h>
#include <assert.h>

struct list l_add_policy = LIST_INIT(struct add_policy_info, next);


int conn_add_match(unsigned int src_addr, unsigned int dst_addr,
 		   unsigned short src_port, unsigned short dst_port)
{
	struct list_iterator li;
	struct add_policy_info *api;
	int retval = 0;
	
	list_lock(&l_add_policy);
	list_iter_set(&li, &l_add_policy);
	while ((api = list_iter_get(&li))) {
		if ((src_addr & api->src_mask) == api->src_addr &&
	    	    (dst_addr & api->dst_mask) == api->dst_addr &&
		    port_match(src_port, api->src_ports) &&
	    	    port_match(dst_port, api->dst_ports)) {
			retval = 1;
			break;
		}
		if ((src_addr & api->src_mask) == api->dst_addr &&
	    	    (dst_addr & api->dst_mask) == api->src_addr &&
		    port_match(src_port, api->dst_ports) &&
	    	    port_match(dst_port, api->src_ports)) {
			retval = 1;
			break;
		}
	}
	list_iter_end(&li);
	list_unlock(&l_add_policy);
	return retval;
}

int conn_add_policy(struct iphdr *iph, struct tcphdr *tcph)
{
	return conn_add_match(iph->saddr, iph->daddr, tcph->source, tcph->dest);
}

void add_telnet_rlogin_policy(void)
{
	struct add_policy_info *api;

	api = malloc(sizeof(struct add_policy_info));
	assert(api);
	memset(api, 0, sizeof(sizeof(struct add_policy_info)));
	api->src_addr = 0;
	api->src_mask = 0;
	api->dst_addr = 0;
	api->dst_mask = 0;
	api->src_ports[0] = 0;
	api->dst_ports[0] = htons(23);
	api->dst_ports[1] = htons(513);
	api->dst_ports[2] = 0;
	list_push(&l_add_policy, api);
};

static void addpolicy_item_print(int i, struct add_policy_info *api)
{
	char buf_src_ports[BUFSIZE], buf_dst_ports[BUFSIZE];
	char host_buf[BUFSIZE];
	
	sprintf_db_ports(api->src_ports, buf_src_ports, sizeof(buf_src_ports), 1);
	sprintf_db_ports(api->dst_ports, buf_dst_ports, sizeof(buf_dst_ports), 1);
	sprintf(host_buf, "%s/%d [%s]", host_lookup(api->src_addr, hl_mode),
		count_mask(api->src_mask), buf_src_ports);
	printf("%2d) %-32s <--> %s/%d [%s]\n", i,
	       host_buf,
	       host_lookup(api->dst_addr, hl_mode), count_mask(api->dst_mask),
	       buf_dst_ports);
}

void addpolicy_list_items(void)
{
	struct list_iterator li;
	struct add_policy_info *api;
	int i = 0;
	
	list_iter_set(&li, &l_add_policy);
	while ((api = list_iter_get(&li))) {
		addpolicy_item_print(i++, api);
		if (i % lines_o == 0)
			lines_o_press_key();
	}
	list_iter_end(&li);
}


void addpolicy_add_item(void)
{
	struct add_policy_info *api;
	unsigned int src_ip, dst_ip;
	unsigned int src_mask, dst_mask;
	int src_ports[MAX_PORTS + 1], dst_ports[MAX_PORTS + 1];
	int nr;


	if (menu_choose_host_mask_ports_dfl("src ip addr/mask ports", &src_ip,
				&src_mask, src_ports, 0, 0, NULL) < 0)
		return;
	if (menu_choose_host_mask_ports_dfl("dst ip addr/mask ports", &dst_ip,
				&dst_mask, dst_ports, 0, 0, NULL) < 0)
		return;
	if ((nr = menu_choose_unr("insert at", 0, list_count(&l_add_policy), list_count(&l_add_policy))) == -1)
		return;
	
	api = malloc(sizeof(struct add_policy_info));
	memset(api, 0, sizeof(struct add_policy_info));
	api->src_addr = src_ip;
	api->src_mask = src_mask;
	port_htons(src_ports);
	memcpy(api->src_ports, src_ports, sizeof(int) * (MAX_PORTS + 1));
	api->dst_addr = dst_ip;
	api->dst_mask = dst_mask;
	port_htons(dst_ports);
	memcpy(api->dst_ports, dst_ports, sizeof(int) * (MAX_PORTS + 1));
	list_lock(&l_add_policy);
	list_insert_at(&l_add_policy, nr, api);
	list_unlock(&l_add_policy);
}

void addpolicy_mod_item(void)
{
	struct add_policy_info *api;
	unsigned int src_ip, dst_ip;
	unsigned int src_mask, dst_mask;
	int src_ports[MAX_PORTS + 1], dst_ports[MAX_PORTS + 1];
	int nr;
	
	addpolicy_list_items();
	if ((nr = menu_choose_unr("choose item", 0, list_count(&l_add_policy) - 1, list_count(&l_add_policy) - 1)) == -1)
		return;
	if (!(api = list_at(&l_add_policy, nr)))
		return;
	if (menu_choose_host_mask_ports_dfl("src ip addr/mask ports",
			    &src_ip, &src_mask, src_ports,
			    api->src_addr, api->src_mask, api->src_ports) < 0)
		return;
	if (menu_choose_host_mask_ports_dfl("dst ip addr/mask ports", 
			    &dst_ip, &dst_mask, dst_ports,
			    api->dst_addr, api->dst_mask, api->dst_ports) < 0)
		return;
	port_htons(src_ports);
	port_htons(dst_ports);
	list_lock(&l_add_policy);
	api->src_addr = src_ip;
	api->src_mask = src_mask;
	memcpy(api->src_ports, src_ports, sizeof(int) * (MAX_PORTS + 1));
	api->dst_addr = dst_ip;
	api->dst_mask = dst_mask;
	memcpy(api->dst_ports, dst_ports, sizeof(int) * (MAX_PORTS + 1));
	list_unlock(&l_add_policy);
}

void addpolicy_del_item(void)
{
	int i;
	struct add_policy_info *api;
	
	addpolicy_list_items();
	i = menu_choose_unr("item nr. to delete", 0, 
			   list_count(&l_add_policy) - 1, -1);
	if (i >= 0) {
		list_lock(&l_add_policy);
		api = list_remove_at(&l_add_policy, i);
		list_unlock(&l_add_policy);
		free(api);
	}
}
