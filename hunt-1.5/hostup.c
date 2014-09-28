/*
 *
 *	This is free software. You can redistribute it and/or modify under
 *	the terms of the GNU General Public License version 2.
 *
 * 	Copyright (C) 1998 by kra
 *
 */
#include "hunt.h"
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <stdio.h>

/*
 * 
 * the icmp and arp processes cannot run in parallel - we
 * are using the same MODULE_HOSTUP for linking the packets
 * 
 */
static struct list l_icmp_packet = LIST_INIT(struct packet, p_next[MODULE_HOSTUP]);
static struct list l_arp_packet = LIST_INIT(struct packet, p_next[MODULE_HOSTUP]);

struct host_up_info {
	unsigned int start_addr;
	unsigned int end_addr;
	int *up_ping;
	int *promisc_ping;
	int *up_arp;
	int *promisc_arp;
	unsigned int up_len;
};


static void func_icmp_packet(struct packet *p, void *arg)
{
	struct iphdr *iph = p->p_iph;
	struct icmphdr *icmph = p->p_hdr.p_icmph;
	struct host_up_info *hui = (struct host_up_info *) arg;
	
	if (ntohl(iph->saddr) >= ntohl(hui->start_addr) && 
	    ntohl(iph->saddr) <= ntohl(hui->end_addr) &&
	    icmph->type == 0 && icmph->code == 0) {
		packet_want(p);
		list_produce(&l_icmp_packet, p);
	}
}

static void func_arp_packet(struct packet *p, void *arg)
{
	struct host_up_info *hui = (struct host_up_info *) arg;
	struct arpeth_hdr *arpethh; 
	unsigned int ip;
	
	arpethh  = (struct arpeth_hdr *)(p->p_arph + 1);
	ip = *(unsigned int *) arpethh->ar_sip;

	if (p->p_arph->ar_op == htons(ARPOP_REPLY) &&
	    ntohl(ip) >= ntohl(hui->start_addr) &&
	    ntohl(ip) <= ntohl(hui->end_addr)) {
		packet_want(p);
		list_produce(&l_arp_packet, p);
	}
}

static void perform_ping(struct host_up_info *hui, int count, int *up, unsigned char *fake_mac)
{
	struct mac_info *m;
	struct packet *p;
	struct timeval tv;
	struct timespec timeout;
	unsigned int ip, src_addr;
	unsigned int idx;
	int j;
	
	printf("ping");
	fflush(stdout);
	for (j = 1; j <= count; j++) {
		for (ip = hui->start_addr; 
		     ntohl(ip) <= ntohl(hui->end_addr); 
		     ip = htonl(ntohl(ip) + 1)) {
			idx = ntohl(ip) - ntohl(hui->start_addr);
			if (!up[idx]) {
				if (!fake_mac) {
					if ((m = mac_info_get(ip))) {
						send_icmp_request(my_eth_ip, 
							  ip, my_eth_mac,
							  m->mac, htons(j + 2000));
						mac_info_release(m);
					}
				} else {
					send_icmp_request(my_eth_ip, ip, 
						my_eth_mac, fake_mac, htons(j + 2000));
				}
			}
		}
		/* listen some time for reply */
		gettimeofday(&tv, NULL);
		timeout.tv_sec = tv.tv_sec + 2;
		timeout.tv_nsec = tv.tv_usec * 1000;
		while ((p = list_consume(&l_icmp_packet, &timeout))) {
			/* src addr is in the range start_addr .. end_addr -
			   look to func_icmp_packet */
			src_addr = p->p_iph->saddr;
			if (is_icmp_reply(p, src_addr, my_eth_ip,
					  p->p_ethh->h_source, my_eth_mac) ||
			    (fake_mac && is_icmp_reply(p, src_addr, my_eth_ip,
					  fake_mac, my_eth_mac))) {
				idx = ntohl(src_addr) - ntohl(hui->start_addr);
				up[idx] = 1;
				host_lookup(src_addr, HL_MODE_DEFERRED);
			}
			packet_free(p);
		}
		printf(".");
		fflush(stdout);
	}
	printf("\n");
}

static void send_arp_message(unsigned int ip, char *dst_mac)
{
	struct arp_spec as;
	
	as.src_mac = my_eth_mac;
	as.dst_mac = dst_mac;
	as.oper = htons(ARPOP_REQUEST);
	as.sender_mac = my_eth_mac;
	as.sender_addr = my_eth_ip;
	as.target_mac = mac_zero;
	as.target_addr = ip;
	
	send_arp_packet(&as);
}

/*
 * it will be good idea to turn off the mac discoverer daemon
 */
static void perform_arp(struct host_up_info *hui, int count, int *up, unsigned char *fake_mac)
{
	int j, idx;
	unsigned int ip, src_addr;
	struct arpeth_hdr *arpethh;
	struct timeval tv;
	struct timespec timeout;
	struct packet *p;
	
	printf("arp");
	fflush(stdout);
	for (j = 1; j <= count; j++) {
		for (ip = hui->start_addr;
		     ntohl(ip) <= ntohl(hui->end_addr);
		     ip = htonl(ntohl(ip) + 1)) {
			idx = ntohl(ip) - ntohl(hui->start_addr);
			if (!up[idx]) {
				if (!fake_mac)
					send_arp_message(ip, mac_broadcast);
				else
					send_arp_message(ip, fake_mac);
			}
		}
		/* listen some time for reply */
		gettimeofday(&tv, NULL);
		timeout.tv_sec = tv.tv_sec + 2;
		timeout.tv_nsec = tv.tv_usec * 1000;
		
		/* the received packets are ARP_REPLY - and from expected range 
		   from func_arp_packet */
		while ((p = list_consume(&l_arp_packet, &timeout))) {
			arpethh = (struct arpeth_hdr *)(p->p_arph + 1);
			src_addr = *(unsigned int *) arpethh->ar_sip;
			if (memcmp(arpethh->ar_sha, p->p_ethh->h_source, ETH_ALEN) == 0 &&
			    memcmp(my_eth_mac, p->p_ethh->h_dest, ETH_ALEN) == 0 &&
			    memcmp(my_eth_mac, arpethh->ar_tha, ETH_ALEN) == 0 &&
			    *(unsigned int *) arpethh->ar_tip == my_eth_ip
			    ) { /* sanity check that it was triggered by as */
				idx = ntohl(src_addr) - ntohl(hui->start_addr);
				up[idx] = 1;
				host_lookup(src_addr, HL_MODE_DEFERRED);
			}
			packet_free(p);
		}
		printf(".");
		fflush(stdout);
	}
	printf("\n");
}

static void list_host_up(struct host_up_info *hui, int *up)
{
	unsigned int addr, idx;
	
	for (addr = hui->start_addr; 
	     ntohl(addr) <= ntohl(hui->end_addr);
	     addr = htonl(ntohl(addr) + 1)) {
		idx = ntohl(addr) - ntohl(hui->start_addr);
		if ((up && up[idx]) || 
		    (!up && (hui->up_ping[idx] || hui->up_arp[idx]))) {
			printf("UP  %s\n", host_lookup(addr, HL_MODE_DEFERRED));
		}
	}
}

static void list_host_promisc(struct host_up_info *hui, int *promisc)
{
	unsigned int addr, idx;
	
	for (addr = hui->start_addr; 
	     ntohl(addr) <= ntohl(hui->end_addr);
	     addr = htonl(ntohl(addr) + 1)) {
		idx = ntohl(addr) - ntohl(hui->start_addr);
		if ((promisc && promisc[idx]) ||
		    (!promisc && (hui->promisc_ping[idx] || hui->promisc_arp[idx]))) {
			printf("in PROMISC MODE  %s\n",
			       host_lookup(addr, HL_MODE_DEFERRED));
		}
	}
}

void host_up(void)
{
	static unsigned int start_ip_def = 0, end_ip_def = 0;
	unsigned int start_ip, end_ip;
	struct ifunc_item ifunc_icmp;
	struct ifunc_item ifunc_arp;
	struct host_up_info *hui;
	struct timespec ts;
	unsigned int len;
	unsigned char buf_mac[BUFSIZE], fake_mac[ETH_ALEN];
	
	if ((start_ip = menu_choose_hostname("start ip addr", host_lookup(start_ip_def, HL_MODE_NR))) == -1)
		return;
	if ((end_ip = menu_choose_hostname("end ip addr", host_lookup(end_ip_def, HL_MODE_NR))) == -1)
		return;
	if ((len = ntohl(end_ip) - ntohl(start_ip) + 1) < 0) {
		printf("bad addresses\n");
		return;
	}
	start_ip_def = start_ip;
	end_ip_def = end_ip;
	
	hui = malloc(sizeof(struct host_up_info));
	hui->start_addr = start_ip;
	hui->end_addr = end_ip;
	hui->up_ping = malloc(sizeof(int) * len);
	hui->promisc_ping = malloc(sizeof(int) * len);
	hui->up_arp = malloc(sizeof(int) * len);
	hui->promisc_arp = malloc(sizeof(int) * len);
	hui->up_len = len;
	memset(hui->up_ping, 0, sizeof(int) * len);
	memset(hui->promisc_ping, 0, sizeof(int) * len);
	memset(hui->up_arp, 0, sizeof(int) * len);
	memset(hui->promisc_arp, 0, sizeof(int) * len);

	switch (menu_choose_char("host up test (arp method) y/n", "yn", 'y')) {
	    case 'y':
		ifunc_arp.func = func_arp_packet;
		ifunc_arp.arg = hui;
		list_enqueue(&l_ifunc_arp, &ifunc_arp);
		perform_arp(hui, 3, hui->up_arp, NULL);
		list_remove(&l_ifunc_arp, &ifunc_arp);
		packet_flush(&l_arp_packet);
	
		list_host_up(hui, hui->up_arp);
		break;
	}
	switch (menu_choose_char("host up test (ping method) y/n", "yn", 'y')) {
	    case 'y':
		printf("mac discovery\n");
		mac_discover_range(hui->start_addr, hui->end_addr, 2);
		ts.tv_sec = 1;
		ts.tv_nsec = 0;
		nanosleep(&ts, NULL);
	
		ifunc_icmp.func = func_icmp_packet;
		ifunc_icmp.arg = hui;
		list_enqueue(&l_ifunc_icmp, &ifunc_icmp);
		perform_ping(hui, 3, hui->up_ping, NULL);
		list_remove(&l_ifunc_icmp, &ifunc_icmp);
		packet_flush(&l_icmp_packet);
	
		list_host_up(hui, hui->up_ping);
		break;
	}
	switch (menu_choose_char("net ifc promisc test (arp method) y/n", "yn", 'y')) {
	    case 'y':
		sprintf_eth_mac(buf_mac, suggest_mac());
		if (menu_choose_mac("choose unused MAC in your network", fake_mac, buf_mac) >= 0) {
			ifunc_arp.func = func_arp_packet;
			ifunc_arp.arg = hui;
			list_enqueue(&l_ifunc_arp, &ifunc_arp);
			perform_arp(hui, 3, hui->promisc_arp, fake_mac);
			list_remove(&l_ifunc_arp, &ifunc_arp);
			packet_flush(&l_arp_packet);
			
			list_host_promisc(hui, hui->promisc_arp);
		}
		break;
	}
	switch (menu_choose_char("net ifc promisc test (ping method) y/n", "yn", 'y')) {
	    case 'y':
		sprintf_eth_mac(buf_mac, suggest_mac());
		if (menu_choose_mac("choose unused MAC in your network", fake_mac, buf_mac) >= 0) {
			ifunc_icmp.func = func_icmp_packet;
			ifunc_icmp.arg = hui;
			list_enqueue(&l_ifunc_icmp, &ifunc_icmp);
			perform_ping(hui, 3, hui->promisc_ping, fake_mac);
			list_remove(&l_ifunc_icmp, &ifunc_icmp);
			packet_flush(&l_icmp_packet);
			
			list_host_promisc(hui, hui->promisc_ping);
		}
		break;
	}
	free(hui->up_ping);
	free(hui->promisc_ping);
	free(hui->up_arp);
	free(hui->promisc_arp);
	free(hui);
}

