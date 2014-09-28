/*
 *
 *	This is free software. You can redistribute it and/or modify under
 *	the terms of the GNU General Public License version 2.
 *
 * 	Copyright (C) 1998 by kra
 *
 */
#include "hunt.h"
#include <sys/types.h>
#include <sys/time.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <signal.h>
#include <unistd.h>
#include <assert.h>


 
#ifndef IP_OFFMASK
#define IP_OFFMASK 0x1fff
#endif
#ifndef IP_MF
#define IP_MF	   0x2000
#endif

int linksock = -1;
int mac_learn_from_ip = 0;

int conn_list_mac = 0;
int conn_list_seq = 0;

struct hash conn_table;
struct hash mac_table;

int hunt_ready = 0;
pthread_mutex_t mutex_hunt_ready = PTHREAD_MUTEX_INITIALIZER;
pthread_cond_t cond_hunt_ready = PTHREAD_COND_INITIALIZER;

/*
 * list of struct packet_info with information which packets skip in process
 * of updating connection
 */
struct list l_skip_update = LIST_INIT(struct packet_info, next);

/*
 * lists of functions which pass packets to modules
 */
struct list l_ifunc_ip = LIST_INIT(struct ifunc_item, next_ip);
struct list l_ifunc_tcp = LIST_INIT(struct ifunc_item, next_tcp);
struct list l_ifunc_udp = LIST_INIT(struct ifunc_item, next_udp);
struct list l_ifunc_icmp = LIST_INIT(struct ifunc_item, next_icmp);
struct list l_ifunc_arp = LIST_INIT(struct ifunc_item, next_arp);
struct list l_ifunc_fast_tcp = LIST_INIT(struct ifunc_item, next_tcp);

/*
 * 
 * packet operations
 * 
 */

static struct list l_packets = LIST_INIT(struct packet, p_next_free);
int packets_allocated = 0;

struct packet *packet_new(void)
{
	struct packet *p;

	if (!(p = list_pop(&l_packets))) {
		if (!(p = malloc(sizeof(struct packet)))) {
			perror("malloc");
			return NULL;
		}
		pthread_mutex_init(&p->p_mutex, NULL);
		p->p_use_count = 0;
		p->p_hdr.p_tcph = NULL;
		p->p_data = NULL;
		p->p_type = PACKET_NONE;
		p->p_ipc = 0;
		p->p_ipc_arg = NULL;
		
		packets_allocated++;
	}
	p->p_use_count = 1;
	return p;
}

void packet_copy_data(struct packet *dst, struct packet *src)
{
	memcpy(dst->p_raw, src->p_raw, src->p_raw_len);
	dst->p_raw_len = src->p_raw_len;
	dst->p_type = src->p_type;
	dst->p_ethh = (struct ethhdr *)(dst->p_raw + 
				((char *)src->p_ethh - src->p_raw));
	dst->p_iph = (struct iphdr *)(dst->p_raw +
				((char *)src->p_iph - src->p_raw));
	dst->p_arph = (struct arphdr *)(dst->p_raw +
				((char *)src->p_arph - src->p_raw));
	dst->p_hdr.p_tcph = (struct tcphdr *)(dst->p_raw +
				((char *)src->p_hdr.p_tcph - src->p_raw));
	dst->p_data_len = src->p_data_len;
	dst->p_data = dst->p_raw + (src->p_data - src->p_raw);
	memcpy(dst->p_arg, src->p_arg, sizeof(src->p_arg));
	dst->p_ipc = src->p_ipc;
	dst->p_ipc_arg = src->p_ipc_arg;
}

void packet_free(struct packet *p)
{
	int is_free;
	
	pthread_mutex_lock(&p->p_mutex);
	if (--p->p_use_count == 0)
		is_free = 1;
	else
		is_free = 0;
	pthread_mutex_unlock(&p->p_mutex);
	if (is_free)
		list_push(&l_packets, p);
}

void packet_want(struct packet *p)
{
	pthread_mutex_lock(&p->p_mutex);
	++p->p_use_count;
	pthread_mutex_unlock(&p->p_mutex);
}

void packet_flush(struct list *l)
{
	struct packet *p;
	
	while ((p = list_pop(l)))
		packet_free(p);
}

void packet_preallocate(int count)
{
	struct packet **p = alloca(count * sizeof(struct packet *));
	int i;
	
	for (i = 0; i < count; i++)
		p[i] = packet_new();
	for (i = 0; i < count; i++)
		packet_free(p[i]);
}

int packet_count(void)
{
	return list_count(&l_packets);
}

/*
 * 
 * TCP connection database
 * 
 */
static inline void fill_uci(struct user_conn_info *uci, struct packet *p)
{
	uci->src_addr = p->p_iph->saddr;
	uci->dst_addr = p->p_iph->daddr;
	uci->src_port = p->p_hdr.p_tcph->source;
	uci->dst_port = p->p_hdr.p_tcph->dest;
}

#if 0
static int ht_eq(unsigned int key, struct conn_info *c,
		 struct packet *p)
{
	if (c->src_addr == p->p_iph->saddr && 
	    c->dst_addr == p->p_iph->daddr &&
	    c->src_port == p->p_hdr.p_tcph->source && 
	    c->dst_port == p->p_hdr.p_tcph->dest)
		return 1;
	if (c->src_addr == p->p_iph->daddr && 
	    c->dst_addr == p->p_iph->saddr &&
	    c->src_port == p->p_hdr.p_tcph->dest && 
	    c->dst_port == p->p_hdr.p_tcph->source)
		return 1;
	return 0;
}
#endif
static int ht_eq(unsigned int key, struct conn_info *c,
		 struct user_conn_info *uci)
{
	if (c->src_addr == uci->src_addr && 
	    c->dst_addr == uci->dst_addr &&
	    c->src_port == uci->src_port && 
	    c->dst_port == uci->dst_port)
		return 1;
	if (c->src_addr == uci->dst_addr && 
	    c->dst_addr == uci->src_addr &&
	    c->src_port == uci->dst_port && 
	    c->dst_port == uci->src_port)
		return 1;
	return 0;
}


void remove_conn_if_dont_match(void)
{
	struct hash_iterator hi;
	struct conn_info *ci;
	unsigned int key;
	int count_to_remove = 0;
	unsigned int *key_to_remove;
	struct conn_info **ci_to_remove;
	
	hash_lock(&conn_table);
	count_to_remove = 0;
	key_to_remove = alloca(sizeof(unsigned int) * hash_count(&conn_table));
	ci_to_remove = alloca(sizeof(struct conn_info *) * hash_count(&conn_table));
	hash_iter_set(&hi, &conn_table);
	while ((ci = hash_iter_get(&hi, &key))) {
		if (!conn_add_match(ci->src_addr, ci->dst_addr, ci->src_port, ci->dst_port)) {
			ci_to_remove[count_to_remove] = ci;
			key_to_remove[count_to_remove++] = key;
		}
	}
	hash_iter_end(&hi);
	for ( ; count_to_remove >= 0; count_to_remove--)
		hash_remove(&conn_table, key_to_remove[count_to_remove],
			    ci_to_remove[count_to_remove]);
	hash_unlock(&conn_table);
}

void conn_free(struct conn_info *ci)
{
	int free_it;
	
	pthread_mutex_lock(&ci->mutex);
	if (--ci->use_count == 0)
		free_it = 1;
	else
		free_it = 0;
	pthread_mutex_unlock(&ci->mutex);
	if (free_it)
		free(ci);
}

struct conn_info *conn_get(struct user_conn_info *uci)
{
	unsigned int key;
	struct conn_info *ci;
	
	key = uci_generate_key(uci);
	hash_lock(&conn_table);
	if ((ci = hash_get(&conn_table, key, uci))) {
		pthread_mutex_lock(&ci->mutex);
		++ci->use_count;
		pthread_mutex_unlock(&ci->mutex);
	}
	hash_unlock(&conn_table);
	return ci;
}

int conn_exist(struct user_conn_info *uci)
{
	unsigned int key;
	struct conn_info *ci;
	
	key = uci_generate_key(uci);
	if ((ci = hash_get(&conn_table, key, uci)))
		return 1;
	else
		return 0;
}

static int packet_match(struct packet_info *pi, struct packet *p)
{
	struct iphdr *iph = p->p_iph;
	struct tcphdr *tcph = p->p_hdr.p_tcph;
	
	if (pi->src_addr == iph->saddr &&
	    pi->dst_addr == iph->daddr &&
	    pi->src_port == tcph->source &&
	    pi->dst_port == tcph->dest &&
	    pi->src.next_seq == tcph->seq &&
	    pi->src.next_d_seq == tcph->ack_seq &&
	    memcmp(pi->src.src_mac, p->p_ethh->h_source, ETH_ALEN) == 0 &&
	    memcmp(pi->src.dst_mac, p->p_ethh->h_dest, ETH_ALEN) == 0)
		return 1;
	else
		return 0;
}

static int conn_skip_update(struct conn_info *ci, struct packet *p)
{
	struct list_iterator iter;
	struct packet_info *pi;
	
	list_iter_set(&iter, &l_skip_update);
	while ((pi = list_iter_get(&iter))) {
		if (packet_match(pi, p)) {
			list_iter_end(&iter);
			list_remove(&l_skip_update, pi);
			return 1;
		}
	}
	list_iter_end(&iter);
	return 0;
}

static void __conn_add(struct packet *p, unsigned int key)
{
	struct iphdr *iph = p->p_iph;
	struct tcphdr *tcph = p->p_hdr.p_tcph;
	struct conn_info *ci;
	struct host_info *h_src, *h_dst;
	
	ci = malloc(sizeof(struct conn_info));
	assert(ci);
	memset(ci, 0, sizeof(struct conn_info));
	ci->use_count = 1;
	pthread_mutex_init(&ci->mutex, NULL);
	
	if (ntohs(tcph->dest) >= 1024 && ntohs(tcph->source) < 1024) {
		ci->src_addr = iph->daddr;
		ci->dst_addr = iph->saddr;
		ci->src_port = tcph->dest;
		ci->dst_port = tcph->source;
		h_src = &ci->dst;
		h_dst = &ci->src;
	} else {
		ci->src_addr = iph->saddr;
		ci->dst_addr = iph->daddr;
		ci->src_port = tcph->source;
		ci->dst_port = tcph->dest;		
		h_src = &ci->src;
		h_dst = &ci->dst;
	}
	h_src->next_seq = htonl(ntohl(tcph->seq) + p->p_data_len +
				tcph->syn ? 1 : 0);
	if (tcph->ack)
		h_src->next_d_seq = tcph->ack_seq;
	h_src->window = tcph->window;
	h_src->id = iph->id;
	memcpy(h_src->dst_mac, p->p_ethh->h_dest, ETH_ALEN);
	memcpy(h_src->src_mac, p->p_ethh->h_source, ETH_ALEN);

	/* guess or try to fill h_dst too */
	h_dst->next_seq = h_src->next_d_seq;
	h_dst->next_d_seq = h_src->next_seq;
	h_dst->window = tcph->window;
	h_dst->id = iph->id;
	memcpy(h_dst->dst_mac, h_src->src_mac, ETH_ALEN);
	memcpy(h_dst->src_mac, h_src->dst_mac, ETH_ALEN);
	
	hash_put(&conn_table, key, ci);
	
	print_new_conn_ind(1);
}

static void ack_storm_notify(struct conn_info *ci, struct user_conn_info *uci)
{
	struct timeval tv;
	int print_it = 0;
	
	if (!ci->ack_storm_notify_sec) {
		gettimeofday(&tv, NULL);
		print_it = 1;
	} else {
		gettimeofday(&tv, NULL);
		if (tv.tv_sec - ci->ack_storm_notify_sec >= 10)
			print_it = 1;
	}
	if (print_it) {
		set_tty_color(COLOR_BRIGHTRED);
		printf("\nhunt: possible ACK storm: ");
		print_user_conn_info(uci, 1);
		set_tty_color(COLOR_LIGHTGRAY);
		ci->ack_storm_notify_sec = tv.tv_sec;
	}
}

static void conn_add_update(struct packet *p)
{
	static struct user_conn_info last_toadd = {0, 0, 0, 0};
	static int last_count = 0;
	unsigned int key;
	struct conn_info *ci;
	struct user_conn_info uci;
	unsigned int old_next_d_seq;
	
	fill_uci(&uci, p);
	key = uci_generate_key(&uci);
	
	hash_lock(&conn_table);
	if ((ci = hash_get(&conn_table, key, &uci)) && 
	    ht_eq(key, ci, &uci) == 1) {
		if (!conn_skip_update(ci, p)) {
			struct host_info *h_src, *h_dst;
			struct iphdr *iph = p->p_iph;
			struct tcphdr *tcph = p->p_hdr.p_tcph;
			
			if (ci->src_addr == iph->saddr &&
			    ci->dst_addr == iph->daddr &&
			    ci->src_port == tcph->source && 
			    ci->dst_port == tcph->dest) {
				h_src = &ci->src;
				h_dst = &ci->dst;
			} else {
				h_src = &ci->dst;
				h_dst = &ci->src;
			}
			old_next_d_seq = h_src->next_d_seq;
			
			h_src->next_seq = htonl(ntohl(tcph->seq) + 
						p->p_data_len);
			if (tcph->ack)
				h_src->next_d_seq = tcph->ack_seq;
			h_src->id = iph->id;	/* well, this should be in IP updater not in TCP */
			h_src->window = tcph->window;
			/* well these can change too :-) */
			memcpy(h_src->dst_mac, p->p_ethh->h_dest, ETH_ALEN);
			memcpy(h_src->src_mac, p->p_ethh->h_source, ETH_ALEN);
			/*
			 * ACK storm detection
			 */
			h_src->delta_d_seq += ntohl(h_src->next_d_seq) - 
						ntohl(old_next_d_seq);
			if (++ci->update_count % 400 == 0) {
				if (ci->src.delta_d_seq == 0 &&
				    ci->dst.delta_d_seq == 0) {
					ack_storm_notify(ci, &uci);
				} else {
					ci->src.delta_d_seq = 0;
					ci->dst.delta_d_seq = 0;
				}
			}
		}
	} else {
		 /* test if we could add the connection */
		if (p->p_data_len > 0) {
			/*
			 * well, it contains data - add it
			 */
			if (conn_add_policy(p->p_iph, p->p_hdr.p_tcph))
				__conn_add(p, key);
		} else {
			/*
			 * well, check it this way because we don't want
			 * to add RST, ACK to FIN, ... as connectinos.
			 */
			if ((last_toadd.src_addr == p->p_iph->saddr &&
			    last_toadd.dst_addr == p->p_iph->daddr &&
			    last_toadd.src_port == p->p_hdr.p_tcph->source &&
			    last_toadd.dst_port == p->p_hdr.p_tcph->dest) ||
			    (last_toadd.src_addr == p->p_iph->daddr &&
			    last_toadd.dst_addr == p->p_iph->saddr &&
			    last_toadd.src_port == p->p_hdr.p_tcph->dest &&
			    last_toadd.dst_port == p->p_hdr.p_tcph->source)) {
				if (++last_count >= 10) {
					last_count = 0;
					if (conn_add_policy(p->p_iph, p->p_hdr.p_tcph))
						__conn_add(p, key);
				}
			} else {
				last_count = 0;
				last_toadd.src_addr = p->p_iph->saddr;
				last_toadd.dst_addr = p->p_iph->daddr;
				last_toadd.src_port = p->p_hdr.p_tcph->source;
				last_toadd.dst_port = p->p_hdr.p_tcph->dest;
			}
		}
	}
	hash_unlock(&conn_table);
}

static void conn_del(struct packet *p)
{
	struct conn_info *ci;
	struct user_conn_info uci;
	unsigned int key;
	int remove_it = 0;
#if 0
	fill_uci(&uci, p);
	key = uci_generate_key(&uci);
	if ((ci = hash_remove(&conn_table, key, &uci))) {
		conn_free(ci);
	}
#endif
	fill_uci(&uci, p);
	key = uci_generate_key(&uci);
	hash_lock(&conn_table);
	if ((ci = hash_get(&conn_table, key, &uci)) && 
	    ht_eq(key, ci, &uci) == 1) {
		if (!conn_skip_update(ci, p)) {
			if (p->p_iph->saddr == ci->src_addr &&
			    p->p_iph->daddr == ci->dst_addr &&
			    p->p_hdr.p_tcph->source == ci->src_port &&
			    p->p_hdr.p_tcph->dest == ci->dst_port) {
				/* from source to dest */
			    	if (p->p_hdr.p_tcph->seq == ci->dst.next_d_seq)
					remove_it = 1;
			} else {
				/* from dest to source */
				if (p->p_hdr.p_tcph->seq == ci->src.next_d_seq)
					remove_it = 1;
			}
		}
	}
	if (remove_it) {
		if (ci == hash_remove(&conn_table, key, &uci))
			conn_free(ci);
		hash_unlock(&conn_table);
	} else {
		hash_unlock(&conn_table);
		conn_add_update(p);
	}
}

static void conn_add(struct packet *p)
{
	struct conn_info *ci;
	struct user_conn_info uci;
	unsigned int key;

	fill_uci(&uci, p);
	key = uci_generate_key(&uci);
	hash_lock(&conn_table);
	if ((ci = hash_get(&conn_table, key, &uci)) && 
	    ht_eq(key, ci, &uci) == 1) {
		conn_add_update(p);
#if 0
			ci = hash_remove(&conn_table, key, &uci);
			hash_unlock(&conn_table);
			conn_free(ci);
			hash_lock(&conn_table);
#endif
	} else {
		__conn_add(p, key);
	}
	hash_unlock(&conn_table);
}

static void conn_update_table(struct packet *p, struct ethhdr *ethh, struct iphdr *iph)
{
	struct tcphdr *tcph = p->p_hdr.p_tcph;

	if (tcph->syn && !tcph->ack) {
		if (conn_add_policy(iph, tcph)) {
			conn_add(p);
		}
	} else if (tcph->rst || tcph->fin) {
		#if 0
		if (conn_add_policy(iph, tcph))
		#endif
			conn_del(p);
	} else {
		#if 0
		if (conn_add_policy(iph, tcph))
		#endif
			conn_add_update(p);
	}
}

/*
 * 
 * function lists
 * 
 */
static void process_tcp(struct packet *p)
{
	struct ifunc_item *li;
	struct list_iterator iter;
	
	list_iter_set(&iter, &l_ifunc_tcp);
	while ((li = list_iter_get(&iter)))
		li->func(p, li->arg);
	list_iter_end(&iter);
}

static void process_udp(struct packet *p)
{
	struct ifunc_item *li;
	struct list_iterator iter;
	
	list_iter_set(&iter, &l_ifunc_udp);
	while ((li = list_iter_get(&iter)))
		li->func(p, li->arg);
	list_iter_end(&iter);
}

static void process_icmp(struct packet *p)
{
	struct ifunc_item *li;
	struct list_iterator iter;
	
	list_iter_set(&iter, &l_ifunc_icmp);
	while ((li = list_iter_get(&iter)))
		li->func(p, li->arg);
	list_iter_end(&iter);
}

static void process_arp(struct packet *p)
{
	struct ifunc_item *li;
	struct list_iterator iter;

	list_iter_set(&iter, &l_ifunc_arp);
	while ((li = list_iter_get(&iter)))
		li->func(p, li->arg);
	list_iter_end(&iter);
}

static void process_ip(struct packet *p)
{
	struct ifunc_item *li;
	struct list_iterator iter;

	list_iter_set(&iter, &l_ifunc_ip);
	while ((li = list_iter_get(&iter)))
		li->func(p, li->arg);
	list_iter_end(&iter);
}

/*
 * sample of ifunc
 */
#if 0
struct list m_packet_list = LIST_INIT(struct packet, p_next[MODULE_NR]);

void m_func_tcp(struct packet *p)
{
	if (want_it) {
		packet_want(p);
		list_produce(&m_packet_list, p);
	}
}
#endif

static inline void fast_tcp_process(struct packet *p)
{
	struct list_iterator iter;
	struct ifunc_item *li;
	
	list_lock(&l_ifunc_fast_tcp);
	list_iter_set(&iter, &l_ifunc_fast_tcp);
	while ((li = list_iter_get(&iter)))
		li->func(p, li->arg);
	list_iter_end(&iter);
	list_unlock(&l_ifunc_fast_tcp);
}

static void mac_table_update(unsigned int ip, char *mac)
{
	struct mac_info *mi;
	
	hash_lock(&mac_table);
	if ((mi = hash_get(&mac_table, ip, NULL))) {
		if (memcmp(mi->mac, mac, sizeof(mi->mac))) {
			pthread_mutex_lock(&mi->mutex);
			memcpy(mi->mac, mac, sizeof(mi->mac));
			pthread_mutex_unlock(&mi->mutex);
		}
	} else {
		mi = malloc(sizeof(struct mac_info));
		assert(mi);
		memcpy(mi->mac, mac, sizeof(mi->mac));
		pthread_mutex_init(&mi->mutex, NULL);
		hash_put(&mac_table, ip, mi);
	}
	hash_unlock(&mac_table);
}

struct mac_info *mac_info_get(unsigned int ip)
{
	struct mac_info *mi;
	
	hash_lock(&mac_table);
	if ((mi = hash_get(&mac_table, ip, NULL))) {
		pthread_mutex_lock(&mi->mutex);
	}
	hash_unlock(&mac_table);
	return mi;
}

void mac_info_release(struct mac_info *mi)
{
	pthread_mutex_unlock(&mi->mutex);
}

static void mac_arp_learn(struct packet *p)
{
	unsigned int ip;
	char *mac;
	struct arpeth_hdr *arpethh;

	arpethh = (struct arpeth_hdr *)(p->p_arph + 1);
	
	if (p->p_arph->ar_op == htons(ARPOP_REPLY) ||
	    p->p_arph->ar_op == htons(ARPOP_REQUEST)) {
		ip = *(unsigned int *) arpethh->ar_sip;
		mac = arpethh->ar_sha;
		if (memcmp(mac, p->p_ethh->h_source, ETH_ALEN) == 0)
			mac_table_update(ip, mac);
		else
			fprintf(stderr, "ARP: MAC src != ARP src for host %s\n", host_lookup(ip, hl_mode));
	}
}

static void mac_ip_learn(struct packet *p)
{
	unsigned int ip;
	char *mac;
	
	ip = p->p_iph->saddr;
	mac = p->p_ethh->h_source;
	mac_table_update(ip, mac);
	/*
	 * well, don't learn mac addresses from dst as they can be spoofed
	 * (even though check can be made)
	 */
}

/*
 * 
 * hunt
 * 
 */
unsigned int pkts_received = 0;
unsigned int pkts_dropped = 0;
unsigned int pkts_unhandled = 0;
unsigned int bytes_received = 0;

void *hunt(void *arg)
{
	struct packet *p;
	struct ethhdr *ethh;
	struct iphdr *iph;
#ifdef WITH_RECVMSG
	struct msghdr msg;
	struct sockaddr_pkt spkt;
	struct iovec iov;
#endif
	pthread_sigmask(SIG_BLOCK, &intr_mask, NULL);
	
	if (verbose)
		printf("hunt pid %d\n", getpid());
	add_telnet_rlogin_policy();
	if (hash_init(&conn_table, 100, (hash_equal_func)ht_eq)) { /* Initialize hash table of connections */
		perror("hash_init");
		exit(1);
	}
	if (hash_init(&mac_table, 100, NULL)) {
		perror("hash init");
		exit(1);
	}
	linksock = tap(eth_device, 1);                /* Setup link socket */ 
	if (linksock < 0) {
		perror("linksock");
		exit(1);
	}
	packet_preallocate(64);
	
	printf("starting hunt\n");
	setpriority(PRIO_PROCESS, getpid(), -20);
	pthread_mutex_lock(&mutex_hunt_ready);
	hunt_ready = 1;
	pthread_cond_signal(&cond_hunt_ready);
	pthread_mutex_unlock(&mutex_hunt_ready);
	while(1) {
		if (!(p = packet_new())) {
			fprintf(stderr, "can't get free packet - out of memory\n");
			exit(1);
		}
#ifdef WITH_RECVMSG
		memset(&msg, 0, sizeof(msg));
		msg.msg_name = &spkt;
		msg.msg_namelen = sizeof(spkt);
		msg.msg_iovlen = 1;
		msg.msg_iov = &iov;
		iov.iov_base = p->p_raw;
		iov.iov_len = sizeof(p->p_raw);
		if ((p->p_raw_len = recvmsg(linksock, &msg, 0)) >= 0)
#else
		if ((p->p_raw_len = recv(linksock, p->p_raw, sizeof(p->p_raw), 0)) > 0)
#endif
		{
			pkts_received++;
			bytes_received += p->p_raw_len;
			/*
			 * don't do continue or break without packet_free !!
			 */
			if (p->p_raw_len < 14) {
				pkts_dropped++;
				goto cont;
			}
			ALIGNPOINTERS_ETH(p, ethh);
			p->p_ethh = ethh;
			/* 
			 * in order to speed thinks as mutch as posible for arp stuff 
			 * the timestamp is moved to swtich p->p_timestamp = time(NULL);
			 */
			p->p_timestamp = 0;
			switch (ntohs(ethh->h_proto)) {
			    case ETH_P_IP:
				p->p_timestamp = time(NULL);
				if (p->p_raw_len < 14 + 20) {
					pkts_dropped++;
					goto cont;
				}
				ALIGNPOINTERS_IP(ethh, iph);
				p->p_iph = iph;
			        if (in_cksum((unsigned short *) iph,
					     IP_HDR_LENGTH(iph)) == 0) {
				if (mac_learn_from_ip)
					mac_ip_learn(p);
				process_ip(p);
				/* drop IP fragments and ip packet len > p_raw_len */
				if ((ntohs(iph->frag_off) & IP_OFFMASK) != 0 ||
				    (ntohs(iph->frag_off) & IP_MF) ||
				    (IP_HDR_LENGTH(iph) + IP_DATA_LENGTH(iph)) > p->p_raw_len) {
					pkts_dropped++;
					goto cont;
				}
				switch (iph->protocol) {
				    case IPPROTO_TCP:
					if (p->p_raw_len < 14 + IP_HDR_LENGTH(iph) + 20) {
						pkts_dropped++;
						goto cont;
					}
					p->p_type = PACKET_TCP;
					ALIGNPOINTERS_TCP(iph, p->p_hdr.p_tcph,
							  p->p_data);
					p->p_data_len = TCP_DATA_LENGTH(iph, p->p_hdr.p_tcph);
					if (ip_in_cksum(iph, (unsigned short *) p->p_hdr.p_tcph,
					    IP_DATA_LENGTH(iph)) == 0) {
						conn_update_table(p, ethh, iph);
						fast_tcp_process(p);
						process_tcp(p);
					} else
						pkts_dropped++;
					break;
				    case IPPROTO_UDP:
					if (p->p_raw_len < 14 + IP_HDR_LENGTH(iph) + 8) {
						pkts_dropped++;
						goto cont;
					}
					p->p_type = PACKET_UDP;
					ALIGNPOINTERS_UDP(iph, p->p_hdr.p_udph, 
							  p->p_data);
					/* check the UDP checksum */
					process_udp(p);
					break;
				    case IPPROTO_ICMP:
					if (p->p_raw_len < 14 + IP_HDR_LENGTH(iph) + 8) {
						pkts_dropped++;
						goto cont;
					}
					p->p_type = PACKET_ICMP;
					ALIGNPOINTERS_ICMP(iph, p->p_hdr.p_icmph,
							   p->p_data);
					if (in_cksum((unsigned short *) p->p_hdr.p_icmph,
					    IP_DATA_LENGTH(iph)) == 0) {
						process_icmp(p);
					} else
						pkts_dropped++;
					break;
				    default:
					pkts_unhandled++;
					break;
				}
				} else
					pkts_dropped++; /* bad IP checksum */
				break;
			    case ETH_P_ARP:
				if (p->p_raw_len < 14 + 28) {
					pkts_dropped++;
					goto cont;
				}
				p->p_type = PACKET_ARP;
				ALIGNPOINTERS_ARP(ethh, p->p_arph);
				/* do process arp first - in order to do it as fast 
				   as posible arpspoof needs it */
				process_arp(p);
				p->p_timestamp = time(NULL); /* well, the process_arp does not get timestamp */
				mac_arp_learn(p);
				break;
			    default:
				pkts_unhandled++;
				break;
			}
		}
cont:
		packet_free(p);
	}
	return NULL;
}

/*
 * 
 * helper functions
 * 
 */
void print_tcp(struct packet *p, struct iphdr *ip, struct tcphdr *tcp)
{
       fprintf(stdout, "%s [%d] seq=(%u) ack=(%u)\t--->\t%s [%d] len=%d/%d\n",
	       host_lookup(ip->saddr, hl_mode), ntohs(tcp->source), 
	       (unsigned int) ntohl(tcp->seq), tcp->ack ? (unsigned int) ntohl(tcp->ack_seq) : 0,
	       host_lookup(ip->daddr, hl_mode), ntohs(tcp->dest), p->p_raw_len, p->p_data_len);
}

static int fill_space_to(char *b, int pos, int where)
{
	if (pos >= 0 && pos < where) {
		return sprintf(b, "%*s", where - pos, "");
	} else
		return 0;
}

int conn_list(struct user_conn_info **ruci, char **rbuf, int with_mac, int with_seq)
{
	struct hash_iterator iter;
	struct conn_info *ci;
	struct user_conn_info *uci;
	int i, count;
	char *b, *b_old, *buf;

	hash_lock(&conn_table);
	count = hash_count(&conn_table);
	if (!count) {
		hash_unlock(&conn_table);
		if (ruci)
			*ruci = NULL;
		if (rbuf)
			*rbuf = NULL;
		return 0;
	}
	if (rbuf) {
		buf = malloc(count * 512);
		assert(buf);
		b = buf;
	} else
		b = buf = NULL;
	if (ruci) {
		uci = malloc(count * sizeof(struct user_conn_info));
		assert(uci);
	} else
		uci = NULL;
	i = 0;
	hash_iter_set(&iter, &conn_table);
	while ((ci = hash_iter_get(&iter, NULL)) && i < count) {
		if (b) {
			b_old = b;
			b += sprintf(b, "%d) %s [%s]", i,
			       	     host_lookup(ci->src_addr, hl_mode),
				     port_lookup(ci->src_port, hl_mode));
			b += fill_space_to(b, b - b_old, 30);
			b += sprintf(b, " --> ");
			b += sprintf(b, "%s [%s]\n",
			             host_lookup(ci->dst_addr, hl_mode),
				     port_lookup(ci->dst_port, hl_mode));
			if (with_seq) {
				b_old = b;
				b += sprintf(b, "     seq=(%u) ack=(%u)",
					(unsigned int) ntohl(ci->src.next_seq), (unsigned int) ntohl(ci->src.next_d_seq));
				b += fill_space_to(b, b - b_old, 45);
				b += sprintf(b, " seq=(%u) ack=(%u)\n",
					(unsigned int) ntohl(ci->dst.next_seq), (unsigned int) ntohl(ci->dst.next_d_seq));
			}
			if (with_mac) {
				b_old = b;
				b += sprintf(b, "     src mac=");
				b += sprintf_eth_mac(b, ci->src.src_mac);
				b += fill_space_to(b, b - b_old, 45);
				b += sprintf(b, " src mac=");
				b += sprintf_eth_mac(b, ci->dst.src_mac);
				b += sprintf(b, "\n");
				
				b_old = b;
				b += sprintf(b, "     dst mac=");
				b += sprintf_eth_mac(b, ci->src.dst_mac);
				b += fill_space_to(b, b - b_old, 45);
				b += sprintf(b, " dst mac=");
				b += sprintf_eth_mac(b, ci->dst.dst_mac);
				b += sprintf(b, "\n");
			}
		}
		if (uci) {
			uci[i].src_addr = ci->src_addr;
			uci[i].dst_addr = ci->dst_addr;
			uci[i].src_port = ci->src_port;
			uci[i].dst_port = ci->dst_port;
		}
		i++;
	}
	hash_iter_end(&iter);
	hash_unlock(&conn_table);
	
	if (ruci)
		*ruci = uci;
	if (rbuf)
		*rbuf = buf;
	return count;
}

void print_mac_table(void)
{
	struct hash_iterator hi;
	char buf[BUFSIZE];
	unsigned int key;
	struct mac_info *mi;
	int i = 0;
	
	printf("--- mac table ---\n");
	hash_iter_set(&hi, &mac_table);
	while ((mi = hash_iter_get(&hi, &key))) {
		sprintf_eth_mac(buf, mi->mac);
		printf("%-24s %s\n", host_lookup(key, hl_mode), buf);
		if (++i % lines_o == 0)
			lines_o_press_key();
	}
	hash_iter_end(&hi);
}

void print_user_conn_info(struct user_conn_info *uci, int count)
{
	int i, ret;
	
	for (i = 0; i < count; i++) {
		ret = printf("%d) %s [%s]", i,
		       	     host_lookup(uci->src_addr, hl_mode),
			     port_lookup(uci->src_port, hl_mode));
		printf("%*s", 25 - ret > 0 ? 20 - ret : 0, "");
		printf(" --> ");
		printf("%s [%s]\n", 
		       host_lookup(uci->dst_addr, hl_mode),
		       port_lookup(uci->dst_port, hl_mode));
	}
}
