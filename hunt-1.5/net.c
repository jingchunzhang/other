/*
 *
 *	This is free software. You can redistribute it and/or modify under
 *	the terms of the GNU General Public License version 2.
 *
 * 	Copyright (C) 1998 by kra
 *
 */
#include "hunt.h"
#include <sys/uio.h>
#include <stdio.h>
#include <unistd.h>
#include <string.h>
#include <assert.h>
#include <errno.h>

int Sendmsg(int s, const struct msghdr *msg, unsigned int flags)
{
	int retval;
	int retry_count = 0;
	struct timespec ts;
	
retry:
	retval = sendmsg(s, msg, flags);
	if (retval < 0 && errno == ENOBUFS && retry_count < 5) {
		ts.tv_sec = 0;
		ts.tv_nsec = 10000000; /* 0.01s */
		nanosleep(&ts, NULL);
		retry_count++;
		goto retry;
	}
	if (retval < 0)
		fprintf(stderr, "sendmsg retval = %d errno = %d\n", retval, errno);
	return retval;
}

int send_tcp_packet(struct tcp_spec *ts)
{
	int tot_len, retval;
	char buf[2048], *data;
	struct ethhdr *eth;
	struct iphdr *ip;
	struct tcphdr *tcp;
	struct msghdr msg;
	struct sockaddr spkt;
	struct iovec iov;
	
	eth = (struct ethhdr *) buf;
	memcpy(eth->h_dest, ts->dst_mac, ETH_ALEN);
	memcpy(eth->h_source, ts->src_mac, ETH_ALEN);
	eth->h_proto = htons(ETH_P_IP);
	
	ip = (struct iphdr *) (eth + 1);
	tcp = (struct tcphdr *) (ip + 1);
	data = (char *) (tcp + 1);
	memset(ip, 0, sizeof(struct iphdr));
	memset(tcp, 0, sizeof(struct tcphdr));
	memcpy(data, ts->data, ts->data_len);
	tcp->dest = ts->dport;
	tcp->source = ts->sport;
	tcp->doff = 5;
	tcp->psh = ts->psh;
	tcp->ack = ts->ack;
	tcp->rst = ts->rst;
	tcp->window = ts->window;
	ip->version = 4;
	ip->ihl = 5;
	tot_len = IPHDR + TCPHDR + ts->data_len;
	ip->tot_len = htons(tot_len);   	    /* 16-bit Total length */
    	ip->ttl = 64;                	    /* 8-bit Time To Live */
    	ip->protocol = IPPROTO_TCP;  	    /* 8-bit Protocol */
	ip->frag_off = htons(IP_DF);
    	ip->saddr = ts->saddr;     	    /* 32-bit Source Address */
    	ip->daddr = ts->daddr;     	    /* 32-bit Destination Address */
	ip->id = ts->id;
	ip->check = 0;
	ip->check = in_cksum((unsigned short *)ip, IPHDR);
	tcp->seq = ts->seq;
	if (ts->ack)
		tcp->ack_seq = ts->ack_seq;
	tcp->check = 0;
	tcp->check = ip_in_cksum(ip, (unsigned short *) tcp,
				      sizeof(struct tcphdr) + ts->data_len);
	memset(&spkt, 0, sizeof(spkt));
	strncpy(spkt.sa_data, eth_device, sizeof(spkt.sa_data));
	
	memset(&msg, 0, sizeof(msg));
	msg.msg_name = &spkt;
	msg.msg_namelen = sizeof(spkt);
	msg.msg_iovlen = 1;
	msg.msg_iov = &iov;
	iov.iov_base = buf;
	iov.iov_len = sizeof(struct ethhdr) + tot_len;

	retval = Sendmsg(linksock, &msg, 0);
	return retval;
}

int send_icmp_packet(struct icmp_spec *is)
{
	int tot_len, retval;
	char buf[2048], *data;
	struct ethhdr *eth;
	struct iphdr *ip;
	struct icmphdr *icmp;
	struct msghdr msg;
	struct sockaddr spkt;
	struct iovec iov;
	int data_len;
	
	eth = (struct ethhdr *) buf;
	memcpy(eth->h_dest, is->dst_mac, ETH_ALEN);
	memcpy(eth->h_source, is->src_mac, ETH_ALEN);
	eth->h_proto = htons(ETH_P_IP);
	
	ip = (struct iphdr *) (eth + 1);
	icmp = (struct icmphdr *) (ip + 1);
	data = (char *) (icmp + 1);
	memset(ip, 0, sizeof(struct iphdr));
	memset(icmp, 0, sizeof(struct icmphdr));
	if (!is->data_len) {
		memset(data, 0, 64);
		data_len = 64;
	} else {
		memcpy(data, is->data, is->data_len);
		data_len = is->data_len;
	}
	ip->version = 4;
	ip->ihl = 5;
	tot_len = IPHDR + sizeof(struct icmphdr) + data_len;
	ip->tot_len = htons(tot_len);
	ip->ttl = 64;
	ip->protocol = IPPROTO_ICMP;
	ip->saddr = is->src_addr;
	ip->daddr = is->dst_addr;
	ip->frag_off = htons(IP_DF);
	ip->id = 0;
	ip->check = 0;
	ip->check = in_cksum((unsigned short *)ip, IPHDR);

	assert(sizeof(struct icmphdr) == 8);
	icmp->type = is->type;
	icmp->code = is->code;
	icmp->un.gateway = is->un.res ;

	icmp->checksum = 0;
	icmp->checksum = in_cksum((unsigned short *)icmp, 
				  sizeof(struct icmphdr) + data_len);

	memset(&spkt, 0, sizeof(spkt));
	strncpy(spkt.sa_data, eth_device, sizeof(spkt.sa_data));
	
	memset(&msg, 0, sizeof(msg));
	msg.msg_name = &spkt;
	msg.msg_namelen = sizeof(spkt);
	msg.msg_iovlen = 1;
	msg.msg_iov = &iov;
	iov.iov_base = buf;
	iov.iov_len = sizeof(struct ethhdr) + tot_len;
	retval = Sendmsg(linksock, &msg, 0);
	return retval;
}

void send_icmp_request(unsigned int src_addr, unsigned int dst_addr,
		       char *src_mac, char *dst_mac, unsigned short seq)
{
	struct icmp_spec icmp;
	
	icmp.src_addr = src_addr;
	icmp.dst_addr = dst_addr;
	icmp.src_mac = src_mac;
	icmp.dst_mac = dst_mac;
	icmp.type = 8;
	icmp.code = 0;
	icmp.un.idseq.id = htons(0xAA);
	icmp.un.idseq.seq = seq;
	icmp.data = NULL;
	icmp.data_len = 0;
	
	send_icmp_packet(&icmp);
}

int is_icmp_reply(struct packet *p, unsigned int src_addr, unsigned int dst_addr,
		  char *src_mac, char *dst_mac)
{
	struct iphdr *iph = p->p_iph;
	struct icmphdr *icmph = p->p_hdr.p_icmph;
	struct ethhdr *ethh = p->p_ethh;
	unsigned short seq, id;
	
	if (iph->saddr == src_addr &&
	    iph->daddr == dst_addr &&
	    icmph->type == 0 && icmph->code == 0) {
		seq = (icmph->un.gateway & 0xFFFF0000) >> 16;
		id = icmph->un.gateway & 0xFFFF;
#if 1
		if (id != htons(0xAA))
			return 0;
#endif
		if (memcmp(ethh->h_dest, dst_mac, ETH_ALEN) == 0 &&
		    memcmp(ethh->h_source, src_mac, ETH_ALEN) == 0)
			return 1;
		else
			return 2;
	}
	return 0;
}

int send_arp_packet(struct arp_spec *as)
{
	char buf[512];
	int retval, data_len;
	struct msghdr msg;
	struct iovec  iov;
	struct ethhdr *eth;
	struct arphdr *arp;
	struct arpeth_hdr *arpeth;
	
	struct sockaddr spkt;

	eth = (struct ethhdr *) buf;
	memcpy(eth->h_dest, as->dst_mac, ETH_ALEN);
	memcpy(eth->h_source, as->src_mac, ETH_ALEN);
	eth->h_proto = htons(ETH_P_ARP);

	arp = (struct arphdr *) (eth + 1);
	arp->ar_hrd = htons(ARPHRD_ETHER);
	arp->ar_pro = htons(ETH_P_IP);
	arp->ar_hln = ETH_ALEN;
	arp->ar_pln = 4;	/* IP */
	arp->ar_op = as->oper;
	
	arpeth = (struct arpeth_hdr *)(arp + 1);
	memcpy(arpeth->ar_sha, as->sender_mac, ETH_ALEN);
	*(unsigned long *)arpeth->ar_sip = as->sender_addr;
	memcpy(arpeth->ar_tha, as->target_mac, ETH_ALEN);
	*(unsigned long *)arpeth->ar_tip = as->target_addr;

	memset(&spkt, 0, sizeof(spkt));
	strncpy(spkt.sa_data, eth_device, sizeof(spkt.sa_data));

	memset(&msg, 0, sizeof(msg));
	msg.msg_name = &spkt;
	msg.msg_namelen = sizeof(spkt);
	msg.msg_iovlen = 1;
	msg.msg_iov = &iov;
	iov.iov_base = buf;
	/*
	 * arp packets are sent as 60 bytes packets (sum of structs are 42)
	 */
	data_len = sizeof(struct ethhdr) + sizeof(struct arphdr) + sizeof(struct arpeth_hdr);
	memset(buf + data_len, 0, 60 - data_len);
/*	iov.iov_len = sizeof(struct ethhdr) + sizeof(struct arphdr) + sizeof(struct arpeth_hdr);*/
	iov.iov_len = 60;

	retval = Sendmsg(linksock, &msg, 0);
	return retval;
}

int send_packet(struct packet *p)
{
	int retval;
	struct sockaddr spkt;
	struct msghdr msg;
	struct iovec iov;
	
	memset(&spkt, 0, sizeof(spkt));
	strncpy(spkt.sa_data, eth_device, sizeof(spkt.sa_data));
	
	memset(&msg, 0, sizeof(msg));
	msg.msg_name = &spkt;
	msg.msg_namelen = sizeof(spkt);
	msg.msg_iovlen = 1;
	msg.msg_iov = &iov;
	iov.iov_base = p->p_raw;
	iov.iov_len = p->p_raw_len;
	
	retval = Sendmsg(linksock, &msg, 0);
	return retval;
}

#if 0
void arp_test(void)
{
	struct arp_spec as;
	int i;
	
	char src_mac[6] = {0x00, 0x60, 0x97, 0x75, 0xA4, 0xA4};
	char dst_mac[6] = {0x00, 0x60, 0x97, 0x72, 0x4E, 0xB5};
	char sender[6] = {0xEA, 0x1A, 0xDE, 0xAD, 0xBE, 0xEF};
	
	linksock = tap(eth_device, 1);
	as.src_mac = sender;
	as.dst_mac = dst_mac;
	as.oper = htons(ARPOP_REPLY);	/* ARPOP_REQUEST */
	as.sender_mac = sender;
	as.sender_addr = inet_addr("192.168.32.13");
	as.target_mac = dst_mac;
	as.target_addr = inet_addr("192.168.32.10");
	
	send_arp_packet(&as);
	
	close(linksock);
}
#endif
