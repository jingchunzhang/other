/*
 *
 *	This is free software. You can redistribute it and/or modify under
 *	the terms of the GNU General Public License version 2.
 *
 * 	Copyright (C) 1998 by kra
 *
 */
#include "hunt.h"
#include <sys/socket.h>
#include <arpa/inet.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <signal.h>
#include <unistd.h>
#include <string.h>
#include <ctype.h>
#include <netdb.h>

#if 0
static char *__tty_color[] = {
		"\033[0;40;30m",		 /* 0	black on black */
		"\033[0;40;31m",		 /* 1	red */
		"\033[0;40;32m",		 /* 2	green */
		"\033[0;40;33m",		 /* 3	brown */
		"\033[0;40;34m",		 /* 4	blue */
		"\033[0;40;35m",		 /* 5	magenta */
		"\033[0;40;36m",		 /* 6	cyan */
		"\033[0;40;37m",		 /* 7	light gray */
		"\033[1;40;30m",		 /* 0	gray */
		"\033[1;40;31m",		 /* 1	brightred */
		"\033[1;40;32m",		 /* 2	brightgreen */
		"\033[1;40;33m",		 /* 3	yellow */
		"\033[1;40;34m",		 /* 4	brightblue */
		"\033[1;40;35m",		 /* 5	brighmagenta */
		"\033[1;40;36m",		 /* 6	brightcyan */
		"\033[1;40;37m",		 /* 7	white */
};
#endif

void print_colors()
{
	int i;
	
	for (i = 0; i < 16; i++) {
		set_tty_color(i);
		printf("%d Hi\n", i);
	}
}

void set_tty_color(enum TTY_COLOR color)
{
	set_tty_color_bg(color, COLOR_BLACK);
}

void set_tty_color_bg(enum TTY_COLOR fg, enum TTY_COLOR bg)
{
	char buf[32];
	
	sprintf(buf, "\033[%d;4%d;3%dm", fg / 8, bg % 8, fg % 8);
	fputs(buf, stdout);
}

int is_power2(unsigned int i)
{
	while (!(i & 1))
		i >>= 1;
        i >>= 1;
	return i ? 0 : 1;
}

int log2(unsigned int i)
{
	int l = 0;

	if (!i)
		return -1;
	while (!(i & 1)) {
		l++;
		i >>= 1;
	}
	i >>= 1;
	if (i)
		return 0;
	else
		return l;
}

int count_mask(unsigned int mask)
{
	int retval;
	
	retval = 0;
	while (mask) {
		if (mask & 1)
			retval++;
		mask >>= 1;
	}
	return retval;
}

void print_data_packet(struct packet *p, int data_len, int count, int dst_packet)
{
	static unsigned int hsrc_seq_done;
	static unsigned int hdst_seq_done;
	int data_start;
	int i;
	
	data_start = 0;
#if 0
	if (count == 1) {
		if (dst_packet)
			hdst_seq_done = ntohl(p->p_hdr.p_tcph->seq) + data_len;
		else
			hsrc_seq_done = ntohl(p->p_hdr.p_tcph->seq) + data_len;
	}
#endif
	if (count > 1) {
		if (dst_packet)
			data_start = hdst_seq_done - ntohl(p->p_hdr.p_tcph->seq);
		else
			data_start = hsrc_seq_done - ntohl(p->p_hdr.p_tcph->seq);
		if (data_start < 0)
			data_start = 0;
	}
	if (!dst_packet)
	    	set_tty_color(COLOR_GREEN);
	for (i = data_start; i < data_len; i++) {
		if (p->p_data[i] == '\r' && i + 1 < data_len && 
		    p->p_data[i + 1] != '\n')
			putchar('\n');
		else {
			if (isprint(p->p_data[i]) || isspace(p->p_data[i]) || 
			    (print_cntrl_chars && (iscntrl(p->p_data[i]) || p->p_data[i] == 033)))
				putchar(p->p_data[i]);
			else {
				printf("<%X>", (unsigned int) (unsigned char) p->p_data[i]);
			}
		}
	}
	if (!dst_packet)
	    	set_tty_color(COLOR_LIGHTGRAY);
	fflush(stdout);
	
	if (count && data_start <= data_len) {
		if (dst_packet)
			hdst_seq_done = ntohl(p->p_hdr.p_tcph->seq) + data_len;
		else
			hsrc_seq_done = ntohl(p->p_hdr.p_tcph->seq) + data_len;
	}
}

void print_data(char *label, void *data, int len)
{
	int i;

	printf("%s: ", label);
	for (i = 0; i < len; i++) {
		printf("%X ", ((unsigned char *)data)[i]);
	}
	printf("\n");
}


unsigned short ip_in_cksum(struct iphdr *iph, unsigned short *ptr, int nbytes)
{

	register long sum = 0;	/* assumes long == 32 bits */
	u_short oddbyte;
	int pheader_len;
	unsigned short *pheader_ptr;
	
	struct pseudo_header {
		unsigned long saddr;
		unsigned long daddr;
		unsigned char null;
		unsigned char proto;
		unsigned short tlen;
	} pheader;
	
	pheader.saddr = iph->saddr;
	pheader.daddr = iph->daddr;
	pheader.null = 0;
	pheader.proto = iph->protocol;
	pheader.tlen = htons(nbytes);

	pheader_ptr = (unsigned short *)&pheader;
	for (pheader_len = sizeof(pheader); pheader_len; pheader_len -= 2) {
		sum += *pheader_ptr++;
	}
	while (nbytes > 1) {
		sum += *ptr++;
		nbytes -= 2;
	}
	if (nbytes == 1) {	/* mop up an odd byte, if necessary */
		oddbyte = 0;	/* make sure top half is zero */
		*(u_char *) (& oddbyte) = *(u_char *) ptr;	/* one byte only */
		sum += oddbyte;
	}
	sum = (sum >> 16) + (sum & 0xFFFF);
	return ~(sum  + (sum >> 16)) & 0xFFFF;
}

unsigned short in_cksum(unsigned short *ptr, int nbytes)
{
	register long sum=0;        /* assumes long == 32 bits */
	u_short oddbyte;
        
	while(nbytes>1){
        	sum+=*ptr++;
	        nbytes-=2;    
	}
	if(nbytes==1){              /* mop up an odd byte, if necessary */
        	oddbyte=0;              /* make sure top half is zero */
	        *(u_char *)(&oddbyte)=*(u_char *)ptr;   /* one byte only */
        	sum+=oddbyte;
	}               
	sum = (sum >> 16) + (sum & 0xFFFF);
	return ~(sum  + (sum >> 16)) & 0xFFFF;
}

int sprintf_eth_mac(char *b, unsigned char *mac)
{
	return sprintf(b, "%02X:%02X:%02X:%02X:%02X:%02X", 
		       mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);
}

int print_eth_mac(unsigned char *mac)
{
	char buf[64];
	
	sprintf_eth_mac(buf, mac);
	return printf("%s", buf);
}

int rawsock(void)
{
	int fd,val=1;
    
	if ((fd = socket(AF_INET, SOCK_RAW, IPPROTO_RAW)) < 0) {
	        if(verbose)
			perror("\n(rawsock) Socket problems [fatal]");
		exit(1);
	}  

#ifdef IP_HDRINCL
	if (setsockopt(fd, IPPROTO_IP, IP_HDRINCL, &val, sizeof(val)) < 0) {  
		if (verbose) {
        		perror("Cannot set IP_HDRINCL socket option");
			fprintf(stderr,"\nIf you are relying on this rather then a hacked kernel to spoof packets, your sunk.\n[cr]");
			getchar();
		}
	}
#endif
	return fd;
}	

#if 0
static unsigned const ethernet_polynomial_le = 0xedb88320U;
static inline unsigned int ether_crc_le(int length, unsigned char *data)
{
	unsigned int crc = 0xffffffff;	/* Initial value. */
	while(--length >= 0) {
		unsigned char current_octet = *data++;
		int bit;
		for (bit = 8; --bit >= 0; current_octet >>= 1) {
			if ((crc ^ current_octet) & 1) {
				crc >>= 1;
				crc ^= ethernet_polynomial_le;
			} else
				crc >>= 1;
		}
	}
	return crc;
}

#endif

int sprintf_db_ports(unsigned int *ports, char *buf, int buf_size, int all)
{
	char *buf_orig;
	int i;
	
	buf_orig = buf;
	if (ports[0] == 0) {
		if (all)
			buf += sprintf(buf, "all");
		return buf - buf_orig;
	}
	for (i = 0; ports[i]; i++) {
		if (PORT_INTERVAL(ports[i])) {
/*			buf += sprintf(buf, "%d:%d ", ntohs(PORT_VAL(ports[i])), ntohs(ports[i+1]));*/
			buf += sprintf(buf, "%s:%s ", 
				       port_lookup(PORT_VAL(ports[i]), hl_mode),
				       port_lookup(ports[i+1], hl_mode));
			++i;
		} else
/*			buf += sprintf(buf, "%d ", ntohs(ports[i]));*/
			buf += sprintf(buf, "%s ", port_lookup(ports[i], hl_mode));
	}
	*(buf - 1) = 0;
	return buf - buf_orig;
}

int port_match(int port, unsigned int *db_ports)
{
	int start, end;
	int pass;
	int i;
	
	if (!db_ports[0])
		return 1;
	pass = 0;
	for (i = 0; db_ports[i]; i++) {
		if (PORT_INTERVAL(db_ports[i])) {
			start = ntohs(PORT_VAL(db_ports[i]));
			end = ntohs(db_ports[++i]);
			if (start <= ntohs(port) && ntohs(port) <= end) {
				pass = 1;
				break;
			}
		} else if (port == db_ports[i]) {
			pass = 1;
			break;
		}
	}
	if (pass)
		return 1;
	else
		return 0;
}

void port_htons(unsigned int *db_ports)
{
	int i;
	unsigned int upper;
	
	for (i = 0; db_ports[i]; i++) {
		upper = db_ports[i] & (~PORT_MASK);
		db_ports[i] = upper | htons(PORT_VAL(db_ports[i]));
	}
}

unsigned char __suggest_mac[ETH_ALEN] = {0xEA, 0x1A, 0xDE, 0xAD, 0xBE, 0x00};
unsigned char *suggest_mac(void)
{
	int i;
	
	for (i = ETH_ALEN - 1; i >= 0; i++) {
		if (++__suggest_mac[i] != 0)
			break;
		++__suggest_mac[i]; /* don't leave it 00 ??? */
	}
	return __suggest_mac;
}

void ctrl_c_prompt(void)
{
	set_tty_color(COLOR_BRIGHTRED);
	printf("CTRL-C to break\n");
	set_tty_color(COLOR_LIGHTGRAY);
	fflush(stdout);
}

void clear_scr(void)
{
	int i;
	
	for (i = 0; i < 50; i++)
		putchar('\n');
}

int writen(int fd, char *ptr, int nbytes)
{
	int	nleft, nwritten;

	nleft = nbytes;
	while (nleft > 0) {
		nwritten = write(fd, ptr, nleft);
		if (nwritten <= 0)
			return(nwritten);		/* error */

		nleft -= nwritten;
		ptr   += nwritten;
	}
	return(nbytes - nleft);
}

