/*
 *
 *	This is free software. You can redistribute it and/or modify under
 *	the terms of the GNU General Public License version 2.
 *
 * 	Copyright (C) 1998 by kra
 *
 */
#ifndef __HUNT_H
#define __HUNT_H

#ifndef _WITH_LINUX_KERNEL_HDR
#include <netinet/if_ether.h>
#include <netinet/ip.h>
#include <netinet/ip_icmp.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#else
#ifdef _REENTRANT
#	undef _REENTRANT
#	define _WAS_REENTRANT
#endif
#include <linux/types.h>
#include <linux/ip.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/socket.h>
#include <linux/sockios.h>
#include <linux/if_arp.h>
#include <linux/if.h>
#include <linux/tcp.h>
#include <linux/udp.h>
#include <linux/icmp.h>
#ifdef _WAS_REENTRANT
#	define _REENTRANT
#	undef _WAS_REENTRANT
#endif
#endif
#include <sys/types.h>
#include <sys/time.h>
#include <sys/resource.h>
#include <netinet/in.h>
#include <time.h>
#include <signal.h>
#include <pthread.h>
#include "c/list.h"
#include "c/hash.h"

#define VERSION	"1.5"

#define max(a, b)	((a) > (b) ? (a) : (b))
#define min(a, b)	((a) > (b) ? (b) : (a))

#define IP_DF           0x4000          /* Flag: "Don't Fragment"       */
#define BUFSIZE		512
#define IPHDR		20
#define TCPHDR		20

extern char *eth_device;
extern int verbose;
extern unsigned char my_eth_mac[ETH_ALEN];
extern unsigned int my_eth_ip;
extern pthread_t main_thread_id;
extern sigset_t intr_mask;

enum PACKET_TYPE {
		PACKET_NONE = 0, 
		PACKET_TCP = 1,
		PACKET_UDP = 2,
		PACKET_ICMP = 3, 
		PACKET_ARP = 4
};

#define MAX_MODULES		8
#define MODULE_DUMP_CONN	0
#define MODULE_HIJACK_CONN	1
#define MODULE_RSTD		2
#define MODULE_ARP_SPOOF	3
#define MODULE_SNIFF		4
#define MODULE_HOSTUP		5
#define MODULE_ARPSPOOF_TEST 	6

#define MAX_PORTS		16

struct packet {
	char 		p_raw[ETH_FRAME_LEN];	/* 1514 */
	int 		p_raw_len;
	int 		p_use_count;
	enum PACKET_TYPE p_type;
	pthread_mutex_t p_mutex;
	
	/* pointers to p_raw */
	struct ethhdr   *p_ethh;
	struct iphdr	*p_iph;
	struct arphdr	*p_arph; /* well, this should be a union with p_iph but 
				  * I am lazy to modify all sources right now */
	union {
		struct tcphdr	*p_tcph;
		struct udphdr	*p_udph;
		struct icmphdr	*p_icmph;
	} p_hdr;
	int		p_data_len;
	char 		*p_data;
	time_t		p_timestamp;
	
	/*
	 * pointers for modules packet list
	 */
	struct packet *p_next_free;
	struct packet *p_next[MAX_MODULES];
	void 	      *p_arg[MAX_MODULES]; /* for use in modules */
	int p_ipc;	/* for interthred communication -
			 * for ordinary packet p_ipc == 0 and p_ipc_arg == NULL
			 */
	void *p_ipc_arg;
};


typedef void (*ifunc)(struct packet *, void *arg);

/*
 * all is in network byte order
 */

struct ifunc_item {
	ifunc func;
	void *arg;
	struct ifunc_list *next_tcp;
	struct ifunc_list *next_udp;
	struct ifunc_list *next_icmp;
	struct ifunc_list *next_arp;
	struct ifunc_list *next_ip;
};

extern struct hash conn_table;
extern struct hash mac_table;

extern struct list l_ifunc_ip;
extern struct list l_ifunc_tcp;
extern struct list l_ifunc_udp;
extern struct list l_ifunc_icmp;
extern struct list l_ifunc_arp;
extern struct list l_ifunc_fast_tcp;

struct host_info {
	unsigned long next_seq;
	unsigned long next_d_seq;
	unsigned char src_mac[ETH_ALEN];
	unsigned char dst_mac[ETH_ALEN];
	unsigned short window;
	unsigned short id;
	unsigned int delta_d_seq;
};

struct conn_info {
	unsigned long  src_addr;
	unsigned long  dst_addr;
	unsigned short src_port;
	unsigned short dst_port;

	struct host_info src;
	struct host_info dst;
	
	int use_count;
	unsigned int update_count;
	unsigned int ack_storm_notify_sec;
	pthread_mutex_t mutex;
};

struct user_conn_info {
	unsigned long  src_addr;
	unsigned long  dst_addr;
	unsigned short src_port;
	unsigned short dst_port;
};

struct packet_info {
	unsigned long  src_addr;
	unsigned long  dst_addr;
	unsigned short src_port;
	unsigned short dst_port;

	struct host_info src;
	
	struct packet_info *next;
};

struct timejob;

struct arp_spoof_info {
	/*
	 * Basic idea is to make dst_addr host to think that host (src_addr) has 
	 * different mac address (src_fake_mac), then when dst_addr sent something
	 * to src_addr then it sends it to src_fake_mac. The src/dst naming is little
	 * bit weired and confusing (currently for me as well).
	 * 
	 * src_addr       IP address I want to spoof/corrupt somewhere in the network
	 * src_mac        true MAC address of src_addr
	 * src_mac_valid  is src_mac valid? (for spoofing hosts that are down)
	 * src_fake_mac   MAC address I want other host (with dst_addr) think src_addr have
	 * 
	 * dst_addr       IP address where to insert the spoof
	 * dst_mac        MAC address belonging to dst_addr
	 * dst_mac_valid  is dst_mac valid? (for spoofing hosts that are down)
	 */
	unsigned char src_fake_mac[ETH_ALEN];
	unsigned char src_mac[ETH_ALEN];
	unsigned char dst_mac[ETH_ALEN];
	int src_mac_valid;
	int dst_mac_valid;
	unsigned int src_addr;
	unsigned int dst_addr;

	/* is src_addr router - can forward packets for other hosts 
	 * (from/to internet) */
	int can_forward;
	/* 1 if arp_spoof_info belongs to arp spoof range */
	int in_range;
	
	int use_count;
	int lock_count;
	int refresh;
	struct timejob *tj_refresh;
	struct timejob *tj_reply; 
	struct arp_spoof_info *next;
	pthread_cond_t  lock_cond;
	pthread_mutex_t mutex;
};

struct arpeth_hdr {
        unsigned char           ar_sha[ETH_ALEN];       /* sender hardware address      */
        unsigned char           ar_sip[4];              /* sender IP address */
        unsigned char           ar_tha[ETH_ALEN];       /* target hardware address      */
        unsigned char           ar_tip[4];              /* target IP address */
};

struct mac_info {
	char mac[ETH_ALEN];
	pthread_mutex_t mutex;
};

struct add_policy_info {
	unsigned int src_addr;
	unsigned int src_mask;
	unsigned int dst_addr;
	unsigned int dst_mask;
	unsigned int src_ports[MAX_PORTS + 1];
	unsigned int dst_ports[MAX_PORTS + 1];
	struct add_policy_info *next;
};
extern struct add_policy_info add_policy;

extern int linksock;

#define ALIGNPOINTERS_ETH(packet, ethh) { \
	(ethh) = (struct ethhdr *) ((packet)->p_raw); \
}

#define ALIGNPOINTERS_IP(ethh, iph) { \
	(iph) = (struct iphdr *) ((char *)ethh + sizeof(struct ethhdr)); \
}

#define ALIGNPOINTERS_ARP(ethh, arph) { \
	(arph) = (struct arphdr *) ((char *)ethh + sizeof(struct ethhdr)); \
}

#define ALIGNPOINTERS_TCP(iph, tcph, pdata) { \
	(tcph) = (struct tcphdr *) (((char *) iph) + (iph->ihl << 2)); \
	(pdata) = ((char *) tcph) + (tcph->doff << 2); \
}

#define ALIGNPOINTERS_UDP(iph, udph, pdata) { \
	(udph) = (struct udphdr *) (((char *) iph) + (iph->ihl << 2)); \
	(pdata) = ((char *) udph) + sizeof(struct udphdr); \
}

#define ALIGNPOINTERS_ICMP(iph, icmph, pdata) { \
	(icmph) = (struct icmphdr *) (((char *) iph) + (iph->ihl << 2)); \
	(pdata) = ((char *) icmph) + sizeof(struct icmphdr); \
}

#define IP_DATA_LENGTH(iph) (ntohs((iph)->tot_len) - ((iph)->ihl << 2))
#define TCP_DATA_LENGTH(iph, tcph) (IP_DATA_LENGTH(iph) - ((tcph)->doff << 2))
#define IP_HDR_LENGTH(iph)   ((iph)->ihl << 2)
#define TCP_HDR_LENGTH(tcph) ((tcph)->doff << 2)


extern inline unsigned int generate_key(unsigned long saddr, unsigned long daddr,
			   unsigned short source, unsigned short dest)
{
	return saddr + daddr + source + dest;
}

#if 0
extern inline unsigned int generate_key_from_packet(struct packet *p)
{
	return generate_key(ntohl(p->p_iph->saddr), ntohl(p->p_iph->daddr),
		ntohs(p->p_hdr.p_tcph->source), ntohs(p->p_hdr.p_tcph->dest));
}
#endif
extern inline unsigned int uci_generate_key(struct user_conn_info *uci)
{
	return generate_key(ntohl(uci->src_addr), ntohl(uci->dst_addr),
		ntohs(uci->src_port), ntohs(uci->dst_port));
}

/*
 * hunt
 */
extern pthread_t th_hunt;

extern unsigned int pkts_received, pkts_dropped, pkts_unhandled;
extern unsigned int bytes_received;

extern int hunt_ready;
extern pthread_mutex_t mutex_hunt_ready;
extern pthread_cond_t cond_hunt_ready;

extern int packets_allocated;
extern int mac_learn_from_ip;

struct packet *packet_new(void);
void packet_free(struct packet *p);
void packet_want(struct packet *p);
void packet_flush(struct list *l);
void packet_copy_data(struct packet *dst, struct packet *src);
void packet_preallocate(int count);
int  packet_count(void);

void conn_free(struct conn_info *ci);
struct conn_info *conn_get(struct user_conn_info *uci);
int conn_exist(struct user_conn_info *uci);

void *hunt(void *arg);

extern int conn_list_mac;
extern int conn_list_seq;
int conn_list(struct user_conn_info **ruci, char **rbuf, int with_mac, int with_seq);
void print_user_conn_info(struct user_conn_info *uci, int count);

void remove_conn_if_dont_match(void);

void print_mac_table(void);
struct mac_info *mac_info_get(unsigned int ip);
void mac_info_release(struct mac_info *mi);


/*
 * menu
 */
int menu_choose_unr(char *label, int min, int max, int dfl);
int menu_choose_char(char *label, char *opt, char dfl);
int menu_choose_yn(char *label, int dfl);
int menu_choose_string(char *label, char *ret_buf, int buf_len, char *dfl);
int menu(char *head, char *str_menu, char *label, char *opt, char dfl);
void press_key(char *label);
unsigned int menu_choose_hostname(char *label, char *dfl);
int menu_choose_ports(char *label, int *ret_ports, char *dfl);
int menu_choose_mac(char *label, unsigned char *mac_ret, char *dfl);
int menu_choose_sdb(char *label, char dfl);

int menu_choose_host_mask_ports(char *label, unsigned int *ret_ip,
		unsigned int *ret_mask, unsigned int *ret_ports, char *dfl);
int menu_choose_host_mask_ports_dfl(char *label, unsigned int *ret_ip,
		unsigned int *ret_mask, unsigned int *ret_ports,
		unsigned int dfl_ip, unsigned int dfl_mask, int *dfl_ports);

void clear_new_conn_ind(void);
void print_new_conn_ind(int add_new);


#define MODE_SRC	0
#define MODE_DST	1
#define MODE_BOTH	2
int sdb_to_int(char c);
char int_to_sdb(int i);
char *sdbmode_to_char(int mode);

/*
 * util
 */
enum TTY_COLOR   {COLOR_BLACK = 0,
		  COLOR_RED = 1,
		  COLOR_GREEN = 2,
		  COLOR_BROWN = 3,
		  COLOR_BLUE = 4,
		  COLOR_MAGENTA = 5,
		  COLOR_CYAN = 6,
		  COLOR_LIGHTGRAY = 7,
		  COLOR_GRAY = 8,
		  COLOR_BRIGHTRED = 9,
		  COLOR_BRIGHTGREEN = 10,
		  COLOR_YELLOW = 11,
		  COLOR_BRIGHTBLUE = 12,
		  COLOR_BRIGHTMAGENTA = 13,
		  COLOR_BRIGHTCYAN = 14,
		  COLOR_WHITE = 15
};

void set_tty_color(enum TTY_COLOR color);
void set_tty_color_bg(enum TTY_COLOR fg, enum TTY_COLOR bg);

int is_power2(unsigned int i);
int log2(unsigned int i);
int count_mask(unsigned int mask);


void print_data_packet(struct packet *p, int data_len, int count, int dst_packet);
int sprintf_db_ports(unsigned int *ports, char *buf, int buf_size, int all);

void print_data(char *label, void *data, int len);

unsigned short ip_in_cksum(struct iphdr *iph, unsigned short *ptr, int nbytes);
unsigned short in_cksum(unsigned short *ptr, int nbytes);
int print_eth_mac(unsigned char *mac);
int sprintf_eth_mac(char *b, unsigned char *mac);
int tap(char *device, int promisc_mode);
int rawsock(void);
int get_ifc_info(char *ifc_name, unsigned int *ip, char *mac);

int port_match(int port, unsigned int *db_ports);
void port_htons(unsigned int *db_ports);

extern unsigned char __suggest_mac[ETH_ALEN];
unsigned char *suggest_mac(void);
void ctrl_c_prompt(void);
void clear_scr(void);

int writen(int fd, char *ptr, int nbytes);

/*
 * resolv.c
 */
#define HL_MODE_NR	 0
#define HL_MODE_DEFERRED 1
#define HL_MODE_NAME	 2

struct resolv_item {
	char *name;
	time_t put_timestamp;
	time_t get_timestamp;
	pthread_mutex_t mutex;
};

extern int hl_mode;
char *host_lookup(unsigned int in, int use_mode);
char *port_lookup(unsigned short serv, int use_mode);
unsigned short service_lookup(char *name);

void resolv_init(void);
void resolv_done(void);

void resolv_remove(unsigned int ip);
void resolv_put(unsigned int ip, const char *name);
struct resolv_item *resolv_get(unsigned int ip);
void resolv_request(unsigned int ip);





/*
 * reset connection
 */
/*
 * reset mode 
 */
void user_rst(struct user_conn_info *uci, int count, int mode);
void rst(struct conn_info *ci, int count, int rstdst);

/*
 * 
 * hijacking
 * 
 */
extern struct list l_hijack_conn;

/*
 * hijack
 */
extern int storm_reset_sec;
extern int stormack_hijack_wait_sec;

int user_stormack_hijack(struct user_conn_info *uci, char *cmdbuf);
int stormack_hijack(struct conn_info *ci, char *cmdbuf);

void func_hijack_dst(struct packet *p, struct conn_info *arg);
void func_hijack_src(struct packet *p, struct conn_info *arg);


/*
 * arphijack
 */
#define INPUT_MODE_RAW		0
#define INPUT_MODE_LINEECHOR	1
#define INPUT_MODE_LINEECHO	2
int user_arp_hijack(struct user_conn_info *uci, char *src_fake_mac,
		    char *dst_fake_mac, int input_mode);
void user_arp_hijack_done(char *src_fake_mac, char *dst_fake_mac);
int arp_hijack(struct conn_info *ci, char *src_fake_mac, char *dst_fake_mac, int input_mode);
void arp_hijack_done(char *src_fake_mac, char *dst_fake_mac);

/*
 * synchijack
 */
int user_hijack_sync(struct user_conn_info *uci);
int hijack_sync(struct conn_info *ci);

/*
 * arpspoof
 */
extern unsigned char mac_broadcast[ETH_ALEN];
extern unsigned char mac_zero[ETH_ALEN];
struct arp_spoof_info *start_arp_spoof(unsigned int src_addr,
				       unsigned int dst_addr,
		char *src_mac, char *dst_mac, char *src_fake_mac,
		int refresh, int can_forward, int in_range);
struct arp_spoof_info *get_arp_spoof(unsigned int src_addr, unsigned int dst_addr);
void stop_arp_spoof(struct arp_spoof_info *asi);
void arpspoof_menu(void);
void print_arp_relayer_daemon(void);
int arpspoof_test(struct arp_spoof_info *asi);
int user_arpspoof_test(struct arp_spoof_info *asi);
void force_arp_spoof(struct arp_spoof_info *asi, int count);
int run_arpspoof_until_successed(struct arp_spoof_info *asi);
int user_run_arpspoof_until_successed(struct arp_spoof_info *asi);
int arpspoof_exit_check();

struct arp_dont_relay {
	unsigned int src_addr;
	unsigned int dst_addr;
	unsigned short src_port;
	unsigned short dst_port;
	struct arp_dont_relay *next;
};

struct arp_dont_relay *arp_dont_relay_insert(
			unsigned int src_addr, unsigned int dst_addr,
			unsigned int src_port, unsigned int dst_port);
void arp_dont_relay_remove(struct arp_dont_relay *adr);

extern int arp_request_spoof_through_request;
extern int arp_rr_count;
extern int arp_spoof_switch;
extern int arp_spoof_with_my_mac;

/*
 * rstd
 */
#define PORT_SHIFT		16
#define PORT_MASK		0xFFFFU
#define PORT_VAL(x)		((x) & (PORT_MASK))
#define PORT_INTERVAL(x)	((x) & (1 << (PORT_SHIFT)))
#define PORT_SET_INTERVAL(x) 	((x) |= 1 << (PORT_SHIFT))

void rstd_menu(void);
void print_rst_daemon(void);


/*
 * sniff
 */
void sniff_menu(void);
void print_sniff_daemon(void);

/*
 * macdisc
 */
void mac_discover(unsigned int ip, int count);
void mac_discover_range(unsigned int start_ip, unsigned int end_ip, int count);
void mac_disc_menu(void);
void print_mac_daemon();

/*
 * tty.c
 */
int tty_cbreak(int fd, int wait_for_chars, int timer_dsec);
int tty_raw(int fd, int wait_for_chars, int timer_dsec);
int tty_reset(int fd);
void tty_atexit(void);
void tty_tput_reset(void);

/*
 * addpolicy.c
 */
extern struct list l_add_policy;
int conn_add_match(unsigned int src_addr, unsigned int dst_addr,
 		   unsigned short src_port, unsigned short dst_port);
int conn_add_policy(struct iphdr *iph, struct tcphdr *tcph);
void add_telnet_rlogin_policy(void);
void addpolicy_list_items(void);
void addpolicy_add_item(void);
void addpolicy_mod_item(void);
void addpolicy_del_item(void);

/*
 * options.c
 */
extern int lines_o;
extern int print_cntrl_chars;

void options_menu(void);
void lines_o_press_key();

/*
 * hostup.c
 */
void host_up(void);

/*
 * pktrelay.c
 */
void relay_menu(void);
int process_pktrelay(struct packet *p, struct arp_spoof_info *asi);

/*
 * timer.c
 */

/*
 * returns number of seconds of next invocation
 * 0 - unregister
 */
typedef int (*time_func)(void *arg, int arg_sec);

struct timejob {
	time_func 	j_func;
	void      	*j_arg;
	int       	j_arg_sec;
	struct timespec j_ts;
	
	/* private members */
	struct time_job *j_next;
};

void register_timejob(struct timejob *tj);
void register_timejob_rel(struct timejob *tj, int relsec);
void register_timejob_milsec_rel(struct timejob *tj, int milsec);

void unregister_timejob(struct timejob *tj);
void timer_init(void);
void timer_done(void);

/*
 * net.c
 * 
 * all have to be filled with network byte order
 */
struct tcp_spec {
	unsigned long saddr;
	unsigned long daddr;
	unsigned short sport;
	unsigned short dport;
	char *src_mac;
	char *dst_mac;
	unsigned long seq;
	unsigned long ack_seq;
	unsigned short window;
	unsigned short id;
	int ack;
	int rst;
	int psh;
	char *data;
	int data_len;
};

int send_tcp_packet(struct tcp_spec *ts);


struct icmp_spec {
	unsigned int src_addr;
	unsigned int dst_addr;
	char *src_mac;
	char *dst_mac;
	
	short type;
	short code;
	union {
		struct {
			unsigned short id;
			unsigned short seq;
		} idseq;
		unsigned int res;
	} un;
	
	void *data;
	int  data_len;
};

int send_icmp_packet(struct icmp_spec *is);
void send_icmp_request(unsigned int src_addr, unsigned int dst_addr,
		       char *src_mac, char *dst_mac, unsigned short seq);
int is_icmp_reply(struct packet *p, unsigned int src_addr, unsigned int dst_addr,
		  char *src_mac, char *dst_mac);


struct arp_spec {
	char *src_mac;
	char *dst_mac;
	
	int oper;
	char *sender_mac;
	unsigned long sender_addr;
	char *target_mac;
	unsigned long target_addr;
};

int send_arp_packet(struct arp_spec *as);

int send_packet(struct packet *p);

static inline void sec_nanosleep(int sec)
{
	struct timespec ts;
	
	ts.tv_sec = sec;
	ts.tv_nsec = 0;
	nanosleep(&ts, NULL);
}

#endif
