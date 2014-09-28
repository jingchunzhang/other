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
#include <netdb.h>
#include <stdlib.h>
#include <string.h>
#include <signal.h>
#include <stdio.h>
#include <ctype.h>
#include <setjmp.h>
#include <errno.h>

static int menu_prompt(char *label, char *buf, int buf_size, char *dfl)
{
	if (!label)
		label = "";
	set_tty_color(COLOR_WHITE);
	if (dfl) {
		if (strlen(label))
			printf("%s [%s]> ", label, dfl);
		else
			printf("[%s]> ", dfl);
	} else
		printf("%s> ", label);
	fgets(buf, buf_size, stdin);
	set_tty_color(COLOR_LIGHTGRAY);
	if (buf[0] == 0x0a) {
		if (dfl)
			strcpy(buf, dfl);
		else
			return -1;
	}
	if (buf[0] == 'x')
		return -1;
	return 0;
}

int parse_unr(char *buf, int min, int max)
{
	char *tmp;
	int i;
	
	i = strtol(buf, &tmp, 10);
	if ((!*tmp || *tmp == 0x0a) && i >= min && i <= max)
		return i;
	else
		return -1;
}

int parse_ports(char *buf, unsigned int *ret_ports)
{
	char *buf_p;
	char *p, *d, *tmp;
	int  ports[MAX_PORTS + 1];
	int err, i;
	int count;
	
	buf_p = buf;
	err =0;
	count = 0;
	while ((p = strtok(buf_p, " ,;\t\n"))) {
		buf_p = NULL;
		if ((d = strchr(p, '-')) || (d = strchr(p, ':'))) {
			*d++ = 0;
			i = strtol(p, &tmp, 10);
			if (*tmp) {
				err = 1;
				break;
			}
			ports[count] = i;
			PORT_SET_INTERVAL(ports[count]);
			count++;
			i = strtol(d, &tmp, 10);
			if (*tmp) {
				err = 1;
				break;
			}
			ports[count++] = i;
		} else {
			i = strtol(p, &tmp, 10);
			if (*tmp) {
				if ((i = service_lookup(p)) == 0) {;
					err = 1;
					break;
				}
			}
			ports[count++] = i;
		}
	}
	ports[count++] = 0;
	if (err || count > MAX_PORTS + 1) {
		printf("bad ports\n");
		return -1;
	} else {
		memcpy(ret_ports, ports, sizeof(int) * count);
		return 0;
	}	
}

static sigjmp_buf jmp_hostbyname;
static int ctrl_c_signaled;

static void ctrl_c_handler(int nr)
{
	int was_already_signaled = ctrl_c_signaled;
	
	ctrl_c_signaled = 1;
	if (!was_already_signaled)
		siglongjmp(jmp_hostbyname, 1);
}

unsigned int parse_hostname(char *buf)
{
	struct sigaction sac, old_sac;
	sigset_t new_mask;
	char *buf_p;
	struct hostent *hent;
	unsigned int ip;
	
	buf_p = buf;
	while(isalnum(*buf_p) || ispunct(*buf_p))
		buf_p++;
	*buf_p = 0;
#if 0
	if (host_name_in_num(buf)) {
		ip = inet_addr(buf);
		return ip;
	} else {
	}
#endif
	hent = NULL;
	if (sigsetjmp(jmp_hostbyname, 0) == 0) {
		ctrl_c_signaled = 0;
		sac.sa_handler = ctrl_c_handler;
		sigemptyset(&sac.sa_mask);
		sigaddset(&sac.sa_mask, SIGINT);
		sac.sa_flags = SA_RESTART;
		sigaction(SIGINT, &sac, &old_sac);
		
		/*
		 * well, maybe it isn't safe to longjmp from gethostbyname,
		 * though I do it bacause user want some respons
		 */
		hent = gethostbyname(buf);
	
		sigaction(SIGINT, &old_sac, NULL);
	} else {
		hent = NULL;
		press_key("\n-- operation canceled - press any key> ");
		sigaction(SIGINT, &old_sac, NULL);
		sigemptyset(&new_mask);
		sigaddset(&new_mask, SIGINT);
		pthread_sigmask(SIG_UNBLOCK, &new_mask, NULL);
	}
	
	if (hent) {
		ip = *(unsigned int *) hent->h_addr_list[0];
		return ip;
	} else {
		printf("can't resolve name %s to host address\n", buf);
		return -1;
	}
}

int parse_mac(char *buf, char *mac_ret)
{
	unsigned char mac[ETH_ALEN];
	char *p, *tmp, *buf_p;
	int count, i, err;
	
	buf_p = buf;
	count = 0;
	err = 0;
	while ((p = strtok(buf_p, ": \t\n")) && count < ETH_ALEN) {
		buf_p = NULL;
		i = strtol(p, &tmp, 16);
		if (*tmp) {
			err  = 1;
			break;
		}
		mac[count++] = i;
	}
	if (count != ETH_ALEN)
		err = 1;
	if (!err) {
		memcpy(mac_ret, mac, ETH_ALEN);
		return 0;
	} else {
		printf("bad mac address\n");
		return -1;
	}
}

#if 0
static int host_name_in_num(char *buf)
{
	for ( ; *buf; buf++) {
		if (!(*buf == '.') && !isdigit(*buf) && !isspace(*buf))
			return 0;
	}
	return 1;
}
#endif




int menu_choose_unr(char *label, int min, int max, int dfl)
{
	char buf[64], __dfl_buf[64], *dfl_buf;
	int i;

	if (min > max)
		return -1;
	if (min < 0 || max < 0)
		return -1;
	if (dfl < 0)
		dfl_buf = NULL;
	else {
		sprintf(__dfl_buf, "%d", dfl);
		dfl_buf = __dfl_buf;
	}
	while (1) {
		if (menu_prompt(label, buf, sizeof(buf), dfl_buf) < 0)
			return -1;
		if ((i = parse_unr(buf, min, max)) >= 0)
			break;
	}
	return i;
}

int menu_choose_mac(char *label, unsigned char *mac_ret, char *dfl)
{
	char buf[BUFSIZE];
	
	while (1) {
		if (menu_prompt(label, buf, sizeof(buf), dfl) < 0)
			return -1;
		if (strncasecmp(buf, "my", 2) == 0 || 
		    strncasecmp(buf, "my eth", 6) == 0 ||
		    strncasecmp(buf, "my eth mac", 10) == 0 ||
		    strncasecmp(buf, "my mac", 6) == 0) {
			memcpy(mac_ret, my_eth_mac, ETH_ALEN);
			return 0;
		}
		if (parse_mac(buf, mac_ret) == 0)
			return 0;
	}
}

unsigned int menu_choose_hostname(char *label, char *dfl)
{
	char buf[256];
	unsigned int ip;
	
	while (1) {
		if (menu_prompt(label, buf, sizeof(buf), dfl) < 0)
			return -1;
		if ((ip = parse_hostname(buf)) != -1)
			break;
	}
	return ip;
}


int menu_choose_ports(char *label, int *ret_ports, char *dfl)
{
	char buf[BUFSIZE];
	
	while (1) {
		if (menu_prompt(label, buf, sizeof(buf), dfl) < 0)
			return -1;
		if (parse_ports(buf, ret_ports) == 0)
			return 0;
	}
}

int menu_choose_host_mask_ports(char *label, unsigned int *ret_ip,
		unsigned int *ret_mask, unsigned int *ret_ports, char *dfl)
{
	char buf[256];
	char *host_name, *mask_str, *ports_str;
	unsigned int ip;
	int with_mask, mask;
	unsigned int ports[MAX_PORTS + 1];
	
	while (1) {
		if (menu_prompt(label, buf, sizeof(buf), dfl) < 0)
			return -1;
		if (strchr(buf, '/'))
			with_mask = 1;
		else
			with_mask = 0;
		
		if (!(host_name = strtok(buf, " /\t\n")))
			continue;
		if ((ip = parse_hostname(host_name)) == -1)
			continue;
		if (with_mask) {
			if (!(mask_str = strtok(NULL, " \t\n")))
				continue;
			if ((mask = parse_unr(mask_str, 0, 32)) < 0)
				continue;
			mask = mask ? 0xFFFFFFFFU >> (32 - mask) : 0;
		} else {
			if (ip == 0)
				mask = 0;
			else if ((ip & 0x80FFFFFFU) == 0)
				mask = 0xFF;
			else if ((ip & 0x40FFFFFFU) == 0)
				mask = 0xFFFFU;
			else if ((ip & 0x20FFFFFFU) == 0)
				mask = 0xFFFFFFU;
			else
				mask = 0xFFFFFFFFU;
		}
		if ((ports_str = strtok(NULL, "\n"))) {
			if (parse_ports(ports_str, ports) < 0)
				continue;
		} else
			memset(ports, 0, sizeof(ports));
		*ret_ip = ip;
		*ret_mask = mask;
		memcpy(ret_ports, ports, sizeof(ports));
		return 0;
	}
}

int menu_choose_host_mask_ports_dfl(char *label, unsigned int *ret_ip,
		unsigned int *ret_mask, unsigned int *ret_ports,
		unsigned int dfl_ip, unsigned int dfl_mask, int *dfl_ports)
{
	char dfl[256], *buf_p;
	
	buf_p = dfl;
	buf_p += sprintf(buf_p, "%s/%d", host_lookup(dfl_ip, hl_mode), count_mask(dfl_mask));
	if (dfl_ports && dfl_ports[0]) {
		buf_p += sprintf(buf_p, " ");
		buf_p += sprintf_db_ports(dfl_ports, buf_p, 
				  &dfl[sizeof(dfl)] - buf_p, 0);
	}
	return menu_choose_host_mask_ports(label, ret_ip, ret_mask, ret_ports,
					   dfl);
}

static pthread_mutex_t menucc_mutex = PTHREAD_MUTEX_INITIALIZER;
static int menucc_in_menu = 0;
static int menucc_conn_ind = 0;
static char *menucc_label;
static char *menucc_opt;
static char menucc_dfl;
static int menucc_conn_s = 0;
static int menucc_conn_s_old = 0;

#define NEW_CONN_IND  '*'
#define NEW_CONN_CLR  '-'

void clear_new_conn_ind(void)
{
	pthread_mutex_lock(&menucc_mutex);
	menucc_conn_s_old = menucc_conn_s;
	pthread_mutex_unlock(&menucc_mutex);
}


void print_new_conn_ind(int add_new)
{
	static int last = 0;
	
	pthread_mutex_lock(&menucc_mutex);
	if (add_new) {
		menucc_conn_s++;
	}
	if (menucc_in_menu && 
	    (menucc_conn_ind == 0 || add_new == 0 || last == 0)) {
		if (menucc_conn_ind) {
			putchar('\r');	/* 0x08 */
			if (menucc_conn_s != menucc_conn_s_old) {
				putchar(NEW_CONN_IND);
				last = 1;
			} else {
				putchar(NEW_CONN_CLR);
				last = 0;
			}
		}
		if (menucc_dfl) {
			if (strlen(menucc_label))
				printf("%s [%c]> ", menucc_label, menucc_dfl);
			else
				printf("[%c]> ", menucc_dfl);
		} else
			printf("%s> ", menucc_label);
		fflush(stdout);
	}
	pthread_mutex_unlock(&menucc_mutex);
}

int menu_choose_char_nconn(char *label, char *opt, char dfl, int conn_ind)
{
	char buf[64];
	int i;
	
	while (1) {
		if (!label)
			label = "";
		set_tty_color(COLOR_WHITE);
		
		pthread_mutex_lock(&menucc_mutex);
		menucc_label = label;
		menucc_opt = opt;
		menucc_dfl = dfl;
		menucc_in_menu = 1;
		menucc_conn_ind = conn_ind;
		pthread_mutex_unlock(&menucc_mutex);
		
		print_new_conn_ind(0);
		
		fgets(buf, sizeof(buf), stdin);
		
		pthread_mutex_lock(&menucc_mutex);
		menucc_in_menu = 0;
		pthread_mutex_unlock(&menucc_mutex);
		
		set_tty_color(COLOR_LIGHTGRAY);
		if (buf[0] == 0x0a && dfl) {
			i = (int) dfl;
			break;
		}
		if (buf[0] == 0x0a) {
			i = -1;
			break;
		}
		if (strchr(opt, buf[0])) {
			i = buf[0];
			break;
		}
	}
	return i;
}

int menu_choose_char(char *label, char *opt, char dfl)
{
	return menu_choose_char_nconn(label, opt, dfl, 0);
}

int menu_choose_yn(char *label, int dfl)
{
	int retval, c;
	
	c = menu_choose_char(label, "nyx", dfl ? 'y' : 'n');
	switch (c) {
	    case 'n':
		retval = 0;
		break;
	    case 'y':
		retval = 1;
		break;
	    default:
		retval = -1;
	}
	return retval;
}

int menu_choose_string(char *label, char *ret_buf, int buf_len, char *dfl)
{
	char buf[BUFSIZE];
	int len, min_len;
	
	if (!label)
		label = "";
	set_tty_color(COLOR_WHITE);
	if (dfl) {
		if (strlen(label))
			printf("%s [%s]> ", label, dfl);
		else
			printf("[%s]> ", dfl);
	} else
		printf("%s> ", label);
	fgets(buf, sizeof(buf), stdin);
	set_tty_color(COLOR_LIGHTGRAY);
	if (buf[0] == 0x0a) {
		if (dfl)
			strcpy(buf, dfl);
		else
			return -1;
	}
	len = strlen(buf);
	if (buf[len - 1] == '\n')
		buf[len - 1] = 0;
	min_len = buf_len < len + 1 ? buf_len : len + 1;
	memcpy(ret_buf, buf, min_len);
	ret_buf[min_len - 1] = 0;
	return 0;
}

int menu(char *head, char *str_menu, char *label, char *opt, char dfl)
{
	if (!head)
		head="";
	if (!str_menu)
	    str_menu = "";
	set_tty_color_bg(COLOR_BLACK, COLOR_WHITE);
	printf("--- %s --- rcvpkt %u, free/alloc %d/%d ---", head, 
	       pkts_received, packet_count(), packets_allocated);
	print_rst_daemon();
	print_arp_relayer_daemon();
	print_mac_daemon();
	print_sniff_daemon();
	printf("---");
	set_tty_color_bg(COLOR_WHITE, COLOR_BLACK);
	printf("\n");
	if (verbose) {
		set_tty_color_bg(COLOR_BLACK, COLOR_WHITE);
		printf("%*s", strlen(head) + 9, " ");
		printf("droppkt %u, other proto pkt %u",
		       pkts_dropped, pkts_unhandled);
		set_tty_color_bg(COLOR_WHITE, COLOR_BLACK);
		printf("\n");
	}
	printf("%s", str_menu);
	set_tty_color(COLOR_LIGHTGRAY);
	if (th_hunt) {
		if (pthread_kill(th_hunt, 0) != 0) {
			set_tty_color(COLOR_BRIGHTRED);
			printf("hunt failed - please restart the program");
			set_tty_color(COLOR_LIGHTGRAY);
		}
	}
	return menu_choose_char_nconn(label, opt, dfl, 1);
}

void press_key(char *label)
{
	if (!label)
	    label = "";
	set_tty_color(COLOR_WHITE);
	printf("%s", label);
	fflush(stdout);
	getchar();
	set_tty_color(COLOR_LIGHTGRAY);
}

int menu_choose_sdb(char *label, char dfl)
{
	char *str = "[s]rc/[d]st/[b]oth";
	char __label[128], *lbl;
	char buf[64];
	char __buf_dfl[2], *buf_dfl;

	if (dfl) {
		__buf_dfl[0] = dfl;
		__buf_dfl[1] = 0;
		buf_dfl = __buf_dfl;
	} else
		buf_dfl = NULL;
	if (label) {
		sprintf(__label, "%s %s", label, str);
		lbl = __label;
	} else
		lbl = str;
	while (1) {
		if (menu_prompt(lbl, buf, sizeof(buf), buf_dfl) < 0)
			return -1;
		if (strchr("sdb", buf[0])) {
			return buf[0];
		} else
			printf("bad src/dst/both\n");
	}
}

char int_to_sdb(int mode)
{
	char retval;
	
	switch (mode) {
	    case MODE_SRC:
		retval = 's';
		break;
	    case MODE_DST:
		retval = 'd';
		break;
	    case MODE_BOTH:
		retval = 'b';
		break;
	    default:
		retval = -1;
		break;
	}
	return retval;
}

int sdb_to_int(char mode)
{
	int retval;
	
	switch (mode) {
	    case 's':
		retval = MODE_SRC;
		break;
	    case 'd':
		retval = MODE_DST;
		break;
	    case 'b':
		retval = MODE_BOTH;
		break;
	    default:
		retval = -1;
		break;
	}
	return retval;
}

char *sdbmode_to_char(int mode)
{
	char *str_mode;
	
	switch (mode) {
	    case MODE_SRC:
		str_mode = "src";
		break;
	    case MODE_DST:
		str_mode = "dst";
		break;
	    case MODE_BOTH:
		str_mode = "both";
		break;
	    default:
		str_mode = "err";
		break;
	}
	return str_mode;
}
