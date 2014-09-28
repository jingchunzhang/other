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
#include <string.h>
#include <stdlib.h>

#define LINES_O_UNLIMITED	1000000
int lines_o = LINES_O_UNLIMITED;

static void list_conn_properties(void)
{
	int c;
	int mac, seq;
	
	c = menu_choose_char("print MAC y/n", "ny", conn_list_mac ? 'y' : 'n');
	switch (c) {
	    case 'n':
		mac = 0;
		break;
	    case 'y':
		mac = 1;
		break;
	    default:
		return;
	}
	c = menu_choose_char("print SEQ y/n", "ny", conn_list_seq ? 'y' : 'n');
	switch (c) {
	    case 'n':
		seq = 0;
		break;
	    case 'y':
		seq = 1;
		break;
	    default:
		return;
	}
	conn_list_mac = mac;
	conn_list_seq = seq;	
}

static void suggest_mac_setup(void)
{
	char buf[128];
	unsigned char buf_mac[ETH_ALEN];
	
	sprintf_eth_mac(buf, __suggest_mac);
	if (menu_choose_mac("suggest MAC base", buf_mac, buf) < 0)
		return;
	memcpy(__suggest_mac, buf_mac, sizeof(buf_mac));
}

static void print_host_properties(void)
{
	switch (menu_choose_char("Resolve host names", "yn", 
				 hl_mode == HL_MODE_NR ? 'n' : 'y')) {
	    case 'y':
		hl_mode = HL_MODE_DEFERRED;
		break;
	    case 'n':
		hl_mode = HL_MODE_NR;
		break;
	    default:
		break;
	}
}

static void mac_learn_from_ip_opt(void)
{
	switch (menu_choose_char("Learn MAC from IP traffic", "yn", 
				 mac_learn_from_ip == 0 ? 'n' : 'y')) {
	    case 'y':
		mac_learn_from_ip = 1;
		break;
	    case 'n':
		mac_learn_from_ip = 0;
		break;
	    default:
		break;
	}
}

static void storm_reset_sec_setup(void)
{
	int sec;
	
	if ((sec = menu_choose_unr("ACK storm reset sec", 0, 10000, storm_reset_sec)) < 0)
		return;
	storm_reset_sec = sec;
}

static void stormack_hijack_wait_sec_setup(void)
{
	int sec;
	
	if ((sec = menu_choose_unr("Sec to wait for next cmd with simple hijack", 0, 10000,
				   stormack_hijack_wait_sec)) < 0)
		return;
	stormack_hijack_wait_sec = sec;
}

static void arp_rr_count_setup(void)
{
	int n;
	
	if ((n = menu_choose_unr("Number of ARP request/reply packets hunt will send", 1, 32, arp_rr_count)) < 0)
		return;
	arp_rr_count = n;
}

static void arp_request_spoof_through_request_setup(void)
{
	switch (menu_choose_char("arp request spoof through request", "yn",
				 arp_request_spoof_through_request ? 'y' : 'n')) {
	    case 'y':
		arp_request_spoof_through_request = 1;
		break;
	    case 'n':
		arp_request_spoof_through_request = 0;
		break;
	    default:
		break;
	}
}

static void arp_spoof_switch_setup(void)
{
	switch (menu_choose_char("switched environment", "yn",
				 arp_spoof_switch ? 'y' : 'n')) {
	    case 'y':
		arp_spoof_switch = 1;
		break;
	    case 'n':
		arp_spoof_switch = 0;
		break;
	    default:
		break;
	}
}

static void arp_spoof_with_my_mac_setup(void)
{
	switch (menu_choose_char("use my mac in ARP spoofing", "yn",
				 arp_spoof_with_my_mac ? 'y' : 'n')) {
	    case 'y':
		arp_spoof_with_my_mac = 1;
		break;
	    case 'n':
		arp_spoof_with_my_mac = 0;
		break;
	    default:
		break;
	}
}

static void printed_lines_per_page(void)
{
	int n;
	
	n = lines_o;
	if (n == LINES_O_UNLIMITED)
		n = 0;
	if ((n = menu_choose_unr("Number of printed lines per page in listenings", 0, 10000, n)) < 0)
		return;
	if (n == 0)
		lines_o = LINES_O_UNLIMITED;
	else
		lines_o = n;
}


int print_cntrl_chars = 1;

static void print_cntrl_chars_setup(void)
{
	switch (menu_choose_char("print cntrl chars", "yn", 'y')) {
	    case 'y':
		print_cntrl_chars = 1;
		break;
	    case 'n':
		print_cntrl_chars = 0;
		break;
	    default:
		break;
	}
}

static void verbose_setup(void)
{
	switch (menu_choose_char("verbose", "yn", 
				 verbose ? 'y' : 'n')) {
	    case 'y':
		verbose = 1;
		break;
	    case 'n':
		verbose = 0;
		break;
	    default:
		break;
	}
}

void lines_o_press_key(void)
{
	press_key("press key");	
}

void options_menu(void)
{
	char buf_menu[2048];
	char buf_mac[128];
	char *o_keys = "lamdcghrsqtwyepvix";
	int run_it;
	
	run_it = 1;
	while (run_it) {
		sprintf_eth_mac(buf_mac, __suggest_mac);
		sprintf(buf_menu,
"l) list add conn policy                \n"
"a/m/d) add/mod/del conn policy entry   \n"
"c) conn list properties    mac %c, seq %c\n"
"g) suggest mac base        %s\n"
"h) host resolving              %c " "      t) arp req spoof through req   %c\n"
"r) reset ACK storm timeout   %3ds"  "      w) switched environment        %c\n"
"s) simple hijack cmd timeout %3ds"  "      y) arp spoof with my mac       %c\n"
"q) arp req/rep packets       %3d "  "      e) learn MAC from IP traffic   %c\n"
"p) number of lines per page  %3d "  "      v) verbose                     %c\n"
"i) print cntrl chars           %c\n"
"x) return\n",
	conn_list_mac ? 'y' : 'n', conn_list_seq ? 'y' : 'n',
	buf_mac,
	hl_mode == HL_MODE_NR ? 'n' : 'y', arp_request_spoof_through_request ? 'y' : 'n',
	storm_reset_sec, 		arp_spoof_switch ? 'y' : 'n',
	stormack_hijack_wait_sec,	arp_spoof_with_my_mac ? 'y' : 'n',
	arp_rr_count,			mac_learn_from_ip ? 'y' : 'n',
	lines_o == LINES_O_UNLIMITED ? 0 : lines_o, verbose ? 'y' : 'n',
	print_cntrl_chars ? 'y' : 'n');

		switch (menu("options", buf_menu, "opt", o_keys, 0)) {
		    case 'l':
			addpolicy_list_items();
			break;
		    case 'a':
			addpolicy_add_item();
			break;
		    case 'd':
			addpolicy_del_item();
			break;
		    case 'm':
			addpolicy_mod_item();
			break;
		    case 'c':
			list_conn_properties();
			break;
		    case 'g':
			suggest_mac_setup();
			break;
		    case 'h':
			print_host_properties();
			break;
		    case 'r':
			storm_reset_sec_setup();
			break;
		    case 's':
			stormack_hijack_wait_sec_setup();
			break;
		    case 'e':
			mac_learn_from_ip_opt();
			break;
		    case 't':
			arp_request_spoof_through_request_setup();
			break;
		    case 'w':
			arp_spoof_switch_setup();
			break;
		    case 'y':
			arp_spoof_with_my_mac_setup();
			break;
		    case 'q':
			arp_rr_count_setup();
			break;
		    case 'p':
			printed_lines_per_page();
			break;
		    case 'v':
			verbose_setup();
			break;
		    case 'i':
			print_cntrl_chars_setup();
			break;
		    case 'x':
			run_it = 0;
			break;
		}
	}
}

