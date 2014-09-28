/*
 *
 *	This is free software. You can redistribute it and/or modify under
 *	the terms of the GNU General Public License version 2.
 *
 * 	Copyright (C) 1998 by kra
 *
 */
#include "hunt.h"
#include <sys/stat.h>
#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>
#include <ctype.h>
#include <errno.h>

#define SNIFF_FILE_DIR	".sniff"

int o_newline = 0;

struct sniff_log {
	unsigned int src_addr;
	unsigned int dst_addr;
	unsigned short src_port;
	unsigned short dst_port;
	
	int  src_to_dst;	
	int  loged_bytes;
	char *buf;
	int  state;
	
	int  file_close;
	FILE *file;
	
	struct sniff_log *next;
};

struct sniff_info {
	unsigned int src_addr;
	unsigned int dst_addr;
	int src_mask;
	int dst_mask;
	int src_ports[MAX_PORTS + 1];
	int dst_ports[MAX_PORTS + 1];
	
	int srch_mode;
	char *search;
		
	int log_mode;
	int log_bytes;
	
	int  file_close;
	FILE *file;
	struct list log;
	int lock_count;
	pthread_cond_t lock_cond;
	pthread_mutex_t mutex;
};

static struct ifunc_item ifunc_sniff;
static int sniffer_running = 0;
static struct list l_sniff_pkt = LIST_INIT(struct packet, p_next[MODULE_SNIFF]);
static pthread_t sniff_thr;
static struct list l_sniff_db = LIST_INIT(struct sniff_log, next);

#define STATE_SRCH	1
#define STATE_LOG	2

#define LOG_BUF_SIZE	2048

static void sniff_info_want(struct sniff_info *si)
{
	pthread_mutex_lock(&si->mutex);
	si->lock_count++;
	pthread_mutex_unlock(&si->mutex);
}

static void sniff_info_release(struct sniff_info *si)
{
	pthread_mutex_lock(&si->mutex);
	if (--(si->lock_count) == 0)
		pthread_cond_broadcast(&si->lock_cond);
	pthread_mutex_unlock(&si->mutex);
}

static void sniff_info_wait_for_release(struct sniff_info *si)
{
	pthread_mutex_lock(&si->mutex);
	while (si->lock_count > 0)
		pthread_cond_wait(&si->lock_cond, &si->mutex);
	pthread_mutex_unlock(&si->mutex);
}


void free_sniff_log(struct sniff_log *slog)
{
	if (slog->buf)
		free(slog->buf);
	if (slog->file_close)
		fclose(slog->file);
	free(slog);
}

void free_sniff_info(struct sniff_info *si)
{
	struct sniff_log *slog;
	
	if (si->search)
		free(si->search);
	while ((slog = list_pop(&si->log)))
		free_sniff_log(slog);
	if (si->file && si->file_close)
		fclose(si->file);
	free(si);
}

static void sniff_item_print(FILE *f, int i, struct sniff_info *si)
{
	char *str_srch_mode, *str_log_mode;
	char buf_src_ports[BUFSIZE], buf_dst_ports[BUFSIZE];
	char buf[BUFSIZE], *b;
	char host_buf[BUFSIZE];
	
	str_srch_mode = sdbmode_to_char(si->srch_mode);
	str_log_mode = sdbmode_to_char(si->log_mode);
	sprintf_db_ports(si->src_ports, buf_src_ports, sizeof(buf_src_ports), 1);
	sprintf_db_ports(si->dst_ports, buf_dst_ports, sizeof(buf_dst_ports), 1);
	b = buf;
	if (si->search)
		b += sprintf(b, "%s for X ", str_srch_mode);
	b += sprintf(b, "log %s %dB", str_log_mode, si->log_bytes);
	
	sprintf(host_buf, "%s/%d [%s]", host_lookup(si->src_addr, hl_mode),
		count_mask(si->src_mask), buf_src_ports);
	fprintf(f, "%2d) %-22s --> %s/%d [%s] %s\n", i,
		host_buf,
	        host_lookup(si->dst_addr, hl_mode), count_mask(si->dst_mask),
	        buf_dst_ports,
	        buf);
}

static void sniff_log_item_print(FILE *f, struct sniff_info *si, struct sniff_log *slog)
{
	char *direction;
	
	if (slog->src_to_dst)
		direction = "-->";
	else
		direction = "<--";
	fprintf(f, "%s [%d] %s %s [%d]\n",
	       host_lookup(slog->src_addr, hl_mode),
	       ntohs(slog->src_port),
	       direction,
	       host_lookup(slog->dst_addr, hl_mode),
	       ntohs(slog->dst_port));
}

/****************************************************************************
 * 
 * functions called from hunt
 * 
 */
static inline int sniff_packet_match(struct packet *p, struct sniff_info *si)
{
	struct iphdr *iph = p->p_iph;
	struct tcphdr *tcph = p->p_hdr.p_tcph;
	
	if ((si->srch_mode == MODE_SRC || si->srch_mode == MODE_BOTH ||
	     si->log_mode  == MODE_SRC || si->log_mode  == MODE_BOTH) &&
	    (iph->saddr & si->src_mask) == (si->src_addr & si->src_mask) &&
	    (iph->daddr & si->dst_mask) == (si->dst_addr & si->dst_mask) &&
	     port_match(tcph->source, si->src_ports) &&
	     port_match(tcph->dest, si->dst_ports))
		return 1;
	if ((si->srch_mode == MODE_DST || si->srch_mode == MODE_BOTH ||
      	     si->log_mode  == MODE_DST || si->log_mode  == MODE_BOTH) &&
	    (iph->saddr & si->dst_mask) == (si->dst_addr & si->dst_mask) &&
	    (iph->daddr & si->src_mask) == (si->src_addr & si->src_mask) &&
	     port_match(tcph->source, si->dst_ports) &&
	     port_match(tcph->dest, si->src_ports))
		return 1;
	return 0;
}

static void func_sniff(struct packet *p, void *arg)
{
	struct list_iterator li;
	struct sniff_info *si;
/*
 * locking l_sniff_db and si->mutex is needed as the si is set to the packet message
 * and will be used in sniff daemon
 */
	list_lock(&l_sniff_db);
	list_iter_set(&li, &l_sniff_db);
	while ((si = list_iter_get(&li))) {
		if (sniff_packet_match(p, si)) {
			packet_want(p);
			sniff_info_want(si);
			p->p_arg[MODULE_SNIFF] = si;
			list_produce(&l_sniff_pkt, p);
			break;
		}
	}
	list_iter_end(&li);
	list_unlock(&l_sniff_db);
}

/****************************************************************************************
 * 
 * functions for sniff daemon
 * 
 */
void sniffer_log_print(struct sniff_info *si, struct sniff_log *slog)
{
	char file_name[BUFSIZE], file_name_buf[BUFSIZE];
	struct stat stat_buf;
	FILE *f;
	int i;

	if (!slog->loged_bytes)
		return;
	if (!slog->file) {
		if (!si->file) {
			sprintf(file_name_buf, "%s/%s:%d_%s:%d",
				SNIFF_FILE_DIR,
				host_lookup(slog->src_addr, HL_MODE_DEFERRED),
				ntohs(slog->src_port),
				host_lookup(slog->dst_addr, HL_MODE_DEFERRED),
				ntohs(slog->dst_port));
			errno = 0;
			i = 0;
			strcpy(file_name, file_name_buf);
			while (stat(file_name, &stat_buf) >= 0 && errno != ENOENT)
				sprintf(file_name, "%s_%d", file_name_buf, ++i);
			if (!(f = fopen(file_name, "w"))) {
				printf("cannot open %s for writing\n", file_name);
				return;
			}
			slog->file = f;
			slog->file_close = 1;
		} else {
			slog->file = si->file;
			slog->file_close = 0;
		}
	}

	sniff_log_item_print(slog->file, si, slog);
	for (i = 0; i < slog->loged_bytes; i++) {
		if (isprint(slog->buf[i]) || (o_newline && isspace(slog->buf[i])))
			fputc(slog->buf[i], slog->file);
		else
			fprintf(slog->file, "[0x%X]", (unsigned char) slog->buf[i]);
	}
	fprintf(slog->file, "\n\n");
	fflush(slog->file);
	slog->loged_bytes = 0;
}

char *memfind(char *data, int data_len, char *str, int str_len)
{
	char *d;
	
	if (data_len == 0 || str_len == 0 || data_len < str_len)
		return NULL;
#if 0	
	{
	int i;

	for (i = 0; i < data_len; i++) {
		if (isprint(data[i]))
			fputc(data[i], stdout);
		else
			fprintf(stdout, "[0x%X]", (unsigned char) data[i]);
	}
	fprintf(stdout, "\n\n");
	}
#endif
	while (data_len >= str_len) {
		if ((d = memchr(data, str[0], data_len - str_len + 1))) {
			if (memcmp(d, str, str_len) == 0) {
				return d;
			}
			data_len -= (d - data) + 1;
			data = d + 1;
		} else
			break;
	}
	return NULL;
}

char *sniff_log_match(struct packet *p, struct sniff_info *si, struct sniff_log *slog)
{
	struct iphdr *iph = p->p_iph;
	struct tcphdr *tcph = p->p_hdr.p_tcph;
	int m_src_to_dst, m_dst_to_src;
	int find;
	char *log_data, *retval = NULL;
	
	find = 0;
	m_src_to_dst = m_dst_to_src = 0;
	if (iph->saddr == slog->src_addr &&
	    iph->daddr == slog->dst_addr &&
	    tcph->source == slog->src_port &&
	    tcph->dest == slog->dst_port)
		m_src_to_dst = 1;
	if (iph->daddr == slog->src_addr &&
	    iph->saddr == slog->dst_addr &&
	    tcph->dest == slog->src_port &&
	    tcph->source == slog->dst_port)
		m_dst_to_src = 1;
	if (!m_dst_to_src && !m_src_to_dst)
		return NULL;
	log_data = p->p_data;
	switch (slog->state) {
    	    case STATE_SRCH:
		if ((si->srch_mode == MODE_SRC || si->srch_mode == MODE_BOTH)
		    && m_src_to_dst)
			find = 1;
		else if ((si->srch_mode == MODE_DST || si->srch_mode == MODE_BOTH)
			 && m_dst_to_src)
			find = 1;
		if (find) {
			if (si->search) {
				log_data = memfind(p->p_data, p->p_data_len, si->search, strlen(si->search));
				if (log_data) {
					slog->state = STATE_LOG;
				}
			} else {
				log_data = p->p_data;
				slog->state = STATE_LOG;
			}
		}
		if (slog->state != STATE_LOG)
			break;
		/* go through */
    	    case STATE_LOG:
		if ((si->log_mode == MODE_SRC || si->log_mode == MODE_BOTH)
		    && m_src_to_dst) {
			retval = log_data;
		} else if ((si->log_mode == MODE_DST || si->log_mode == MODE_BOTH) &&
			 m_dst_to_src) {
			retval = log_data;
		}
		break;
    	default:
		fprintf(stderr, "sniffer - bad state\n");
		retval = NULL;
		break;
  	}
	if (!retval)
		retval = (void *) 1;
	return retval;
}

char *sniffer_match(struct packet *p, struct sniff_info *si, struct sniff_log **__slog)
{
	struct iphdr *iph = p->p_iph;
	struct tcphdr *tcph = p->p_hdr.p_tcph;
	char *retval = NULL;
	struct list_iterator li;
	struct sniff_log *slog;
	void *rret;
	
	list_iter_set(&li, &si->log);
	retval = NULL;
	while ((slog = list_iter_get(&li))) {
		if ((retval = sniff_log_match(p, si, slog)))
			break;
	}
	list_iter_end(&li);
	if (!retval && p->p_data_len) {
		slog = malloc(sizeof(struct sniff_log));
		if (ntohs(tcph->dest) >= 1024 && ntohs(tcph->source) < 1024) {
			slog->src_addr = iph->daddr;
			slog->dst_addr = iph->saddr;
			slog->src_port = tcph->dest;
			slog->dst_port = tcph->source;
		} else {
			slog->src_addr = iph->saddr;
			slog->dst_addr = iph->daddr;
			slog->src_port = tcph->source;
			slog->dst_port = tcph->dest;
		}
		slog->file = NULL;
		slog->file_close = 0;
		slog->src_to_dst = 0;
		slog->loged_bytes = 0;
		slog->buf = NULL;
		slog->state = si->search ? STATE_SRCH : STATE_LOG;
		slog->next = NULL;
		list_push(&si->log, slog);
		retval = sniff_log_match(p, si, slog);
		/* ok, request - resolve addresses for future use */
		host_lookup(slog->src_addr, HL_MODE_DEFERRED);
		host_lookup(slog->dst_addr, HL_MODE_DEFERRED);
	}
	
	if (retval) {
		if (p->p_hdr.p_tcph->rst || p->p_hdr.p_tcph->fin) {
			/* ok, wee don't handle half open connection */
			sniffer_log_print(si, slog);
			rret = list_remove(&si->log, slog);
			assert(rret);
			free_sniff_log(slog);
			retval = NULL;
		}	
	}
	
	if (retval == (void *) 1)
		retval = NULL;
	if (retval)
		*__slog = slog;
	else
		*__slog = NULL;
	return retval;
}

#if 0
static void log_data(FILE *f, char *data, int data_len)
{
	char *d;
	
	for (d = data; d < data + data_len; d++) {
		if (isprint(*d) || (o_newline && isspace(*d)))
			fputc(*d, f);
		else
			fprintf(f, "[0x%X]", (unsigned char) *d);
	}
}
#endif

void sniffer_log(char *data, struct packet *p, struct sniff_info *si, struct sniff_log *slog)
{
	int data_len, space, i;

	if (!data)
		return;
	if (!slog->buf)
		slog->buf = malloc(LOG_BUF_SIZE);
	data_len = p->p_data_len - (data - p->p_data);
#if 0
	printf("log data_len = %d: --", data_len);
	log_data(stdout, data, data_len);
	printf("\n");
#endif
	if (data_len || slog->loged_bytes >= si->log_bytes) {
		struct iphdr  *iph = p->p_iph;

		if (slog->src_to_dst && slog->src_addr == iph->daddr) {
			sniffer_log_print(si, slog);
			slog->src_to_dst = 0;
		} else if (!slog->src_to_dst && slog->src_addr == iph->saddr) {
			sniffer_log_print(si, slog);
			slog->src_to_dst = 1;
		}
	}
	while (data_len) {
		if ((space = LOG_BUF_SIZE - slog->loged_bytes) < 0)
			space = 0;
		i = min(data_len, space);
		memcpy(&slog->buf[slog->loged_bytes], data, i);
		slog->loged_bytes += i;
		data += i;
		data_len -= i;
		if (slog->loged_bytes == LOG_BUF_SIZE) {
			sniffer_log_print(si, slog);
			slog->state = si->search ? STATE_SRCH : STATE_LOG;
		}
	}
	if (slog->loged_bytes >= si->log_bytes) {
		sniffer_log_print(si, slog);
		slog->state = si->search ? STATE_SRCH : STATE_LOG;
	}
}

static void *sniffer(void *arg)
{
	struct sniff_info *si;
	struct sniff_log *slog;
	struct packet *p;
	char *data;
	
	pthread_sigmask(SIG_BLOCK, &intr_mask, NULL);
	setpriority(PRIO_PROCESS, getpid(), 10);
	while ((p = list_consume(&l_sniff_pkt, NULL))) {
		si = p->p_arg[MODULE_SNIFF];
		if ((data = sniffer_match(p, si, &slog)))
			sniffer_log(data, p, si, slog);
		sniff_info_release(si);
		packet_free(p);
	}
	return NULL;
}

/*****************************************************************************************
 * 
 * management
 * 
 */
static int sniff_daemon_init(void)
{
	struct stat stat_buf;
	
	if (stat(SNIFF_FILE_DIR, &stat_buf) == 0) {
		if (!S_ISDIR(stat_buf.st_mode)) {
			printf(SNIFF_FILE_DIR " isn't directory\n");
			return -1;
		} 
	} else {
		if (errno == ENOENT) {
			if (mkdir(SNIFF_FILE_DIR, 0700) < 0) {
				printf(SNIFF_FILE_DIR " can't be created\n");
				return -1;
			}
			printf("directory " SNIFF_FILE_DIR " created\n");
		} else {
			printf(SNIFF_FILE_DIR " error\n");
			return -1;
		}
	}
	return 0;
}

static void start_sniff(void)
{
	if (sniffer_running) {
		printf("sniffer already running\n");
		return;
	}
	if (sniff_daemon_init())
		return;
	list_produce_start(&l_sniff_pkt);
	pthread_create(&sniff_thr, NULL, (void *(*)(void *)) sniffer, NULL);
	ifunc_sniff.func = func_sniff;
	ifunc_sniff.arg = NULL;
	list_enqueue(&l_ifunc_tcp, &ifunc_sniff);
	sniffer_running = 1;
	printf("sniffer started\n");
}

static void stop_sniff(void)
{
	struct list_iterator li;
	struct packet *p;
	struct sniff_info *si;
	struct sniff_log *slog;
	
	if (!sniffer_running) {
		printf("sniffer isn't running\n");
		return;
	}
	list_remove(&l_ifunc_tcp, &ifunc_sniff);
	/* flush packets from l_sniff_pkt */
	while ((p = list_pop(&l_sniff_pkt))) {
		si = p->p_arg[MODULE_SNIFF];
		sniff_info_release(si);
		packet_free(p);
	}
	list_produce_done(&l_sniff_pkt);
	pthread_join(sniff_thr, NULL);
	
	list_lock(&l_sniff_db);
	list_iter_set(&li, &l_sniff_db);
	while ((si = list_iter_get(&li))) {
		while ((slog = list_pop(&si->log)))
			free_sniff_log(slog);
	}
	list_iter_end(&li);
	list_unlock(&l_sniff_db);
	
	sniffer_running = 0;
	printf("sniffer stopped\n");
}

void print_sniff_daemon(void)
{
	if (sniffer_running) {
		if (pthread_kill(sniff_thr, 0) != 0) {
			pthread_join(sniff_thr, NULL);
			sniff_thr = (pthread_t) 0;
			sniffer_running = 0;
			set_tty_color(COLOR_BRIGHTRED);
			printf("Sniffer daemon failed - bug\n");
			set_tty_color(COLOR_LIGHTGRAY);
		} else
			printf("S");
	}
}

/*
 * user interface
 */

static void sniff_item_log_print(FILE *f, int *l_nr, struct sniff_info *si)
{
	struct list_iterator li;
	struct sniff_log *slog;
	char *state;
	char host_buf[BUFSIZE];
	
	list_iter_set(&li, &si->log);
	while ((slog = list_iter_get(&li))) {
		switch (slog->state) {
		    case STATE_LOG:
			state = "LOG";
			break;
		    case STATE_SRCH:
			state = "SRCH";
			break;
		    default:
			state = "ERR";
			break;
		}
		sprintf(host_buf, "%s [%s]", 
			host_lookup(slog->src_addr, hl_mode),
			port_lookup(slog->src_port, hl_mode));
		fprintf(f, "\t%-24s -> %s [%s] loged=%dB state=%s\n",
			host_buf,
			host_lookup(slog->dst_addr, hl_mode),
			port_lookup(slog->dst_port, hl_mode),
			slog->loged_bytes, state);
		
		if (++(*l_nr) % lines_o == 0)
			lines_o_press_key();
	}
	list_iter_end(&li);
}

static void sniff_list_db(int all)
{
	struct list_iterator li;
	struct sniff_info *si;
	int i = 0;
	int l_nr = 0;
	
	list_iter_set(&li, &l_sniff_db);
	while ((si = list_iter_get(&li))) {
		sniff_item_print(stdout, i++, si);
		if (++l_nr % lines_o == 0)
			lines_o_press_key();
		if (all)
			sniff_item_log_print(stdout, &l_nr, si);
	}
	list_iter_end(&li);
}

	
static void sniff_add_item(void)
{
	char buf[BUFSIZE], *buf_p;
	char file_name[BUFSIZE], file_name_buf[BUFSIZE];
	struct sniff_info *si;
	unsigned int src_ip, dst_ip;
	int src_mask, dst_mask;
	int src_ports[MAX_PORTS + 1], dst_ports[MAX_PORTS + 1];
	int srch_mode, len;
	int log_mode, log_bytes;
	int nr;
	FILE *f;
	
	if (menu_choose_host_mask_ports_dfl("src ip addr/mask ports", &src_ip,
			&src_mask, src_ports, 0, 0, NULL) < 0)
		return;
	if (menu_choose_host_mask_ports_dfl("dst ip addr/mask ports", &dst_ip,
			&dst_mask, dst_ports, 0, 0, NULL) < 0)
		return;
	buf_p = NULL;
	srch_mode = 'b';
	switch (menu_choose_char("want to search for y/n", "yn", 'y')) {
	    case 'y':
		if ((srch_mode = menu_choose_sdb("srch_mode", 'b')) == -1)
			return;
		if (menu_choose_string("search for", buf, sizeof(buf), NULL) < 0)
			return;
		buf_p = buf;
		break;
	};
	if ((log_mode = menu_choose_sdb("log mode", 's')) < 0)
		return;
	if ((log_bytes = menu_choose_unr("log bytes", 0, 1000000000, 64)) < 0)
		return;
	if (menu_choose_string("log file name [by conn]", file_name_buf, sizeof(file_name_buf), NULL) < 0)
		file_name_buf[0] = 0;
	if ((nr = menu_choose_unr("insert at", 0, list_count(&l_sniff_db), list_count(&l_sniff_db))) == -1)
		return;

	if (file_name_buf[0]) {
		sprintf(file_name, "%s/%s", SNIFF_FILE_DIR, file_name_buf);
		if (!(f = fopen(file_name, "a+"))) {
			printf("can't open %s for writing\n", file_name);
			return;
		}
	} else
		f = NULL;
	si = malloc(sizeof(struct sniff_info));
	memset(si, 0, sizeof(struct sniff_info));
	pthread_mutex_init(&si->mutex, NULL);
	pthread_cond_init(&si->lock_cond, NULL);
	si->lock_count = 0;
	list_init(&si->log, offset_of(struct sniff_log, next));
	si->src_addr = src_ip;
	si->src_mask = src_mask;
	port_htons(src_ports);
	memcpy(si->src_ports, src_ports, sizeof(int) * (MAX_PORTS + 1));
	si->dst_addr = dst_ip;
	si->dst_mask = dst_mask;
	port_htons(dst_ports);
	memcpy(si->dst_ports, dst_ports, sizeof(int) * (MAX_PORTS + 1));
	si->srch_mode = sdb_to_int(srch_mode);
	
	if (buf_p) {
		len = strlen(buf_p) + 1;
		si->search = malloc(len);
		assert(si->search);
		memcpy(si->search, buf_p, len);
	}
	si->log_mode = sdb_to_int(log_mode);
	si->log_bytes = log_bytes;
	if (f) {
		si->file = f;
		si->file_close = 1;
	} else
		si->file_close = 0;
	list_insert_at(&l_sniff_db, nr, si);
}

static void sniff_mod_item(void)
{
	char buf[BUFSIZE], *buf_p;
	struct sniff_info *si;
	struct sniff_log *slog;
	unsigned int src_ip, dst_ip;
	int src_mask, dst_mask;
	int src_ports[MAX_PORTS + 1], dst_ports[MAX_PORTS + 1];
	int srch_mode, len;
	int log_mode, log_bytes;
	int nr;
	
	sniff_list_db(0);
	if ((nr = menu_choose_unr("choose item", 0, list_count(&l_sniff_db) - 1, list_count(&l_sniff_db) - 1)) == -1)
		return;
	if (!(si = list_at(&l_sniff_db, nr)))
		return;
	if (menu_choose_host_mask_ports_dfl("src ip addr/mask ports",
			    &src_ip, &src_mask, src_ports,
			    si->src_addr, si->src_mask, si->src_ports) < 0)
		return;
	if (menu_choose_host_mask_ports_dfl("dst ip addr/mask ports", 
			    &dst_ip, &dst_mask, dst_ports,
			    si->dst_addr, si->dst_mask, si->dst_ports) < 0)
		return;
	buf_p = NULL;
	srch_mode = 'b';
	switch (menu_choose_char("want to search for y/n", "yn", 'y')) {
	    case 'y':
		if ((srch_mode = menu_choose_sdb("srch_mode", int_to_sdb(si->srch_mode))) < 0)
			return;
		if (menu_choose_string("search for", buf, sizeof(buf), si->search) < 0)
			return;
		buf_p = buf;
		break;
	};
	if ((log_mode = menu_choose_sdb("log mode", int_to_sdb(si->log_mode))) < 0)
		return;
	if ((log_bytes = menu_choose_unr("log bytes", 0, 1000000000, si->log_bytes)) < 0)
		return;

	port_htons(src_ports);
	port_htons(dst_ports);

	list_lock(&l_sniff_db);
	pthread_mutex_lock(&si->mutex);
	while (si->lock_count > 0)
		pthread_cond_wait(&si->lock_cond, &si->mutex);
	while ((slog = list_pop(&si->log)))
		free_sniff_log(slog);
	si->src_addr = src_ip;
	si->src_mask = src_mask;
	memcpy(si->src_ports, src_ports, sizeof(int) * (MAX_PORTS + 1));
	si->dst_addr = dst_ip;
	si->dst_mask = dst_mask;
	memcpy(si->dst_ports, dst_ports, sizeof(int) * (MAX_PORTS + 1));
	si->srch_mode = sdb_to_int(srch_mode);
	if (buf_p) {
		free(si->search);
		len = strlen(buf_p) + 1;
		si->search = malloc(len);
		assert(si->search);
		memcpy(si->search, buf_p, len);
	}
	si->log_mode = sdb_to_int(log_mode);
	si->log_bytes = log_bytes;
	pthread_mutex_unlock(&si->mutex);
	list_unlock(&l_sniff_db);
}

static void sniff_del_item(void)
{
	int i;
	struct sniff_info *si;
	
	sniff_list_db(0);
	i = menu_choose_unr("item nr. to delete", 0, 
			   list_count(&l_sniff_db) - 1, -1);
	if (i >= 0) {
		list_lock(&l_sniff_db);
		si = list_remove_at(&l_sniff_db, i);
		sniff_info_wait_for_release(si);
		free_sniff_info(si);
		list_unlock(&l_sniff_db);
	}
}

void newline_option(void)
{
	switch (menu_choose_char("Print newline,... as newline,...", "yn", 
				 o_newline ? 'y' : 'n')) {
	    case 'y':
		o_newline = 1;
		break;
	    case 'n':
		o_newline = 0;
		break;
	    default:
		break;
	}
}

void sniff_options(void)
{
	char *o_menu = "n) print new line,... as new line,...\n"
		       "x) return\n";
	char *o_keys = "nx";
	int run_it;
	
	run_it = 1;
	while (run_it) {
		switch (menu("sniff options", o_menu, "sniffopt", o_keys, 0)) {
		    case 'n':
			newline_option();
			break;
		    case 'x':
			run_it = 0;
			break;
		}
	}
}

void sniff_menu(void)
{
	char *r_menu =  "s/k)   start/stop sniff daemon\n"
			"l)     list sniff database   c) list sniff connection\n"
			"a/m/d) add/mod/del sniff item\n"
			"o)     options\n"
			"x)     return\n";
	char *r_keys = "sklcamdox";
	int run_it;
	
	run_it = 1;
	while (run_it) {
		switch (menu("sniff daemon", r_menu, "sniff", r_keys, 0)) {
		    case 's':
			start_sniff();
			break;
		    case 'k':
			stop_sniff();
			break;
		    case 'l':
			sniff_list_db(0);
			break;
		    case 'c':
			sniff_list_db(1);
			break;
		    case 'a':
			sniff_add_item();
			break;
		    case 'm':
			sniff_mod_item();
			break;
		    case 'd':
			sniff_del_item();
			break;
		    case 'o':
			sniff_options();
			break;
		    case 'x':
			run_it = 0;
			break;
		}
	}
}
