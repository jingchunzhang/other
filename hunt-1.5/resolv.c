#include "hunt.h"
#include <sys/types.h>
#include <sys/time.h>
#include <sys/wait.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <signal.h>
#include <assert.h>
#include "c/hash.h"

#define CHECK_INTERVAL  (10)
#define RESOLV_ITEM_LIVETIME (20 * 60)
#define RESOLV_ITEM_REFRESH  (RESOLV_ITEM_LIVETIME / 2)

struct hash ip_to_name_table;
int hl_mode = 0;

struct req {
	unsigned int ip;
	struct req   *next;	/* doesn't used if passed through pipe */
};

struct res {
	int  		err;
	unsigned int 	ip;
	int  		name_len;
	char 		name[0];	/* little trick, see later */
};

struct slave {
	struct req 	s_req;
	time_t 		s_timestamp;
	pid_t  		s_pid;
	int    		s_fd;
	struct slave	*s_next;
};


#define MAX_SLAVES	5
#define SLAVE_MAX_IDLE	(1 * 60)

static int   fd_req = -1;	/* pipe to resolver daemon */
static pid_t pid_req = 0;	/* pid of resolver daemon */
static pid_t pid_parent = 0;

/*
 * operation on hash table
 */
void resolv_remove(unsigned int ip)
{
	struct resolv_item *r;
	
	if ((r = hash_remove(&ip_to_name_table, ip, NULL))) {
		pthread_mutex_lock(&r->mutex);
		if (r->name)
			free(r->name);
		free(r);
	}
}

void resolv_put(unsigned int ip, const char *name)
{
	struct resolv_item *r;
	
	hash_lock(&ip_to_name_table);
	resolv_remove(ip);
	r = malloc(sizeof(struct resolv_item));
	r->name = strdup(name);
	r->put_timestamp = r->get_timestamp = time(NULL);
	pthread_mutex_init(&r->mutex, NULL);
	hash_put(&ip_to_name_table, ip, r);
	hash_unlock(&ip_to_name_table);
}

struct resolv_item *resolv_get(unsigned int ip)
{
	struct resolv_item *r;
	
	hash_lock(&ip_to_name_table);
	if ((r = hash_get(&ip_to_name_table, ip, NULL))) {
		pthread_mutex_lock(&r->mutex);
		r->get_timestamp = time(NULL);
	}
	hash_unlock(&ip_to_name_table);
	return r;
}

void resolv_release(struct resolv_item *r)
{
	pthread_mutex_unlock(&r->mutex);
}

void resolv_request(unsigned int ip)
{
	struct req req;
	struct in_addr addr;
	
	addr.s_addr = ip;
	req.ip = ip;
	req.next = NULL;
	write(fd_req, &req, sizeof(struct req));
	resolv_put(ip, inet_ntoa(addr)); /* ok, will be changed after request is processed */
}

static void check_interval(int __time)
{
	struct hash_iterator li;
	struct resolv_item *r;
	unsigned int ip;
	
	hash_lock(&ip_to_name_table);
	hash_iter_set(&li, &ip_to_name_table);
	while ((r = hash_iter_get(&li, &ip))) {
		if (r->put_timestamp + RESOLV_ITEM_LIVETIME < __time)
			resolv_remove(ip);
		else if (r->get_timestamp - r->put_timestamp >= RESOLV_ITEM_REFRESH)
			resolv_request(ip);
	}
	hash_iter_end(&li);
	hash_unlock(&ip_to_name_table);
}

static void *update_thr(void *arg)
{
	struct timeval timeout;
	fd_set rdset;
	int fd = (int) arg;
	struct res r;
	char buf[256];
	int update_thr_run;
	int retval;
	time_t __time;
	time_t last_time_check;
	
	pthread_sigmask(SIG_BLOCK, &intr_mask, NULL);
	if (verbose)
		printf("update resolv thread pid %d\n", getpid());
	setpriority(PRIO_PROCESS, getpid(), 10);
	update_thr_run = 1;
	last_time_check = 0;
	while (update_thr_run && pthread_kill(main_thread_id, 0) == 0) {
		FD_ZERO(&rdset);
		FD_SET(fd, &rdset);
		timeout.tv_sec = min(CHECK_INTERVAL, 10);
		timeout.tv_usec = 0;
		retval = select(fd + 1, &rdset, NULL, NULL, &timeout);
		if (retval > 0 && FD_ISSET(fd, &rdset) && 
		    read(fd, &r, sizeof(struct res)) == sizeof(struct res)) {
			if (r.err == 0 && r.name_len) {
				if (read(fd, buf, r.name_len) != r.name_len)
					printf("bad read of len in update thr\n");
				buf[r.name_len] = 0;
				resolv_put(r.ip, buf);
			}
		}
		__time = time(NULL);
		if (last_time_check + CHECK_INTERVAL < __time) {
			check_interval(__time);
			last_time_check = __time;
		}	
	}
	return NULL;
}

/*
 * daemon/slaves for resolving
 */
static volatile int resolv_slave_run;
static void sig_slave_term(int signum)
{
	resolv_slave_run = 0;
}

static void resolv_slave(int fd)
{
	struct sigaction sa;
	struct in_addr addr;
	struct hostent *host_ent;
	struct timeval timeout;
	char buf[256];
	struct res *res;
	struct req req;
	char *name;
	fd_set rdset;
	int retval;
	
	setpriority(PRIO_PROCESS, getpid(), 10);
	resolv_slave_run = 1;
	sa.sa_handler = sig_slave_term;
	sigemptyset(&sa.sa_mask);
	sa.sa_flags = SA_RESTART;
	sigaction(SIGTERM, &sa, NULL);

	while (resolv_slave_run && getppid() != 1) {
		FD_ZERO(&rdset);
		FD_SET(fd, &rdset);
		timeout.tv_sec = 10;
		timeout.tv_usec = 0;
		retval = select(fd + 1, &rdset, NULL, NULL, &timeout);
		if (retval > 0 && FD_ISSET(fd, &rdset) &&
		    read(fd, &req, sizeof(struct req)) == sizeof(struct req)) {
			addr.s_addr = req.ip;
			host_ent = NULL;
			host_ent = gethostbyaddr((char *)&addr, sizeof(struct in_addr),
						 AF_INET);
			res = (struct res *) buf;
			if (!host_ent) {
				/* name = inet_ntoa(addr); */
				res->err = 1;
				res->ip = req.ip;
				res->name_len = 0;
			} else {
				name = host_ent->h_name;
				/* make sure write is atomic - dont use several writes 
				 * the kernel garantie atomicity to  1024B */
				res->err = 0;
				res->ip = req.ip;
				res->name_len = strlen(name) + 1;
				strcpy(res->name, name);
				assert((void *) res->name == (void *)(res + 1));
			}
			write(fd, res, sizeof(struct res) + res->name_len);
		}
	}
	close(fd);
	exit(0);
}


static volatile int resolv_daemon_run;
static void sig_term(int signum)
{
	resolv_daemon_run = 0;
}

static void send_req_to_slave(int fd, struct list *slaves, struct list *requests)
{
	struct list_iterator li;
	struct slave *sl;
	struct req *r;
	struct req req;
	int pipe[2];

	list_iter_set(&li, slaves);
	while (list_count(requests) && (sl = list_iter_get(&li))) {
		if (sl->s_req.ip == 0) {
			r = list_pop(requests);
			sl->s_req = *r;
			sl->s_req.next = NULL;
			sl->s_timestamp = time(NULL);
			req = *r;
			req.next = NULL;
			write(sl->s_fd, &req, sizeof(struct req));
			free(r);
		}
	}
	list_iter_end(&li);
	while (list_count(requests) && list_count(slaves) < MAX_SLAVES) {
		r = list_pop(requests);
		sl = malloc(sizeof(struct slave));
		sl->s_req = *r;
		sl->s_timestamp = time(NULL);
		req = *r;
		free(r);
		socketpair(AF_UNIX, SOCK_STREAM, 0, pipe);
		sl->s_fd = pipe[0];
		if ((sl->s_pid = fork()) == 0) {
			/* slave */
			close(pipe[0]);
			close(fd);
			list_iter_set(&li, slaves);
			while ((sl = list_iter_get(&li)))
				close(sl->s_fd);
			list_iter_end(&li);
			resolv_slave(pipe[1]);
			exit(0);
		} else if (sl->s_pid > 0) {
			/* parent */
			close(pipe[1]);
			list_enqueue(slaves, sl);
			write(sl->s_fd, &req, sizeof(struct req));
		} else
			printf("err launching dns slave\n");
	}
}

static void remove_idle_slaves(struct list *slaves)
{
	struct list_iterator li;
	struct slave *sl;
	time_t cur_time;
	
	cur_time = time(NULL);
	list_iter_set(&li, slaves);
	while ((sl = list_iter_get(&li))) {
		if (sl->s_req.ip == 0 && 
		    sl->s_timestamp + SLAVE_MAX_IDLE < cur_time) {
			kill(sl->s_pid, SIGTERM);
			waitpid(sl->s_pid, NULL, 0);
			close(sl->s_fd);
			list_remove(slaves, sl);
			free(sl);
		}
	}
	list_iter_end(&li);
}

static void cleanup_slaves(struct list *slaves)
{
	struct list_iterator li;
	struct slave *sl;

	list_iter_set(&li, slaves);
	while ((sl = list_iter_get(&li)))
		kill(sl->s_pid, SIGTERM);
	list_iter_end(&li);
	list_iter_set(&li, slaves);
	while ((sl = list_iter_get(&li)))
		waitpid(sl->s_pid, NULL, 0);
	list_iter_end(&li);
	while ((sl = list_pop(slaves)))
		free(sl);
}

static void handle_response(int fd, struct slave *sl)
{
	char buf[256];
	struct res *res;
	
	res = (struct res *) buf;
	if (read(sl->s_fd, buf, sizeof(struct res)) == sizeof(struct res)) {
		if (res->name_len)
			read(sl->s_fd, res + 1, res->name_len);
		if (res->err == 0) {
			write(fd, buf, sizeof(struct res) + res->name_len);
		}
		sl->s_req.ip = 0;
		sl->s_timestamp = time(NULL);
	}
}

static void resolv_daemon(int fd)
{
	struct list_iterator li;
	struct sigaction sa;
	struct req req;
	struct list slaves = LIST_INIT(struct slave, s_next);
	struct list requests = LIST_INIT(struct req, next);
	struct req *r;
	fd_set select_fd;
	int select_max;
	struct timeval timeout;
	struct slave *sl;
	int retval;

	if (verbose)
		printf("resolv daemon pid %d\n", getpid());
	setpriority(PRIO_PROCESS, getpid(), 10);
	resolv_daemon_run = 1;
	sa.sa_handler = sig_term;
	sigemptyset(&sa.sa_mask);
	sa.sa_flags = SA_RESTART;
	sigaction(SIGTERM, &sa, NULL);

	while (resolv_daemon_run && kill(pid_parent, 0) == 0) {
		FD_ZERO(&select_fd);
		select_max = 0;
		list_iter_set(&li, &slaves);
		while ((sl = list_iter_get(&li))) {
			FD_SET(sl->s_fd, &select_fd);
			select_max = max(select_max, sl->s_fd);
		}
		list_iter_end(&li);
		FD_SET(fd, &select_fd);
		select_max = max(select_max, fd);
		timeout.tv_sec = 10;
		timeout.tv_usec = 0;
		
		retval = select(select_max + 1, &select_fd, NULL, NULL, &timeout);
		if (retval > 0) {
			/* handle responses from clients */
			list_iter_set(&li, &slaves);
			while ((sl = list_iter_get(&li))) {
				if (FD_ISSET(sl->s_fd, &select_fd))
					handle_response(fd, sl);
			}
			list_iter_end(&li);
			
			/* handle requests from hunt */
			if (FD_ISSET(fd, &select_fd)) {
				if (read(fd, &req, sizeof(struct req)) == sizeof(struct req)) {
					r = malloc(sizeof(struct req));
					*r = req;
					list_enqueue(&requests, r);
				}
			}
			send_req_to_slave(fd, &slaves, &requests);
		}
		remove_idle_slaves(&slaves);
	}
	cleanup_slaves(&slaves);
	close(fd);
	exit(0);
}


char *host_lookup(unsigned int in, int use_mode)
{
 	static char hostname_buf[BUFSIZE] = {0};
	static int hostname_idx = 0;
	struct in_addr addr;
	char *name, *retval;
	int len;
	struct hostent *host_ent;
	struct resolv_item *r;
	
	addr.s_addr = in;
	host_ent = NULL;
	
	if (in == 0)
		return inet_ntoa(addr);
	r = NULL;
	switch (use_mode) {
	    case HL_MODE_NAME:
		if (!(r = resolv_get(in))) {
			host_ent = gethostbyaddr((char *)&addr, sizeof(struct in_addr),
						AF_INET);
			if(!host_ent)
		        	name = inet_ntoa(addr);
			else
				name = host_ent->h_name;
		} else
			name = r->name;
		break;
	    case HL_MODE_DEFERRED:
		if (!(r = resolv_get(in))) {
			resolv_request(in);
			name = inet_ntoa(addr);
		} else
			name = r->name;
		break;
	    case HL_MODE_NR:
	    default:
		name = inet_ntoa(addr);
		break;
	}
		
	len = strlen(name);
	if (len + hostname_idx + 1 > sizeof(hostname_buf))
		hostname_idx = 0;
	strcpy((retval = hostname_buf + hostname_idx), name);
	hostname_idx += len + 1;
	if (r)
		resolv_release(r);
	return retval;
}

/*
 * init/done
 */
void resolv_init(void)
{
	int pipe[2];
	pthread_t res_update_thr;

	pid_parent = getppid();
	socketpair(AF_UNIX, SOCK_STREAM, 0, pipe);
	if ((pid_req = fork()) == 0) {
		/* child */
		close(pipe[0]);
		sigprocmask(SIG_BLOCK, &intr_mask, NULL);
		resolv_daemon(pipe[1]);
	} else if (pid_req < 0) {
		printf("dns daemon failed to start - exiting\n");
		exit(1);
	}
	close(pipe[1]);
	fd_req = pipe[0];
	
	hash_init(&ip_to_name_table, 100, NULL);
	pthread_create(&res_update_thr, NULL, update_thr, (void *) fd_req);
}

void resolv_done(void)
{
	kill(pid_req, SIGTERM);
	waitpid(pid_req, NULL, 0);
}


char *port_lookup(unsigned short serv, int use_mode)
{
 	static char servname_buf[BUFSIZE] = {0};
	static int servname_idx = 0;
	char name_buf[64];
	char *name, *retval;
	int len;
	struct servent *serv_ent;

	if (serv == 0)
		return "0";
	
	switch (use_mode) {
	    case HL_MODE_NAME:
	    case HL_MODE_DEFERRED:
		serv_ent = getservbyport(serv, "tcp");
		if(!serv_ent)
		        ; /* go through */
		else {
			name = serv_ent->s_name;
			break;
		}
	    case HL_MODE_NR:
	    default:
		name = name_buf;
		sprintf(name, "%d", ntohs(serv));
		break;
	}
		
	len = strlen(name);
	if (len + servname_idx + 1 > sizeof(servname_buf))
		servname_idx = 0;
	strcpy((retval = servname_buf + servname_idx), name);
	servname_idx += len + 1;
	return retval;
}

unsigned short service_lookup(char *name)
{
	struct servent *serv_ent;

	if (!(serv_ent = getservbyname(name, "tcp")))
		return 0;
	else
		return htons(serv_ent->s_port);
}
