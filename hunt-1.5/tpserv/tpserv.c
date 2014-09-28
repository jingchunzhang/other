/*
 *
 *	This is free software. You can redistribute it and/or modify under
 *	the terms of the GNU General Public License version 2.
 *
 * 	Copyright (C) 1999 by kra
 *
 */
#include <sys/types.h>
#include <sys/time.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <stdlib.h>
#include <signal.h>
#include <string.h>
#include <errno.h>
#include <stdio.h>
#include <fcntl.h>
#include <stdarg.h>
#include <syslog.h>

/*
 * listen by default on this port
 */
int serv_port = 7044;

#define TPSERV_VERSION	"0.5"
#define BUFSIZE		1460

char *prog_name = NULL;
int is_daemon = 0;
int verbose = 0;
int tpserv_connect = 0;

static int writen(int fd, char *ptr, int nbytes)
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

static int max(int v1, int v2)
{
	return v1 > v2 ? v1 : v2;
}

static void log(int level, int pid, char *format, ...)
{
	char buf[BUFSIZE];
	va_list va;
	FILE *f;
	
	va_start(va, format);
	if (verbose > 1) {
		if (level <= LOG_ERR)
			f = stderr;
		else
			f = stdout;
		fprintf(f, "%5d: ", pid);
		vfprintf(f, format, va);
		fputc('\n', f);
	} else {
		vsnprintf(buf, sizeof(buf), format, va);
		syslog(level, "%s", buf);
	}
	va_end(va);
}
		
static char *print_connection(struct sockaddr_in *from_addr, struct sockaddr_in *to_addr)
{
	static char buf[BUFSIZE];
	char *p;
	
	p = buf;
	p += sprintf(p, "from %s:%d", inet_ntoa(from_addr->sin_addr), ntohs(from_addr->sin_port));
	p += sprintf(p, " to %s:%d", inet_ntoa(to_addr->sin_addr), ntohs(to_addr->sin_port));
	return buf;
}


static void print_read(int pid, struct sockaddr_in *from_addr, struct sockaddr_in *to_addr, int len)
{
	if (verbose <= 1)
		return;
	log(LOG_DEBUG, pid, "read  %4d bytes %s", len, print_connection(from_addr, to_addr));
}

static void print_write(int pid, struct sockaddr_in *from_addr, struct sockaddr_in *to_addr, int len)
{
	if (verbose <= 1)
		return;
	log(LOG_DEBUG, pid, "write %4d bytes %s", len, print_connection(from_addr, to_addr));
}

static void print_connect(int pid, struct sockaddr_in *from_addr, struct sockaddr_in *to_addr)
{
	if (!verbose)
		return;
	log(LOG_DEBUG, pid, "connect          %s", print_connection(from_addr, to_addr));

}

static void print_disconnect(int pid, struct sockaddr_in *from_addr, struct sockaddr_in *to_addr)
{
	if (!verbose)
		return;
	log(LOG_DEBUG, pid, "disconnect       %s", print_connection(from_addr, to_addr));
}

#if 0
static void *memfind(const void *dst, int t_len, const void *src, int m_len)
{
        int i;
	const char *t = dst, *m = src;
	
        for (i = t_len - m_len + 1 ; i > 0; i--, t++)
                if (t[0] == m[0] && memcmp(t, m, m_len) == 0)
                        return (void *) t;
        return 0;
}
#endif

static void process_request_echo(int fd, int pid, struct sockaddr_in *from_addr, struct sockaddr_in *to_addr)
{
	char buf[BUFSIZE];
	int len;
	
	while ((len = read(fd, buf, sizeof(buf))) > 0) {
		print_read(pid, from_addr, to_addr, len);
		if (writen(fd, buf, len) != len)
			break;
		print_write(pid, to_addr, from_addr, len);
	}
}

static void process_request_connect(int fd, int pid, struct sockaddr_in *from_addr, struct sockaddr_in *to_addr)
{
	char buf[BUFSIZE];
	struct sockaddr_in local_addr;
	int to_addr_len, local_addr_len;
	fd_set rset;
	int maxfd, len;
	int fd_remote;
	
	if ((fd_remote = socket(AF_INET, SOCK_STREAM, 0)) < 0) {
		log(LOG_ERR, pid, "socket failed %d:%s\n", errno, strerror(errno));
		exit(1);
	}
	to_addr_len = sizeof(*to_addr);
	if (connect(fd_remote, to_addr, to_addr_len) < 0) {
		log(LOG_ERR, pid, "failed to connect to remote addr\n");
		exit(1);
	}
	local_addr_len = sizeof(local_addr);
	if (getsockname(fd_remote, (struct sockaddr *) &local_addr, &local_addr_len) < 0) {
		log(LOG_ERR, pid, "getpeername failed %d:%s\n", errno, strerror(errno));
		exit(1);
	}

	while (1) {
		FD_ZERO(&rset);
		FD_SET(fd, &rset);
		FD_SET(fd_remote, &rset);
		maxfd = max(fd, fd_remote) + 1;
		if (select(maxfd, &rset, NULL, NULL, NULL) > 0) {
			/*
			 * from/to client to server (as)
			 */
			if (FD_ISSET(fd, &rset)) {
				if ((len = read(fd, buf, sizeof(buf))) > 0) {
					print_read(pid, from_addr, to_addr, len);
					if (writen(fd_remote, buf, len) != len)
						return;
					print_write(pid, &local_addr, to_addr, len);
				} else /* read eof or error */
					return;
			}
			/*
			 * from/to as to true destination server
			 */
			if (FD_ISSET(fd_remote, &rset)) {
				if ((len = read(fd_remote, buf, sizeof(buf))) > 0) {
					print_read(pid, to_addr, &local_addr, len);
					/*
					 * here we can modify/insert something to the data stream
					 * instaed of plain writen
					 */
					if (writen(fd, buf, len) != len)
						return;
					print_write(pid, to_addr, from_addr, len);
				} else /* read eof or error */
					return;
			}
		}
	}
}

void serv_slave(int fd, int pid)
{
	struct sockaddr_in to_addr, from_addr;
	int to_addr_len, from_addr_len;
	
	to_addr_len = sizeof(to_addr);
	memset(&to_addr, 0, sizeof(to_addr));
	if (getsockname(fd, (struct sockaddr *) &to_addr, &to_addr_len) < 0) {
		log(LOG_ERR, pid, "getsockname failed %d:%s\n", errno, strerror(errno));
		exit(1);
	}
	from_addr_len = sizeof(from_addr);
	memset(&from_addr, 0, sizeof(from_addr));
	if (getpeername(fd, (struct sockaddr *) &from_addr, &from_addr_len) < 0) {
		log(LOG_ERR, pid, "getpeername failed %d:%s\n", errno, strerror(errno));
		exit(1);
	}
	print_connect(pid, &from_addr, &to_addr);

	if (tpserv_connect)
		process_request_connect(fd, pid, &from_addr, &to_addr);
	else
		process_request_echo(fd, pid, &from_addr, &to_addr);
	

	close(fd);
	print_disconnect(pid, &from_addr, &to_addr);
}

void usage(const char *name)
{
	printf("usage: %s [-V] [-v] [-h] [-D] [-c] [-p port]\n", name);
	exit(1);
}

int main(int argc, char *argv[])
{
	struct sockaddr_in servaddr, cliaddr;
	struct sigaction sa;
	int lfd, clifd;
	int child_pid;
	int clilen, c;
	int on = 1;
	char *tmp;

	if ((prog_name = rindex(argv[0], '/')) == NULL)
		prog_name = argv[0];
	else
		prog_name++;
	
	while ((c = getopt(argc, argv, "p:h?vVDc")) != EOF) {
		switch (c) {
		    case 'p':
			serv_port = strtoul(optarg, &tmp, 0);
			if (*tmp) {
				fprintf(stderr, "bad: -p %s\n", optarg);
				exit(1);
			}
			break;
		    case 'V':
			printf("%s: version %s", prog_name, TPSERV_VERSION);
			exit(0);
		    case 'v':
			verbose++;
			break;
		    case 'D':
			is_daemon = 1;
			break;
		    case 'c':
			tpserv_connect = 1;
			break;
		    case 'h':
		    case '?':
		    default:
			usage(prog_name);
		}
	}
	
	memset(&sa, 0, sizeof(struct sigaction));
#ifdef SA_NOCLDWAIT
	sa.sa_flags = SA_NOCLDWAIT;
#endif
#if 0
	sa.sa_flags |= SA_NOCLDSTOP;
#endif
	sa.sa_handler = SIG_IGN;
	if (sigaction(SIGCHLD, &sa, NULL) < 0) {
		fprintf(stderr, "sigaction failed %d:%s\n", errno, strerror(errno));
		exit(1);
	}
	
	if ((lfd = socket(AF_INET, SOCK_STREAM, 0)) < 0) {
		fprintf(stderr, "socket failed %d:%s\n", errno, strerror(errno));
		exit(1);
	}
	if (setsockopt(lfd, SOL_SOCKET, SO_REUSEADDR, (char *) &on, sizeof(on)) < 0) {
		fprintf(stderr, "setsockopt failed %d:%s\n", errno, strerror(errno));
		exit(1);
	}
	if (setsockopt(lfd, SOL_SOCKET, SO_KEEPALIVE, (char *) &on, sizeof(on)) < 0) {
		fprintf(stderr, "setcoskopt failed %d:%s\n", errno, strerror(errno));
		exit(1);
	}
	memset(&servaddr, 0, sizeof(servaddr));
	servaddr.sin_family = AF_INET;
	servaddr.sin_addr.s_addr = htonl(INADDR_ANY);
	servaddr.sin_port = htons(serv_port);
	
	if (bind(lfd, (struct sockaddr *) &servaddr, sizeof(servaddr)) < 0) {
		fprintf(stderr, "bind failed %d:%s\n", errno, strerror(errno));
		exit(1);
	}
	if (listen(lfd, 10) < 0) {
		fprintf(stderr, "listen failed %d:%s\n", errno, strerror(errno));
		exit(1);
	}

	if (is_daemon) {
		daemon(0, 0);
		openlog(prog_name, LOG_PID, LOG_DAEMON);
	}
	if (verbose)
		log(LOG_DEBUG, getpid(), "ready");

	for (;;) {
		clilen = sizeof(cliaddr);
		do {
			clifd = accept(lfd, (struct sockaddr *) &cliaddr, &clilen);
		} while (clifd < 0 && errno == EINTR);
		if (clifd < 0) {
			log(LOG_ERR, getpid(), "accept failed %d:%s", errno, strerror(errno));
			exit(1);
		}
		if ((child_pid = fork()) == 0) {
			/* slave */
			close(lfd);
			serv_slave(clifd, getpid()); /* closes clifd */
			exit(0);
		} else if (child_pid > 0) {
			/* parent */
			close(clifd);
		} else {
			/* fork error - ignore */
			close(clifd);
		}
	}
}

