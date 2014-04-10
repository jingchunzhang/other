#include <stdio.h>
#include <dirent.h>
#include <errno.h>
#include <string.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <sys/time.h>
#include <unistd.h>
#include <stdlib.h>
#include <string.h>
#include <fcntl.h>
#include "netdata.h"
#include "i_conv.h"
#define TIME_OUT 2
#define ID __FILE__
#define LN __LINE__


int parseend(char *inbuf, int *contenlen)
{
	char *p = strstr(inbuf, "\r\n\r\n");
	if (!p)
		return -1;

	int retlen = p + 4 - inbuf;

	p = strstr(inbuf, "Content-Length:");
	if (!p)
		p = strstr(inbuf, "Content-length:");

	if (!p)
		return -2;

	p += strlen("Content-length: ");
	char *e = strstr(p, "\r\n");
	if (!e)
		return -3;
	*e = 0x0;
	*contenlen = atoi(p);
	*e = '\r';
	return retlen;
}

int gethttphead(char *buf, char *domain, char *myurl)
{
	char *tmp = buf;
	int len = 0;
	len = sprintf(tmp, "GET %s HTTP/1.1\r\n", myurl);
	tmp += len;
	len = sprintf(tmp, "Accept: text/html, application/xhtml+xml, */*\r\n");
	tmp += len;
	len = sprintf(tmp, "Referer: http://%s\r\n", domain);
	tmp += len;
	len = sprintf(tmp, "Accept-Language: UTF-8\r\n");
	tmp += len;
	len = sprintf(tmp, "Accept-Encoding: deflate\r\n");
	tmp += len;
	len = sprintf(tmp, "User-Agent: Mozilla/5.0 (compatible; MSIE 9.0; Windows NT 6.1; Trident/5.0)\r\n");
	tmp += len;
	len = sprintf(tmp, "Content-Type: application/x-www-form-urlencoded\r\n");
	tmp += len;
	len = sprintf(tmp, "Host: %s\r\n", domain);
	tmp += len;
	len = sprintf(tmp, "Connection: close\r\n");
	tmp += len;
	len = sprintf(tmp, "Cache-Control: no-cache\r\n");
	tmp += len;
	len = sprintf(tmp, "\r\n");
	tmp += len;
	return tmp - buf ;
}

int createsocket(char *ip, int port)
{
	int					sockfd;
//	struct linger		ling;
	struct sockaddr_in	servaddr;


	sockfd = socket(AF_INET, SOCK_STREAM, 0);
	if (sockfd < 0)
	{
		fprintf(stderr, "socket error %s\n", strerror(errno));
		return -1;
	}

	memset(&servaddr, 0, sizeof(servaddr));
	servaddr.sin_family = AF_INET;
	servaddr.sin_port = htons(port);
	inet_pton(AF_INET, ip, &servaddr.sin_addr);

	int rc = connect(sockfd, (struct sockaddr *) &servaddr, sizeof(servaddr));
	if (rc)
	{
		fprintf(stderr, "connect error %s\n", strerror(errno));
		return -1;
	}
	return sockfd;
}

int recvdata(int sockfd, char *outbuf)
{
	//	fprintf(stdout, "start recvdata!\n");
	int rc = 0;
	char rcvbuf[1024];
	char *p = outbuf;
	int maxfd;
	int rcvlen;
	int headok = 0;
	int head_len = 0;
	int content_len;
	fd_set rset;
	for ( ; ; ) 
	{
		FD_ZERO(&rset);
		FD_SET(sockfd, &rset);
		struct timeval tv;
		tv.tv_sec = 10;
		maxfd = sockfd+1;
		rc = select(maxfd, &rset, NULL, NULL, &tv);
		if (rc == 0)
		{
			fprintf(stderr, "select time out %s\n", strerror(errno));
			return TIME_OUT;
		}
		if(rc < 0)
		{
			fprintf(stderr, "select error %s\n", strerror(errno));
			rc = -1;
			break;
		}
		if (FD_ISSET(sockfd, &rset)) 
		{
			memset(rcvbuf, 0, sizeof(rcvbuf));
			rcvlen = recv(sockfd, rcvbuf, sizeof(rcvbuf), O_NONBLOCK);
			if (rcvlen == 0)
			{
				break;
			}
			if (rcvlen < 0)
			{
				if(errno == EINTR || errno == EAGAIN)
					continue;
				fprintf(stderr, "select error %s %s %d\n", strerror(errno), ID, LN);
				rc = -1;
				break;
			}
			//fprintf(stdout, "start recvdata[%s]\n", rcvbuf);
			memcpy(p, rcvbuf, rcvlen);
			if (headok == 0)
			{
				head_len = parseend(outbuf, &content_len);
				if (head_len >0)
				{
					headok = 1;
					//		fprintf(stdout, "head_len %d c_len %d %d %d\n", head_len, content_len, rcvlen, p - outbuf);
				}
			}
			p += rcvlen;
		}
		if (headok)
		{
			//	fprintf(stdout, "XXX head_len %d c_len %d %d %d\n", head_len, content_len, rcvlen, p - outbuf);
			if (p - outbuf == head_len + content_len)
				break;
		}
	}
	if (headok == 1)
		rc = 0;
	return rc;
}

int get_ip_by_domain(char *serverip, char *domain)
{
	char                    *ptr, **pptr;
	char                    str[128] = {0x0};
	struct hostent  *hptr;

	ptr = domain;
	if ( (hptr = gethostbyname(ptr)) == NULL) {
		return -1;
	}

	switch (hptr->h_addrtype) {
		case AF_INET:
#ifdef  AF_INET6
		case AF_INET6:
#endif
			pptr = hptr->h_addr_list;
			for ( ; *pptr != NULL; pptr++)
			{
				inet_ntop(hptr->h_addrtype, *pptr, str, sizeof(str));
				strcpy(serverip, str);
				return 0;
			}
			break;

		default:
			return -1;
			break;
	}
	return -1;
}

int getdata(char *domain, char *url, char *data)
{

	char head[1024] = {0x0};
	char ip[128] = {0x0};
	if (get_ip_by_domain(ip, domain))
	{
		fprintf(stderr, "get_ip_by_domain error %s", strerror(errno));
		return -1;
	}
	int headlen = gethttphead(head, domain, url);
//	fprintf(stderr, "[%s]\n", head);

	int repeat = 0;
	int sockfd;
repeat_send:
	sockfd = createsocket(ip, 80);
	if (sockfd < 0)
	{
		fprintf(stderr, "createsocket error %s", strerror(errno));
		return -1;
	}

	int sendlen = send(sockfd, head, headlen, O_NONBLOCK);
	int rc = recvdata(sockfd, data);
	close (sockfd);
	if (rc == TIME_OUT)
	{
		repeat++;
		if (repeat < 3)
		{
			sleep (3);
			goto repeat_send;
		}
	}
	return rc;
}
