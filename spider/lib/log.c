#include "log.h"
#define MAX_LOG_LEN 512
void wlog(int fd, int level, const char* fmt, ...) 
{
	if (level < loglevel)
		return ;
	int l;
	char buf[MAX_LOG_LEN];
    struct tm tmm; 
	time_t now = time(NULL);
	localtime_r(&now, &tmm);  
	l = snprintf(buf, MAX_LOG_LEN - 1, "[%04d-%02d-%02d %02d:%02d:%02d]", tmm.tm_year + 1900, tmm.tm_mon + 1, tmm.tm_mday, tmm.tm_hour, tmm.tm_min, tmm.tm_sec);

	va_list ap;
	va_start(ap, fmt);
	l += vsnprintf(buf + l, MAX_LOG_LEN - l - 1, fmt, ap);
	va_end(ap);
	
	write(fd, buf, l);
}

