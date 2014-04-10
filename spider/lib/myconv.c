#include <unistd.h>
#include <stdio.h>
#include <sys/types.h>
#include <iconv.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <string.h>
#include <errno.h>
#include <stdlib.h>

int convert(const char *fromset,const char *toset,char *from,size_t from_len,char *to,size_t *to_len)
{
	iconv_t cd;
	cd=iconv_open(toset,fromset);
	if (cd == (iconv_t)(-1))
	{
		fprintf(stderr, "iconv err %m\n");
		return -1;
	}
	char **from2=&from;
	char **to2=&to;
	if(iconv(cd, from2, &from_len, to2,to_len)==-1)
	{
		fprintf(stderr, "iconv err %m\n");
		iconv_close(cd);
		return -1;
	}
	iconv_close(cd);
	return 0;
}

int main(int argc, char **argv)
{
	if (argc != 2)
	{
		fprintf(stderr, "a.out infile\n");
		return -1;
	}
	char from[1024] = {0x0};
	char to[10240] = {0x0};
	FILE *fp = fopen(argv[1], "r");
	if (!fp)
	{
		fprintf(stderr, "open %s error %s\n", argv[1], strerror(errno));
		return -1;
	}
	while (fgets(from, sizeof(from), fp))
	{
		char *t = strchr(from, '\n');
		if (t)
			*t = 0x0;
		//convert("BIG5","GB2312",from,strlen(from),to,S);  //把gb2312转换成big5
		size_t ol = 10240;
		int ret = convert("utf-8","gbk",from,strlen(from),to, &ol);  //把gb2312转换成big5
		if (ret)
			break;
		printf("%s\n",to);
		memset(from, 0, sizeof(from));
		memset(to, 0, sizeof(to));
	}
	fclose(fp);
	return 0;
}
