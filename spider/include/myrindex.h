#ifndef MY_RINDEX_H_
#define MY_RINDEX_H_
#include "myshm.h"

int setrindex(int index, char *text);  /*index:hashindex; text:appname&appdesc*/
/*setrindex ���Զ��ִ�text������rindex��index��¼text������hash��λ��*/

int getrindex(char *subtext);
/*getrindex, ��ȡsubtext��rindex��λ��*/

#endif
