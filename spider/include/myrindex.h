#ifndef MY_RINDEX_H_
#define MY_RINDEX_H_
#include "myshm.h"

int setrindex(int index, char *text);  /*index:hashindex; text:appname&appdesc*/
/*setrindex 会自动分词text，建立rindex，index记录text在数据hash的位置*/

int getrindex(char *subtext);
/*getrindex, 获取subtext在rindex的位置*/

#endif
