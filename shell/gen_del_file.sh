#!/bin/sh

if [ $# -ne 1 ]
then
	echo "Usage `basename $0` indir"
	exit
fi

for file in $1/*d
do
	idx=`echo $file | awk -F\/ '{print $NF}' |awk -F\. '{print substr($1, 2)}'`
	domain=fcs$idx.56.com
	cat $file |grep qvga.mp4|awk -v dmain=$domain '{suffix=substr($0, 20); print "http://10.26.80.214:49716/&delfile="dmain""suffix"&deltype=all"}'
done
