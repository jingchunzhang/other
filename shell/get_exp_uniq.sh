#!/bin/sh

if [ $# -ne 2 ]
then
	echo " Usage get_uniq.sh indir outdir!"
	exit;
fi

for day in "09 10 11 12 13 14 15 16"
do
	outfile=$2/$day.expu

	echo "ls $1/* |grep -v $day| xargs cat $file | sort -u -T $1 > $outfile" |sh &
done
