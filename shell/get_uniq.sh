#!/bin/sh

if [ $# -ne 2 ]
then
	echo " Usage get_uniq.sh indir outdir!"
	exit;
fi

for file in $1/*
do
	bfile=`basename $file`
	outfile=$2/$bfile

	echo "cat $file | sort -u > $outfile" |sh &
done
