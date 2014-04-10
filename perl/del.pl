#!/usr/bin/perl

if (@ARGV != 6)
{
	printf "Usage del.pl dbfile rfile outfile maxhit isp force!\n";
	exit;
}

$dbfile = shift;
$rfile = shift;
$ofile = shift;
$maxhit = shift;
$isp = shift;
$force = shift;

if (!open dbfile, "< $dbfile") {
	die "$!";
}

if (!open rfile, "< $rfile") {
	die "$!";
}

if (!open ofile, "> $ofile") {
	die "$!";
}

%hash = ();

while (<rfile>) {
	chomp;
	s/^\s+//;   # ������ͷ�Ŀհ�
	s/\s+$//;   # ������β�Ŀհ�
	s/\s+/ /g;   # ѹ���ڲ��Ŀհ�

	my @c = split (/ /, $_);
	$hash{$c[-1]} = $c[0];
}
close rfile;

$len = length("/home/webadm/htdocs");

while (<dbfile>) {
	chomp;
	my @c = split (/\t/, $_);
	my $index = index($c[-1], "/home/webadm/htdocs");
	next if ($index < 0);

	my $f = substr($c[-1], $index + $len);
	my $key = "/".$c[0].$f;
	my $val = $hash{$key};
	if ($val eq undef || $val < $maxhit)
	{
		$key = substr($key, 1);
		if ($force)
		{
			print ofile "wget \"http://10.26.80.214:49716/&delfile=$key&deltype=$isp&force\"\n";
		}
		else
		{
			print ofile "wget \"http://10.26.80.214:49716/&delfile=$key&deltype=$isp\"\n";
		}
		next;
	}
}
close dbfile;

