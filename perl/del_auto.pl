#!/usr/bin/perl
#

my $rootdir = "/diska/cdc/auto_rm_cs_file/";

use POSIX 'strftime';
use URI::Escape;

use lib "./lib";
use UrlRequest;
use MyDB;

my $curmon = POSIX::strftime('%Y%m', localtime(time()));
my $curtime = POSIX::strftime('%Y%m%d%H%M%S', localtime(time()));

my $monitor_table = "t_alarm_msg_".$curmon;

my $dellog = $rootdir."dellogfile";

if (!open dellog, ">> $dellog") {
	die "$!";
}

my $csipdir = "/home/syncfile/";
opendir(my $cs, $csipdir) or die "cant opendir $csipdir $!\n";
push @csipfile, (map {sprintf("%s/new_cs_", $_)} grep {!/^\./} readdir $cs);
closedir($cs);

%cshash = ();

sub process_csfile
{
	my $infile = shift;
	my $isp = shift;

	if (!open infile, "< $infile") {
		die "$!";
	}

	while (<infile>)
	{
		chomp;
		my @item = split (/\\t/, $_);
		my @ips = split (/,/, $_);
		foreach my $ip (@ips)
		{
			$cshash{$ip} = $isp;
		}
	}
	close infile;

}

sub do_rm_cs_file
{
	my $ip = shift;
	my $isp = shift;

	print dellog "$curtime process $ip $isp\n";

	my $shellfile = sprintf("%s/%s_60_90", $rootdir, $ip);

	my $cmd = sprintf("sh %s/get_cs_files.sh %s 60 90 %s", $rootdir, $ip, $shellfile);

	system($cmd);

	my $force = 0;
	$force = 1 if (($isp ne "tel") && ($isp ne "cnc")); 

	my $rmfile = sprintf("%s/%s_rm_file", $rootdir, $ip);
	my $perlcmd = sprintf("perl %s/del.pl %s %s/flv_file_stat %s 10 %s %d", $rootdir, $shellfile, $rootdir, $rmfile, $isp, $force);
	system($perlcmd);
}

my $start = length("new_cs_");

foreach my $csfile (@csipfile)
{
	my $bname = basename($csfile);
	my $end = index($bname, ".txt");
	next if ($end < 0);

	my $isp = substr($bname, $start, $end - $start);
	process_csfile($csfile, $isp);
}

my $monitor_db = MyDB->new("monitor", "ip:port", "username", "passwd");
my $voss_db = MyDB->new("voss", "ip:port", "username", "passwd");

my $monitor_sql = sprintf ("select ip from %s where rule_id = 16777217 and flag in (0, 2, 3) ;", $monitor_table);

my $records = $monitor_db->get_records($monitor_sql);
foreach my $ips (@$records) {
	my $ip = $ips->{ip};

	my $isp = $cshash{$ip};
	next if ($isp eq undef);

	do_rm_cs_file($ip, $isp);
}

