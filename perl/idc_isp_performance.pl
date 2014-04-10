#!/usr/bin/perl

use POSIX 'strftime';

use lib "./lib";
use MyDB;
my $voss_db = MyDB->new("voss", "ip:port", "username", "passwd");

my $start = 1;
my $end = 61;

while ($start < $end)
{
	my $curday = POSIX::strftime('%Y%m%d', localtime(time() - 86400 * $start));
	%hash = ();
	$start++;
	my $sql = sprintf ("select ip, fsize, TIMESTAMPDIFF(SECOND, task_stime, task_ctime) as span from t_ip_task_info_%s where role = 2 and over_status = 'OVER_OK' ", $curday);
	my $records = $voss_db->get_records($sql);
	foreach my $ips (@$records) {
		my $ip = $ips->{ip};
		my $span = $ips->{span} >= 0 ? $ips->{span} : 0;
		my $fsize = $ips->{fsize};
		my $count = 1;

		my $v = $hash{$ip};

		if ($v eq undef)
		{
			$v->{span} = $span;
			$v->{fsize} = $fsize;
			$v->{count} = $count;
			$hash{$ip} = $v;
		}
		else
		{
			$v->{count}++;
			$v->{fsize} = $v->{fsize} + $fsize;
			$v->{span} = $v->{span} + $span;
		}
	}

	my @k = keys %hash;

	foreach $ip (@k)
	{
		my $v = $hash{$ip};
		my $up_sql = sprintf ("replace into t_ip_performance values ('%s', '%s', %d , %d, %d);", $ip, $curday, $v->{count}, $v->{fsize}, $v->{span} );
		$voss_db->do_sql($up_sql);
	}
}
