#!/usr/bin/perl

if (@ARGV != 3)
{
	printf "Usage diff.pl file1 file2 outdir!\n";
	exit;
}

$file1 = shift;
$file2 = shift;
$outdir = shift;

$afile = $outdir."/afile";
$rfile = $outdir."/rfile";

if (!open file1, "< $file1") {
	die "$!";
}

if (!open file2, "< $file2") {
	die "$!";
}

if (!open afile, "> $afile") {
	die "$!";
}

if (!open rfile, "> $rfile") {
	die "$!";
}

my $prelen = length("/diska/m2v/photo2video/upImg/");

sub process
{
	my $prefix = shift;
	my $local_prelen = length($prefix);
	%hash = ();

	while (<file1>) {
		chomp;
		$hash{$_} = 1;
		last if (substr($_, $prelen, $local_prelen) ne $prefix);
	}

	my $last = 0;
	while (<file2>) {
		chomp;
		my $val = $hash{$_};
		if (substr($_, $prelen, $local_prelen) ne $prefix)
		{
			$last = 1;
		}
		if ($val eq undef)
		{
			print rfile "$_\n";
			last if ($last);
			next;
		}
		delete $hash{$_};
		last if ($last);
	}

	@hashkey = keys  %hash;
	foreach $key(@hashkey)
	{
		print afile "$key\n";
		delete $hash{$key};
	}
}

my $idx = 0;
while ($idx < 100)
{
	my $p = $idx."/";
	process($p);
	$idx++;
}

close file2;
close file1;
close afile;
close rfile;

