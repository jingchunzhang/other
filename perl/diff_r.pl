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
$dfile = $outdir."/dfile";

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

if (!open dfile, "> $dfile") {
	die "$!";
}

%hash = ();

while (<file1>) {
	chomp;
	my @c = split / /, $_;
	$hash{$c[1]} = $c[0];
}
close file1;

while (<file2>) {
	chomp;
	my @c = split / /, $_;
	my $val = $hash{$c[1]};
	if ($val eq undef)
	{
		print rfile "$_\n";
		next;
	}
	if ($val ne $c[0])
	{
		print dfile "$_ $val\n";
	}
	delete $hash{$c[1]};
}
close file2;

@hashkey = keys  %hash;
foreach $key(@hashkey)
{
	print afile "$key $hash{$key}\n";
}

close afile;
close rfile;
close dfile;

