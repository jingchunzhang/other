#!/usr/bin/perl

if (@ARGV != 4)
{
	printf "Usage diff.pl file1 file2 afile rfile!\n";
	exit;
}

$file1 = shift;
$file2 = shift;

$afile = shift;
$rfile = shift;

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

%hash = ();

while (<file1>) {
	chomp;
	$hash{$_} = 1;
}
close file1;

while (<file2>) {
	chomp;
	my $key = $hash{$_};
	if ($key eq undef)
	{
		print rfile "$_\n";
		next;
	}
	delete $hash{$_};
}
close file2;

@hashkey = keys  %hash;
foreach $key(@hashkey)
{
	print afile "$key\n";
}

close afile;
close rfile;

