#!/usr/bin/perl

if (@ARGV != 2)
{
	printf "Usage diff.pl misfile access!\n";
	exit;
}

$file1 = shift;
$file2 = shift;

if (!open file1, "< $file1") {
	die "$!";
}

if (!open file2, "< $file2") {
	die "$!";
}

%hash = ();

while (<file1>) {
	chomp;
	$hash{$_} = 1;
}
close file1;

my $total = 0;
my $hit = 0;

while (<file2>) {
	chomp;
	$total++;
	my $key = $hash{$_};

	if ($key eq undef)
	{
		$hit++;
		next;
	}
}
close file2;

$ratio = $hit/$total;

print "$ratio  $hit $total!\n";
