#!/usr/bin/perl

if (@ARGV != 2)
{
	printf "Usage split.pl infile outdir!\n";
	exit;
}

$file1 = shift;
$outdir = shift;

if (!open file1, "< $file1") {
	die "$!";
}

sub put_2_file
{
	my $day = shift;
	my $file = shift;

	my $outfile = $outdir."/".$day;
	if (!open outfile, ">> $outfile")
	{
		print "$day  : $outfile\n";
		die "$!";
	}

	print outfile "$file\n";
	close outfile;
}

while (<file1>) {
	chomp;
	my @ng = split /\:/, $_;
	my $day = substr($ng[0], 1, 2);
	my @cc = split / /, $ng[3];
	my $file = $cc[1];
	put_2_file($day, $file);
}
close file1;

