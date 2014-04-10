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

my $prelen = length("/diska/m2v/photo2video/upImg/");
%hash=();

sub get_fd_by_fn
{
	my $fn = shift;
	my $fd = $hash{$fn};
	if ($fd eq undef)
	{
		if (!open fd, "> $fn")
		{
			die "$!";
		}
		$fd = fd;
		$hash{$fn} = $fd;
	}
	return $fd;
}

sub put_2_file
{
	my $day = shift;
	my $file = shift;

	my $outfile = $outdir."/".$day;
	my $fd = get_fd_by_fn($outfile);

	print $fd "$file\n";
}

while (<file1>) {
	chomp;
	next if (length($_) < $prelen + 5);
	my $idx = index($_, "/", $prelen);
	my $day = substr($_, $prelen, $idx-$prelen);
	put_2_file($day, $_);
}
close file1;

