package MyDB;

#=============================
# pyh <pangj@earthlink.net>
#=============================

use strict;
use DBI;


# my $db = MyDB->new($db,$host,$user,$passwd)
sub new
{
    my ($class,$db,$host,$user,$passwd) = @_;

    $db ||= 'db';
    $host ||= 'host:port';
    $user ||= 'user';
    $passwd ||= 'passwd';

    my $dbh = DBI->connect("dbi:mysql:$db:$host", $user, $passwd,
             {
                 PrintError => 1,
                 RaiseError => 0,
                 AutoCommit => 1,
             } ) or die $DBI::errstr;

    bless { 'dbh'=>$dbh }, $class;
}


# $db->get_records($str,$ref)
# here $ref is optional,it's values array's ref
sub get_records
{
    my ($self,$str,$ref) = @_;
    $self = $self->new unless ref $self;

    my @values = ();
    if (defined $ref) {
        @values = @$ref;
    }

    my $dbh = $self->{'dbh'};
    my $sth = $dbh->prepare($str);

    $sth->execute(@values) or die $dbh->errstr;
    
    my @records;
    while ( my $ref = $sth->fetchrow_hashref ) {
        push @records, $ref;
    }

    $sth->finish;

    return \@records;
}


# $db->get_line($str,$ref)
# here $ref is optional,it's values array's ref
sub get_line
{
    my ($self,$str,$ref) = @_;
    $self = $self->new unless ref $self;

    my @values = ();
    if (defined $ref) {
        @values = @$ref;
    }

    my $dbh = $self->{'dbh'};
    my $sth = $dbh->prepare($str);

    $sth->execute(@values) or die $dbh->errstr;

    my @records = $sth->fetchrow_array;
    $sth->finish;

    return @records;
}


# $db->do_sql( $str, $ref )
# here $ref is optional,it's values array's ref
sub do_sql
{
    my ($self,$str,$ref) = @_;
    $self = $self->new unless ref $self;

    my @values = ();
    if (defined $ref) {
        @values = @$ref;
    }

    my $dbh = $self->{'dbh'};
    my $sth = $dbh->prepare($str);

    $sth->execute(@values) or die $dbh->errstr;
    $sth->finish;
}
    

# $db->disconnect;
sub disconnect
{
    my ($self) = @_;
    $self = $self->new unless ref $self;

    my $dbh = $self->{'dbh'};
    $dbh->disconnect;
}

# self destroy
sub DESTROY 
{
    my $self = shift;
    my $dbh = $self->{'dbh'};
    if ($dbh) {
        local $SIG{'__WARN__'} = sub {};
        $dbh->disconnect();
    }
}

1;
