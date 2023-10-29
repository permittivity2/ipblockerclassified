#!/usr/local/perl/localperl/perl-5.32.0/bin/perl -w
#vim: noai:ts=4:sw=4

use strict;
use lib '/home/gardner/lib/';
use IPblocker;
use Log::Log4perl qw(get_logger);
use Data::Dumper;

$Data::Dumper::Sortkeys = 1;
$Data::Dumper::Indent   = 1;

my $logger = get_logger();

my $ipb = IPblocker->new(
    {
        configsfile  => '/home/gardner/bin/ipBlocker.new.conf',
        log4perlconf => '/home/gardner/bin/ipBlocker.new.pl.log.conf',
    }
);

$logger->debug("IPblocker object created");
$logger->debug( "IPblocker object: " . Dumper( $ipb->{configs} ) ) if ( $logger->is_debug() );

$ipb->go();
# my $sleeper = $ipb->{configs}->{sleep};
# $logger->info("Sleeping for %d seconds\n", $sleeper);
# for ( 1 .. $sleeper ) {
#     $logger->info($_ . "****************************************************************************************************");
#     sleep 1;
# }
# # printf "\n";
# $ipb->go();

# my $logs_to_review = $ipb->{configs}->{logs_to_review};


# my $logmsg = "logs_to_review object: ";
# foreach ( sort keys %{$logs_to_review} ) {
#     $logmsg .= "  $_ => " . $logs_to_review->{$_}->{file} . "|";
# }
# $logger->debug($logmsg);

# for ( sort keys %{$logs_to_review} ) {
#     # $logger->debug( "IPblocker object: " . Dumper( $logs_to_review->{$_} ) );
#     my $logobj = $ipb->readlogfile( $logs_to_review->{$_} );
# }

# $logger->debug( "IPblocker object: " . Dumper($ipb) );

# sleep 1;

# for ( sort keys %{$logs_to_review} ) {
#     $logger->debug( "IPblocker object: " . Dumper( $logs_to_review->{$_} ) );
#     my $logobj = $ipb->readlogfile( $logs_to_review->{$_} );
# }

#$logger->info( "IPblocker object: " . Dumper($ipb) );
