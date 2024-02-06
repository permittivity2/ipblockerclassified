# FILEPATH: Untitled-1

package Net::IPBlocker::GrepRegexpsSSHD;

use strict;
use warnings;
use Exporter;
use Regexp::IPv6     qw($IPv6_re);
use Log::Any qw($log);  # Allegedly handles lots of different logging modules
use threads;
use Data::Dumper;

local $Data::Dumper::Sortkeys = 1;
local $Data::Dumper::Indent   = 1;

our @EXPORT_OK = qw(grep_regexps);

my $logger = $log;
my $REGEX_IPV4 = q/\b((?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?))\b/;
my $REGEX_IPV6      = q/\b($IPv6_re)\b/;

=head1 NAME

Net::IPBlocker::GrepRegexpsDefault - Default regular expressions for IP blocking for sshd logs (auth.log)

=head1 SYNOPSIS

This works with the Net::IPBlocker module to provide a framework for getting bad IPs from a ssh log file.

The calling code will always pass in the log object and the log contents.

The sshd log has two special items.  We don't want to add IPs to be blocked with special user names.  
Also, the sshd log is usually an auth log so we filter out lines that don't have sshd in them.
Both of these may be set in the configs file like this (as an example):

 logs_to_review[authlog][filterin][01] = "sshd"
 logs_to_review[authlog][filterin][02] = "openssh"
 logs_to_review[authlog][filterout][01] = "sshd.*for johnboy"
 logs_to_review[authlog][filterout][02] = "sshd.*Accepted.*for trinity"
 logs_to_review[authlog][filterout][03] = "sshd.*Accepted.*for neo"


=head1 DESCRIPTION

This module provides a default regular expression sub for IP blocking. 
These regular expressions can be used with the L<Net::IPBlocker> module to match and block IP addresses.

=head1 METHODS

=head2 get_regexps

Returns an array of default regular expressions for IP blocking.

    my @regexps = Net::IPBlocker::GrepRegexpsDefault->get_regexps();

=cut

# Description:  Using the logobj, this greps against the log contents for matching lines and then gets the
#               IP address on each line.
# Requires:     $self, $log
# Returns:      Hash reference of IP addresses with count of how many times the IP address was found
sub grep_regexps {
    my ( $self, $logobj ) = @_;
    my $TID = "TID: " . threads->tid;
    $logger->debug("$TID|In grep_regexps in " . __PACKAGE__ . " module.");

    $logger->debug("$TID|Dumper of log object: " . Dumper($logobj) . "\n") if $logger->is_debug();
    my $matches      = {};
    my @log_contents = @{ $logobj->{logcontents} };

    $logger->debug("$TID|Dumper of log contents: " . Dumper(@log_contents)) if $logger->is_debug();

    return {} if ( !@log_contents );

    $logger->info("$TID|Started with " . scalar(@log_contents) . " lines to review ");
    foreach my $filterin ( sort keys %{ $logobj->{filterin} } ) {
        my $pattern = $logobj->{filterin}{$filterin};
        $logger->debug("$TID|Grepping for >>$pattern<< across " . scalar(@log_contents) . " lines ");

        @log_contents = grep { /$pattern/ } @log_contents;
    } ## end foreach my $filterin ( sort...)    
    $logger->info("$TID|After filtering in, we have " . scalar(@log_contents) . " lines to review ");

    foreach my $filterout ( sort keys %{ $logobj->{filterout} } ) {
        my $pattern = $logobj->{filterout}{$filterout};
        $logger->debug("$TID|Grepping for >>$pattern<< in $logobj->{file} from byte position $logobj->{seek}");

        @log_contents = grep { !/$pattern/ } @log_contents;
    } ## end foreach my $filterout ( sort...)
    $logger->info("$TID|After filtering out, we have " . scalar(@log_contents) . " lines to review ");  

    # DO NOT SORT NUMERICALLY!  The info in the configs states the order is sorted alphabetically
    foreach my $regex ( sort keys %{ $logobj->{regexpdeny} } ) {
        my $pattern = $logobj->{regexpdeny}{$regex};
        $logger->debug("$TID|Grep'ing for >>$pattern<< in $logobj->{file} from byte position $logobj->{seek}");

        my @current_matches = grep { /$pattern/ } @log_contents;
        $logger->debug( "$TID|Dumper of current matches: " . Dumper(@current_matches) ) if $logger->is_debug();

        foreach my $line (@current_matches) {
            chomp($line);
            $logger->debug("$TID|Checking >>$line<< for IP address");

            foreach my $ip_address ( $line =~ /$REGEX_IPV4/g, $line =~ /$REGEX_IPV6/g ) {
                $matches->{$ip_address}++;
                $logger->debug("$TID|Found IP address: $ip_address");
            }
        } ## end foreach my $line (@current_matches)
    } ## end foreach my $regex ( sort keys...)

    $logger->debug( "$TID|Dump of IP matches after all regex comparisons: " . Dumper($matches) ) if $logger->is_debug();

    my $log_msg = "$TID|Matched IP addresses to be reviewed for potential blocking: ";
    $log_msg .= join( ",", keys %{$matches} );
    $logger->debug($log_msg . "\n");

    return $matches;
} ## end sub grep_regexps

# Description: This is the gosh darn retaliatory strike and attack method.  It will strike the malicious IP addresses
#              with a malformed tcp packet to the port that the malicious IP address was attacking.
sub gdr() {
}

1;

=head1 AUTHOR

Your Name <your@email.com>

=head1 LICENSE

This library is free software; you can redistribute it and/or modify it under the same terms as Perl itself.

=cut
