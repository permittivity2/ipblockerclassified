# FILEPATH: Untitled-1

package Net::IPBlocker::GrepRegexpsMail;

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

Net::IPBlocker::GrepRegexpsDefault - Default regular expressions for IP blocking

=head1 SYNOPSIS

    This works with the Net::IPBlocker module to provide a default sub for regular expressions for IP blocking.
    This is alos a framework that could be used to create other modules that provide default regular expressions for 
    IP Blocking of particular types of files such as Apache logs, Postfix logs, Auth logs, etc.

    The calling code will always pass in the log object and the log contents.

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
    my ( $self, $log ) = @_;
    my $TID = "TID: " . threads->tid;
    $logger->debug("$TID|In grep_regexps in " . __PACKAGE__ . " module.");

    $logger->info("$TID|Dumper of log object: " . Dumper($log));

    my $matches      = {};
    my @log_contents = @{ $log->{logcontents} };

    $logger->info("$TID|Dumper of log contents: " . Dumper(\@log_contents));

    return {} if ( !@log_contents );

    # DO NOT SORT NUMERICALLY!  The info in the configs states the order is sorted alphabetically
    foreach my $regex ( sort keys %{ $log->{regexpdeny} } ) {
        my $pattern = $log->{regexpdeny}{$regex};
        $logger->debug("$TID|Grep'ing for >>$pattern<< in $log->{file} from byte position $log->{seek}");

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
    $logger->info($log_msg);

    return $matches;
} ## end sub grep_regexps

1;

=head1 AUTHOR

Your Name <your@email.com>

=head1 LICENSE

This library is free software; you can redistribute it and/or modify it under the same terms as Perl itself.

=cut
