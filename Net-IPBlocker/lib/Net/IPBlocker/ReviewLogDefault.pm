# FILEPATH: Untitled-1

package Net::IPBlocker::ReviewLogDefault;

use strict;
use warnings;
use Exporter;
use Regexp::IPv6     qw($IPv6_re);
use Log::Any qw($log);  # Allegedly handles lots of different logging modules
use threads;
use Data::Dumper;
use POSIX qw(LONG_MAX);

local $Data::Dumper::Sortkeys = 1;
local $Data::Dumper::Indent   = 1;


our @EXPORT_OK = qw(grep_regexps);

# "Global" variables
my $logger = $log;
my $REGEX_IPV4 = q/\b((?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?))\b/;
my $REGEX_IPV6      = q/\b($IPv6_re)\b/;
my $tracker = {};

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

=head2 new

This is the constructor for the module.  It is not required but is nice to have.

This sub is called after the module is successfully loaded as a sanity check.

=cut

# Description:  Constructor for the module
# Returns:      blessed reference
sub new() {
    my $class = shift;
    my $args  = shift;
    my $self = {
        parentobjself => $args->{parentobjself},
        logobj        => $args->{logobj},
        configs       => $args->{parentobjself}->{configs},
    };

    $logger->info("In new in " . __PACKAGE__ . " module");
    $logger->debug("Dumper of self: " . Dumper($self)) if $logger->is_debug();

    # Set the enqueue alias
    *iptablesqueue_enqueue = $args->{iptablesqueue_enqueue};

    bless $self, $class;  
    return $self;
} ## end sub new

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
    $logger->debug("In grep_regexps in " . __PACKAGE__ . " module.");

    my $matches      = {};
    my @log_contents = @{ $log->{logcontents} };

    return $matches if ( !@log_contents );

    # DO NOT SORT NUMERICALLY!  The info in the configs states the order is sorted alphabetically
    my $epoch = time();
    foreach my $regex ( sort keys %{ $log->{regexpdeny} } ) {
        my $pattern = $log->{regexpdeny}{$regex};
        $logger->debug("Grep'ing for >>$pattern<< in $log->{file} from byte position $log->{seek}");

        my @current_matches = grep { /$pattern/ } @log_contents;
        $logger->debug( "Dumper of current matches: " . Dumper(@current_matches) ) if $logger->is_debug();

        foreach my $line (@current_matches) {
            chomp($line);
            $logger->debug("Checking >>$line<< for IP address");

            foreach my $ip_address ( $line =~ /$REGEX_IPV4/g, $line =~ /$REGEX_IPV6/g ) {
                # $matches->{$ip_address};
                if ( !exists $tracker->{jailed}->{$ip_address} ) {
                    $tracker->{jailed}->{$ip_address} = $epoch;
                    $matches->{$ip_address}->{count}++;
                    $matches->{$ip_address}->{logline} = $line;
                    $logger->debug("Found IP address: $ip_address in log line: $line");
                }
            }
        } ## end foreach my $line (@current_matches)
    } ## end foreach my $regex ( sort keys...)

    $logger->debug( "Dump of IP matches after all regex comparisons: " . Dumper($matches) ) if $logger->is_debug();

    if ( !keys %{$matches} ) {
        $logger->debug("No IP addresses found in log file: $log->{file}");
        return $matches;
    }

    my $log_msg = "Matched IP addresses to be sent back for potential blocking: ";
    $log_msg .= join( ",", keys %{$matches} );
    $logger->info($log_msg);

    return $matches;
} ## end sub grep_regexps

# Description:  A sub ran after the IPs have been enqueue'd for blocking
#               By default, this sub will track the IPs that have been enqueued and then after 30 minutes will delete the rule from iptables
#               Actually, this sub passes a delete rule to the iptablesqueue_enqueue sub
# Assumes:      $logobj has set $logobj->{enqueued} to rules that have been enqueued
# Requires:     $self, $logobj
sub post_enqueue {
    my ( $self, $logobj ) = @_;
    my $jailtime = $logobj->{jailtime} || $self->{configs}->{jailtime} || 1800;
    $logger->debug("In post_enqueue in " . __PACKAGE__ . " module.");

    $logger->debug("Dumper of logobj: " . Dumper($logobj)) if $logger->is_debug();

    $logger->debug("Dumper of self: " . Dumper($self)) if $logger->is_debug();

    my $epoch = time();
    foreach my $jailedtime ( keys %{$tracker->{jailed}} ) {
        $logger->debug("Checking jailedtime: $jailedtime");
        if ( $jailedtime + $jailtime < $epoch ) {
            foreach my $rule ( @{$tracker->{jailed}->{$jailedtime}} ) {
                my $args = { options => "-w -D", rule => $rule }; 
                $self->iptablesqueue_enqueue($args);
                $logger->info("Enqueuing this delete rule: $rule");
            }
            delete $tracker->{jailed}->{jailedtime};
            $logger->info("Deleted jailedtime $jailedtime from tracker");
        }
    
    }
    return 1;
}

1;

=head1 AUTHOR

Your Name <your@email.com>

=head1 LICENSE

This library is free software; you can redistribute it and/or modify it under the same terms as Perl itself.

=cut
