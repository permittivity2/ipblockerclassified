#!/usr/bin/perl -w
##!/usr/local/perl/localperl/perl-5.32.0/bin/perl -w
#vim: noai:ts=4:sw=4

use strict;
use lib '/home/gardner/git/ipblockerclassified/lib/';
use IPblocker;
use Log::Log4perl qw(get_logger);
use Data::Dumper;
use Getopt::ArgParse;

$Data::Dumper::Sortkeys = 1;
$Data::Dumper::Indent   = 1;

my $logger = get_logger();    # This will change to the IPblocker object's logger when it is instantiated

main();

sub main {

    # Setup command line options
    my $clargs = setupArgParse();

    # Setup IPblocker object
    my $ipbArgs = {
        configsfile         => $clargs->configsfile,
        dumpconfigsandexit  => $clargs->dumpconfigsandexit,
        forceremovelockfile => $clargs->forceremovelockfile,
        # ignoreinterfaceips  => $clargs->ignoreinterfaceips,  # Not yet implemented
        iptables            => $clargs->iptables,
        lockfile            => $clargs->lockfile,
        log4perlconf        => $clargs->log4perlconf,
        loglevel            => $clargs->loglevel,
        prodmode            => $clargs->prodmode,
        queuechecktime      => $clargs->queuechecktime,
        readentirefile      => $clargs->readentirefile,
        cycles              => $clargs->cycles,
    };

    my $ipb    = IPblocker->new($ipbArgs);
    my $logger = $ipb->{logger} || get_logger();

    $logger->info("About to go!");

    # Start IPblocker object
    $ipb->go();
} ## end sub main

# Setup command line options
# This is often a lengthy subroutine so making it last is a probably good idea for readability
# The "add_arg" adds to a list so the order of the options for display is reverse order listed here.
# Meaning, if you want the help to display in a certain order, list them in reverse order here.
sub setupArgParse {
    my $args = shift;

    my $description = "Blocks IPs based on regex used to get entry in a log file.  Command line options take ";
    $description .= "precedence over config file options.";
    $description .= "\n\nThis is Perl so 0 (zero) is false and anything else is true.  ";
    my $ap = Getopt::ArgParse->new_parser(
        prog        => 'IP Blocker',
        description => $description,
        epilog      => 'Copyright 2023.  Copyright notice at: https://www.gnu.org/licenses/gpl-3.0.txt',
    );

    my $helpreadentirefile = "Read the entire file before processing.  Default is to not read the entire. ";
    $helpreadentirefile .= "This is a global setting and can be overridden per log file via a config file. ";
    $helpreadentirefile .= "No default is set here but will default to not reading the entire file. ";
    $ap->add_arg(
        '--readentirefile',
        type => 'Bool',
        dest => 'readentirefile',

        # default => 0,
        help => $helpreadentirefile,
    );

    my $helpqueuechecktime = "When the queue is empty, how long to wait before checking again.  ";
    $helpqueuechecktime .= "When the queue is not empty, this value is ignored ";
    $helpqueuechecktime .= "and the queue is checked as fast as possible.  ";
    $helpqueuechecktime .= "This value is in seconds.  ";
    $helpqueuechecktime .= "It seems unnecessary to have this value configurable, but here it is.";
    $ap->add_arg(
        '--queuechecktime',
        type    => 'Scalar',
        dest    => 'queuechecktime',
        # default => 3,
        help    => $helpqueuechecktime,
    );

    $ap->add_arg(
        '--prodmode',
        type    => 'Scalar',
        dest    => 'prodmode',
        default => 0,
        help    => 'The production mode to use.  0 = test mode, 1 = production mode',
    );

    $ap->add_arg(
        '--loglevel',
        choices => [qw(TRACE DEBUG INFO WARN ERROR FATAL)],
        dest    => 'loglevel',
        help    => 'The log level to use',
    );

    $ap->add_arg(
        '--log4perlconf',
        type    => 'Scalar',
        dest    => 'log4perlconf',
        default => '/etc/ipblocker/log4perl.conf',
        help    => 'The log4perl configuration file to use',
    );

    $ap->add_arg(
        '--lockfile',
        type => 'Scalar',
        dest => 'lockfile',

        # default => '/var/run/ipblocker.run.from.perlscript',
        # default => 0,
        help => 'The lock file location to use to prevent multiple instances from running',
    );

    $ap->add_arg(
        '--iptables',
        type => 'Scalar',
        dest => 'iptables',

        # default => '/sbin/iptables',
        help => 'The iptables command to use',
    );
    
    # $ap->add_arg(
    #     '--ignoreinterfaceips',
    #     choices => [qw(0 1)],
    #     help    => 'Add IPs on the interfaces to allowlist.  Default is to add them (1).  Set to 0 to not add them.',
    # );

    my $help = "Danger danger danger!  ";
    $help .= "This will force removal of lock file (if possible) before starting.  ";
    $help .= "Seriously, you better know what you are doing if you use this option.  ";
    $help .= "It will remove the lock file if it exists.  This is not advised unless you are sure the lock ";
    $help .= "file is stale.  You can potential have multiple ipblocker parent processes running at the ";
    $help .= "same time.  This will cause problems.  You have been warned. ";
    $ap->add_arg(
        '--forceremovelockfile',
        type    => 'Bool',
        dest    => 'forceremovelockfile',
        default => 0,
        help    => $help,
    );

    $ap->add_arg(
        '--dumpconfigsandexit',
        type    => 'Bool',
        dest    => 'dumpconfigsandexit',
        default => 0,
        help    => 'Dump the configs and exit',
    );

    $ap->add_arg(
        '--cycles',
        type => 'Scalar',
        dest => 'cycles',
        help => 'How many times to cycle through the queue before exiting.  Default is LONG_MAX (a large integer).',
    );

    $ap->add_arg(
        '--configsfile',
        type => 'Scalar',

        # dest => 'configsfile',
        default => '/etc/ipblocker/ipblocker.conf',
        help    => 'The configuration file to use',
    );

    return $ap->parse_args();
} ## end sub setupArgParse
