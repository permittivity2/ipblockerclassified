#!/usr/bin/perl -w
#vim: noai:ts=4:sw=4

use strict;
use warnings;
use lib '/home/gardner/git/ipblockerclassified/Net-IPBlocker/lib/';
use Net::IPBlocker;
use Log::Any::Adapter;
use Log::Log4perl qw(get_logger);
use Data::Dumper;
use Getopt::ArgParse;
use Carp;
use List::Util qw(any);

$Data::Dumper::Sortkeys = 1;
$Data::Dumper::Indent   = 1;

Log::Any::Adapter->set('Log4perl');

my $logger = get_logger();

main();

### Subroutines below here ###

sub main {

    # Setup command line options
    my $clargs = setupArgParse();

    if ( $clargs->loglevel && $clargs->log4perlconf ) {
        my $msg = "You cannot use --loglevel and --log4perlconf at the same time.  Choose one or the other.  ";
        $msg .= "This is because the loglevel in the log4perl config file will override the command line loglevel.  ";
        $msg .= "So, just drop the --loglevel option and use the --log4perconf or vice versa.\n\n";
        croak $msg;
    }

    my $logger = setup_logger( $clargs );

    # Setup IPBlocker arguments
    my $ipbArgs = {
        configsfile         => $clargs->configsfile,
        dumpconfigsandexit  => $clargs->dumpconfigsandexit,
        forceremovelockfile => $clargs->forceremovelockfile,
        # ignoreinterfaceips  => $clargs->ignoreinterfaceips,  # Not yet implemented
        iptables            => $clargs->iptables,
        lockfile            => $clargs->lockfile,
        prodmode            => $clargs->prodmode,
        queuechecktime      => $clargs->queuechecktime,
        queuecycles         => $clargs->queuecycles,
        readentirefile      => $clargs->readentirefile,
        totalruntime        => $clargs->totalruntime,
    };

    my $ipb    = Net::IPBlocker->new($ipbArgs);

    $logger->info("About to go!");

    # Start IPblocker object
    $ipb->go();
} ## end sub main

sub setup_logger {
    my ($clargs) = @_;

    # Check if log4perl configuration is specified
    if ($clargs->log4perlconf) {
        # Check if the specified configuration file is readable
        croak "\nUnable to read log4perl config file >> $clargs->log4perlconf <<\n" unless -r $clargs->log4perlconf;

        # Initialize Log4perl based on whether a logwatch interval is specified
        if ($clargs->logwatch_interval) {
            Log::Log4perl->init_and_watch($clargs->log4perlconf, $clargs->logwatch_interval);
        } else {
            Log::Log4perl->init($clargs->log4perlconf);
        }
    } else {
        # Setup default logging configuration if no log4perl configuration is specified
        my $loglevel = $clargs->loglevel || 'WARN';  # Default log level
        my $conf = qq(
            log4perl.rootLogger                                 = $loglevel, Screen
            log4perl.appender.Screen                            = Log::Log4perl::Appender::Screen
            log4perl.appender.Screen.stderr                     = 0
            log4perl.appender.Screen.layout                     = Log::Log4perl::Layout::PatternLayout
            log4perl.appender.Screen.layout.ConversionPattern   = %d|%p|%l|%m{chomp}%n
        );
        Log::Log4perl->init(\$conf);
    }

    # Attempt to get the logger
    my $logger = get_logger() || croak "Unable to get logger";
    return $logger;
}


# sub setup_logger() {
#     my ( $clargs ) = @_;

#     if ( $clargs->log4perlconf ) {
#         if ( -r $clargs->log4perlconf ) {
#             if ( $clargs->logwatch_interval ) {
#                 Log::Log4perl->init_and_watch($clargs->log4perlconf, $clargs->logwatch_interval);
#             }
#             else {
#                 Log::Log4perl->init($clargs->log4perlconf);
#             }
#         } else {
#             croak "Unable to read log4perl config file >> $clargs->log4perlconf <<";
#         }
#     }
#     else {
#         my $loglevel = $clargs->loglevel;
#         my $conf = qq(
#             log4perl.rootLogger                                 = $loglevel, Screen
#             log4perl.appender.Screen                            = Log::Log4perl::Appender::Screen
#             log4perl.appender.Screen.stderr                     = 0
#             log4perl.appender.Screen.layout                     = Log::Log4perl::Layout::PatternLayout
#             log4perl.appender.Screen.layout.ConversionPattern   = %d|%p|%l|%m{chomp}%n                
#         );         
#         Log::Log4perl->init(\$conf);
#     }

#     $logger = get_logger() || croak "Unable to get logger";
#     return $logger;
# } ## end sub setup_Logger

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

    $ap->add_arg(
        '--totalruntime',
        type    => 'Scalar',
        dest    => 'totalruntime',
        help    => 'How long to run in seconds.  Default is LONG_MAX (a large integer).',
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

    $ap->add_arg(
        '--queuecycles',
        type    => 'Scalar',
        dest    => 'queuecycles',
        help    => 'How many times to cycle through the queue before exiting.  Default is LONG_MAX (a large integer).',
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
        '--logwatch_interval',
        type    => 'Scalar',
        dest    => 'logwatch_interval',
        default => 5,
        help    => 'The log4perl watch interval to use',
    );

    $ap->add_arg(
        '--loglevel',
        choices => [qw(TRACE DEBUG INFO WARN ERROR FATAL)],
        dest    => 'loglevel',
        default => 'INFO',
        help    => 'The log level to use',
    );

    $ap->add_arg(
        '--log4perlconf',
        type    => 'Scalar',
        dest    => 'log4perlconf',
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
