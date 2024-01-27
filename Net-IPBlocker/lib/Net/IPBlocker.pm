package Net::IPBlocker;

use 5.006;
use strict;
use warnings;
use POSIX qw(LONG_MAX);
use DateTime;
use File::Basename;
use List::Util qw(any);

# use Getopt::Long;
# use File::Lockfile;
use Time::HiRes qw(usleep gettimeofday time);

# use Regexp::Common qw/ net number /;
# use NetAddr::IP::Util qw(inet_ntoa);
# use Net::DNS::Dig;
# use Term::ANSIColor;
use Config::File;
use Carp;
use Log::Log4perl qw(get_logger :nowarn :levels);
use Log::Any qw($log);
use Data::Dumper;
use Regexp::IPv6     qw($IPv6_re);
use LockFile::Simple qw(lock trylock unlock);
use File::Path       qw(make_path);
use Net::Ifconfig::Wrapper;

# Thread setup
use threads;
# use threads::shared;
use Thread::Queue;
my $DataQueue  = Thread::Queue->new();
my $LoggerTIDS = ();                     # Thread IDs for tracking or whatever

# Another queue for iptables commands
my $IptablesQueue = Thread::Queue->new();
my $IptablesTIDS  = ();                     # Thread IDs for tracking or whatever

# Data Dumper setup
$Data::Dumper::Sortkeys = 1;
$Data::Dumper::Indent   = 1;

### Global Variables  (clearly the threading stuff is global, duh)
## I hate global variables!
# logger --- I really debated whether to make this global or not.  I decided to make it global because it is used
#   in the signal interupts and those use prototyped subs.  I don't know how (if possible) to pass $self to the
#   signal interupt subs with so much threaded.
my $logger;      # This gets set after log4Perl is loaded in new()
                 # Some might say to use 'our' instead of 'my' but does it matter when it is global to lexical scope of
                 #   the package?
my $lock_obj;    # This is the lock object and is set in set_lockFile()
                 # Needs to be global because it is used in the signal interupts and those use prototyped subs.
## Regex for IPv4 and IPv6 capturing.
#   This is critical and needs be consistent across the entire module
# my $REGEX_IPV4 = q/.*\b((?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?))\b.*/;
my $REGEX_IPV4 = q/\b((?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?))\b/;
my $REGEX_IPV6      = q/\b($IPv6_re)\b/;
my $IPTABLESRUNLINE = 0;    #This is just an odd one.  It is used to track the line number of the sub iptables_thread()
                            #  where run_iptables() is called.  This is used in the signal interupts to print out the
                            #  line number of where the iptables command was run.  This is used for debugging.
                            #  This is set in the iptables_thread() sub.
our $tracker = {};          # Mostly chains added and rules added are stuffed in here for tracking purposes
my $DEFAULTS = {
    allowdeny            => 'Allow,Deny',
    allowlist            => {},
    configsfile          => '/etc/ipblocker/ipblocker.conf',
    cycles               => LONG_MAX,
    cyclesleep           => 0.5,
    dumpconfigsandexit   => 0,
    denylist             => {},
    forceremovelockfile  => 0,
    globalallowlist      => {},
    chainprefix          => "IPBLOCKER_",
    globalchains         => [qw / INPUT OUTPUT FORWARD /],
    globaldenylist       => {},
    globalregexallowlist => {},
    globalregexdenylist  => {},
    ignoreinterfaceips   => 1,                                   #This adds the IPs from the interfaces to the allowlist
    iptables             => '/sbin/iptables',
    lockfile             => '/var/run/ipblocker.run.default',
    log4perlconf         => '/etc/ipblocker/log4perl.conf',
    loglevel             => 'Will use value from log4perl.conf', # Can be set from calling script.
                                                                 #   If no value sent from calling script, then
        #   use value from configs file.  If no value in configs file then I think the
        #   Easy Init log4perl is used which defaults to DEBUG, i think.
    logcontents       => {},
    logs_to_review    => {},
    logwatch_interval => 3,
    prodmode          => 0,
    queuechecktime    => 1,
    queuecycles       => LONG_MAX,
    readentirefile    => 0,
};

=head1 NAME

Net::IPBlocker - Blocks IPs based on regex from specified log files

=head1 VERSION

Version 0.01

=cut

our $VERSION = '0.01';


=head1 SYNOPSIS

Blocks IPs based on Regular Expressions in specified log files.

 use Net::IPBlocker;
 my $foo = Net::IPBlocker->new();
 $foo->go(); 

You can send all configs into the constructor as a hash, I really advise using a config file.  
The default config file is F</etc/ipblocker/ipblocker.conf> but you can set it to another file.
If a config file is not found, it will use default values for everything and that will probably not work very well.

 my $foo = Net::IPBlocker->new( { configsfile => '/etc/ipblocker/ipblocker.conf' } );
 $foo->go();

=head2 Future Enhancements

=over 4

=item * Add jail time for IPs

This involves adding a database to store the IPs and the time they were blocked.
This also means adding a mechanism to unblock IPs after a certain amount of time.
Luckily, I have threaded this so adding that is just a matter of adding another thread.
I am open to ideas of what database to use.  I am thinking SQLite.
Or, possibly just a file with the IPs (the rule) and the time they are to be unblocked (deleted 
from iptables).

=item * Add synchronized appender logging:
      
https://metacpan.org/dist/Log-Log4perl/view/lib/Log/Log4perl/Appender/Synchronized.pm

=item * Fix the ability for Log4perl to re-read the "log4perl.conf" which seems to not work right now

=item * my $interfaces = Net::Ifconfig::Wrapper::Ifconfig('list', '', '', '');

This is a list of interfaces.  Need to figure out how to use this to get the IP address of the
interfaces.  Need to add those IPs to the global allow list.

=item * Fix sub add_ifconfig_ips_to_allowlist() to handle IPv4 and IPv6 addresses

=item * Change from using log4perl to Log::Any

=back

=head2 DESCRIPTION

This has been a very long running project of mine.  I have been using this script for years to block IPs and then 
realized Fail2Ban exists.  I have tried to use Fail2Ban multiple times but it never seems to work right for me.
It seems to lock-up. 
This module tries to incorporate the ideas of my past experience with the general idea of Fail2Ban.

I highly encourage you to use a config file.  The default config file is in the same location as this module but you 
can set it to another file.

When installing this, you should also receive a script called "ipBlocker.pl".  This is a sample script that uses 
this module.

Finally, for now, this module use log4perl.  I didn't realize there was a heated debate about log4perl vs Log::Any vs 
whatever else.  I am open to changing this to Log::Any but I need to figure out how to do that.

=head1 SUBROUTINES/METHODS

=head2 new

Reads configs, logging configs, sets up logging, sets up a class and returns a blessed object
The sub go() is where the action starts

Example:

  use IPblocker;

  my $args = {
    configsfile         => '/etc/ipblocker/ipblocker.conf',
    dumpconfigsandexit  => '0', # True false value
    forceremovelockfile => '0', # True false value
    iptables            => 'sudo /sbin/iptables',
    lockfile            => '/var/run/ipblocker.run',
    log4perlconf        => '/etc/ipblocker/log4perl.conf',  #Can also be 0 to use default log4perl
    loglevel            => 'DEBUG', # Can be TRACE DEBUG INFO WARN ERROR FATAL
    prodmode            => '0', # True false value --- Determins if the iptables commands are actually run
    queuechecktime      => '3', # How long to wait when the queue is empty before checking again. Any float value.
    readentirefile      => '0', # True false value --- Determines if the entire log file is read or
                                # new entries since last run are read.
    cycles              => 'LONG_MAX', # How many times to run the main loop.  LONG_MAX is the default.
  };

  my $ipb    = IPblocker->new($args);
  my $logger = $ipb->{logger};

=head3 All arguments to new() and their defaults

=head4 allowdeny

allowdeny            => 'Allow,Deny',

Set to 'Allow,Deny' or 'Deny,Allow' to determine the order of the allow and deny lists.
Seteting to 'Allow,Deny' means the allow list is processed first and then the deny list is processed.
Meaning, as an example, if 1.1.1.1 is on the allow list and allowdeny is set to Allow,Deny, then
the IP of 1.1.1.1 will never be blocked.  If allowdeny is set to Deny,Allow, then it is possible 
for 1.1.1.1 to be blocked.

=head4 allowlist

allowlist            => {},

A list of IPs to allow.  This is a hash reference.  The key is the order to allow the IP.  The value is the IP.
Example:
 allowlist => (
  '01' => '1.1.1.1',
  '4' => '1.1.1.4',
  '10' => '1.1.1.2',
  '100' => '1.1.1.3',
  
 )

The allow list is sorted in standard Perl sort order.  So, be sure to pad 0's or whatever to the front of the key.

=head4 configsfile

configsfile          => '/etc/ipblocker/ipblocker.conf',

Use a config file!  This is the default config file location.  You can set it to another file.

=head4 cycles

cycles               => LONG_MAX,

How many times to run the main loop.  LONG_MAX is the default.  Why not infinity?  Because I don't want to.

=head4 cyclesleep

cyclesleep           => 0.5,

How long to sleep between cycles.  This is in seconds.  Default is 0.5 seconds.  You can use a float value.

=head4 dumpconfigsandexit

dumpconfigsandexit   => 0,

If set to 1 (true), then the configs are dumped to stdout and the script exits.  This is useful for creating a 
config file.

=head4 denylist

denylist             => {},

Similar to allow list but for IPs to deny.  This is a hash reference.  The key is the order to deny the IP.

=head4 forceremovelockfile

forceremovelockfile  => 0,

This will force removal of lock file (if possible) before starting.  Seriously, you better know what you are doing.

=head4 chainprefix

chainprefix          => "IPBLOCKER_",

This is the prefix for the chains created in iptables.  This is the prefix you will see in iptables for 
all the chains created by this module.

=head4 globalchains

globalchains         => [qw / INPUT OUTPUT FORWARD /],

This is a list of the global chains to add the global chain to.
The global chain is where all the subordinate file logger chains are added.

I see some value in adding the global chain to some other chain but by default we add it to INPUT, OUTPUT, and FORWARD.
Or, possibly, you don't want to add to the FORWARD chain.
Maybe you onkly care about INPUT table.  I don't know.  Whatever works best for you.

=head4 iptables

iptables             => '/sbin/iptables',

This is the iptables command to use.  You can use sudo or whatever you want.
I really encourage using sudo but by default it is not used.  
Using sudo and non-root user is a bit more work.  You need to setup sudoers to allow the user to run iptables.
However, I think it is worth it for an added measure of security.
If you change this to use sudo, then you may also need to change the lockfile location to a location that the user 
can write to.

=head4 lockfile

lockfile             => '/var/run/ipblocker.run.default',

This is the lock file location to use to try to prevent multiple instances from running.

=head4 log4perlconf

log4perlconf         => '/etc/ipblocker/log4perl.conf',

This is the log4perl configuration file to use.  You can also set this to 0 to use the default log4perl configuration.

=head4 loglevel

loglevel             => 'INFO'

THis can be TRACE DEBUG INFO WARN ERROR FATAL.

=head4 prodmode

prodmode          => 0,

This is a true/false value.  If set to 1 (true), then the iptables commands are actually run.  If set to 0 (false), 
then the iptables commands are not run.  This is useful for testing.

By default, this is set to 0 (false).

=head4 queuechecktime

queuechecktime    => 1,

When the queue is empty, how long to wait before checking again.  When the queue is not empty, this value is ignored

=head4 queuecycles

queuecycles       => LONG_MAX,

How many times to check the queue.  LONG_MAX is the default.  Why not infinity?  Because I don't want to.

=head4 readentirefile

readentirefile    => 0,

This is a true/false value.  If set to 1 (true), then the entire log file is read.  If set to 0 (false), then only
new entries since the last run are read.
This can aslo be set per log file in the configs file.

=cut

sub new() {
    my $class = shift;
    my $args  = shift;

    if ( !$args ) {
        carp("No arguments passed to new().  This may not be an issue.");
        $args = {};
    }
    elsif ( ref($args) ne 'HASH' ) {
        croak("Arguments passed to new() are not a hash reference");
    }

    # Allow command line to override default configs file location
    my $configsfile = $args->{configsfile} || $DEFAULTS->{configsfile};

    my $self = {
        configsfile => $configsfile,
        clargs      => $args,
    };

    # Create the $self object
    bless $self, $class;

    # Load all the configs into the $self object under the configs key
    # The sub load_configs() expects $self to be an object and have configsfile setup
    $self->load_configs();

    if ( $self->{configs}->{dumpconfigsandexit} ) {
        ## Rip out some stuff that is used internally and not needed for the configs file
        delete $self->{configs}->{configsfile};
        delete $self->{configs}->{globalchain};
        delete $self->{configs}->{dumpconfigsandexit};
        print "This can basically be copy/pasted into a config file:\n";
        recursiveHashPrint( $self->{configs} );
        exit;
    } ## end if ( $self->{configs}->...)

    # Setup logging.
    $logger = $self->setup_Logger();
    $logger->info("Logging initialized and ready to go");
    $logger->debug( "Dumping self: " . Dumper($self) ) if ( $logger->is_debug() );

    return $self;
} ## end sub new

sub recursiveHashPrint {
    my ( $ref, $prefix ) = @_;
    $prefix = '' unless defined $prefix;    # Initialize prefix if not provided

    if ( ref($ref) eq 'HASH' ) {
        foreach my $key ( sort keys %{$ref} ) {

            # Concatenate the current key to the prefix for the next level
            my $new_prefix = $prefix ? "$prefix][$key" : "[$key";
            recursiveHashPrint( $ref->{$key}, $new_prefix );
        } ## end foreach my $key ( sort keys...)
    } ## end if ( ref($ref) eq 'HASH')
    elsif ( ref($ref) eq 'ARRAY' ) {

        # If the reference is an array, join and print the elements
        my $line = "$prefix] = " . join( ', ', @{$ref} ) . "\n";
        $line =~ s/\[//;
        $line =~ s/\]//;
        print $line;
    } ## end elsif ( ref($ref) eq 'ARRAY')
    else {
        # Print the scalar value
        my $line = "$prefix]=$ref\n";
        $line =~ s/\[//;
        $line =~ s/\]//;
        print $line;
    } ## end else [ if ( ref($ref) eq 'HASH')]
} ## end sub recursiveHashPrint

=head2 go

This is where the action starts.  This is called from the script that uses this module after
new() is instantiated.

This creates a thread for each log watcher and a thread for the iptables queue watcher.
If you have 5 files to watch, then there will be 5 threads watching those files + 1 thread to add commands to 
iptables.

=cut

sub go() {
    my $self       = shift;
    my $start_time = time();

    # If there are no log files to review, then there is nothing to do
    unless ( $self->{configs}->{logs_to_review} ) {
        $logger->error("No logs defined in configs to review");
        return 0;
    }

    # Set a few items
    $self->set_iptables_command() or $logger->error("Unable to set iptables command");
    $self->set_signal_handler();
    $self->{configs}->{globalchain} = $self->{configs}->{chainprefix} . "global";
    $self->set_lockFile() or $logger->logdie("Unable to set lock file");

    # $self->add_ifconfig_ips_to_allowlist() if ( $self->{configs}->{ignoreinterfaceips} );  # Not yet implemented

    # Create iptables queueing and thread for commands to run against iptables
    my $iptables_thr = threads->create( \&iptables_thread, $self );

    # Create the global chain and add it to the global chains
    $self->add_global_chain();

    # Add the global allow and deny IPs to the global allow and deny chains
    $self->add_global_allow_deny_ips();

    # Create a thread for each logger watcher
    # my $logger_thr = threads->create( \&logger_thread, $self );
    $logger->logdie("Unable to review logs") unless ( $self->logger_thread() );

    # sleep 20 and die "death death death";

    # Call the dataQueue_runner() sub to run the DataQueue queue
    #   This is basically the end of main
    #   The dataQueue_runner() sub will run until the DataQueue queue is set to undef which
    #   can be done by multiple ways.
    # $self->dataQueue_runner();

    my $cycles     = $self->{configs}->{cycles};
    my $cyclesleep = $self->{configs}->{cyclesleep};
    while ($cycles) {
        $cycles--;
        usleep $cyclesleep * 1000000;
        my $logmsg = "Cycle";
        $logmsg .= "s" if ( $cycles != 1 );
        $logmsg .= " remaining: $cycles.";
        $logmsg .= "s" if ( $cyclesleep != 1 );
        $logmsg .= ".";
        $logger->trace($logmsg) if ( $logger->is_debug() );
    } ## end while ($cycles)

    my $runtime = time() - $start_time;
    $runtime = sprintf( "%.4f", $runtime );
    $logger->info("Runtime: $runtime second(s)");
    $self->stop();
} ## end sub go

sub iptables_thread() {
    my ($self) = @_;
    my $TID = threads->tid;
    $TID = "TID: " . $TID;

    my $cyclesleep = $self->{configs}->{queuechecktime};
    my $cycles     = $self->{configs}->{queuecycles};
    my $logmsg     = "$TID|Starting iptables queue watching thread with $cycles cycles and $cyclesleep seconds";
    $logmsg .= " between cycles";
    $logger->info($logmsg);

    while (1) {
        my $iptablesQueue_pending = eval { $IptablesQueue->pending() };
        if ( !defined $iptablesQueue_pending ) {
            my $logmsg = "$TID|IptablesQueue is in an undefined state. This is probably intentional. ";
            $logmsg .= "Exiting the loop.";
            $logger->info($logmsg);
            last;
        } ## end if ( !defined $iptablesQueue_pending)

        if ( $iptablesQueue_pending > 0 ) {
            $logger->info("$TID|Queue length of IptablesQueue is $iptablesQueue_pending");
            my $data = $IptablesQueue->dequeue();
            $logger->debug( "$TID|Dequeued from IptablesQueue: " . Dumper($data) ) if $logger->is_debug();
            $self->run_iptables($data) || $logger->error( "Not successful running iptables command: " . Dumper($data) );
            $IPTABLESRUNLINE = __LINE__;               # See commentary way above about this variable
            $IPTABLESRUNLINE = $IPTABLESRUNLINE - 1;
        } ## end if ( $iptablesQueue_pending...)
        elsif ( $iptablesQueue_pending == 0 ) {

            # This is a bit of extra logging but if we are at this point, speed is not an issue
            my $logmsg = "$TID|IptablesQueue depth is 0 so sleeping for $cyclesleep second";
            $logmsg .= "s" if ( $cyclesleep != 1 );
            $logmsg .= ".";
            $logger->info($logmsg);
            usleep $cyclesleep * 1000000;
        } ## end elsif ( $iptablesQueue_pending...)
        else {
            $logger->error("$TID|IptablesQueue queue is in an unknown state. Exiting due to an unknown issue.");
            last;
        }
    } ## end while (1)
} ## end sub iptables_thread

# Description:  Adds IPs on the local interfaces to the global allowlist
#  This does not work becasue it only handles IPv4 addresses and other issues
sub add_ifconfig_ips_to_allowlist() {
    my $self = shift;
    return 1;

   # my $interfaces = Net::Ifconfig::Wrapper::Ifconfig('list', '', '', '');
   # my $key = " ";
   # foreach my $iface (keys %$interfaces) {
   #     print "Interface: $iface\n";
   #     if (exists $interfaces->{$iface}{'inet'}) {
   #         foreach my $inet (@{$interfaces->{$iface}{'inet'}}) {
   #             $logger->info("Adding $inet->{'addr'} from $iface->{'name'} to global allowlist");
   #             # The global allowlist is later sorted alphabetically (ASCII, I think) so I use spaces to make sure the
   #             #  the device IPs are at the top of the list
   #             $self->{configs}->{allowlist}->{$key}=$inet->{'addr'};
   #             $key .= $key; # seems a bit odd but it just adds more spaces to the key
   #         }
   #     }
   #     if (exists $interfaces->{$iface}{'inet6'}) {
   #         foreach my $inet6 (@{$interfaces->{$iface}{'inet6'}}) {
   #             print "IPv6 Address: $inet6->{'addr'}\n";
   #             $logger->info("Adding $inet6->{'addr'} from $iface->{'name'} to global allowlist");
   #             # The global allowlist is later sorted alphabetically (ASCII, I think) so I use spaces to make sure the
   #             #  the device IPs are at the top of the list
   #             $self->{configs}->{allowlist}->{$key}=$inet6->{'addr'};
   #             $key .= $key; # seems a bit odd but it just adds more spaces to the key
   #         }
   #     }
   # }
} ## end sub add_ifconfig_ips_to_allowlist


# Unnecesary sub.  I am leaving it here for now in case I need it later.
# sub dataQueue_runner() {
#     my ($self) = @_;
#     my $TID = threads->tid;
#     $TID = "TID: " . $TID;

#     local $Data::Dumper::Terse  = 1;    # Disable use of $VARn
#     local $Data::Dumper::Indent = 0;    # Disable indentation

#     $logger->info("$TID|DataQueue runner");
#     my $queuechecktime = $self->{configs}->{queuechecktime};
#     my $queuecycles    = $self->{configs}->{queuecycles};

#     while (1) {
#         my $dataqueue_pending = eval { $DataQueue->pending() };
#         unless ( defined $dataqueue_pending ) {
#             $logger->info("$TID|DataQueue is in an undefined state. This is probably intentional. Exiting the loop.");
#             last;
#         }

#         if ( $dataqueue_pending > 0 ) {
#             $logger->info("$TID|Queue length of DataQueue is $dataqueue_pending");
#             my $data = $DataQueue->dequeue();
#             ##### Need to add an 'if ( $data eq "stop" )' here to call sub stop() and gracefully exit
#             $logger->debug( "$TID|Dequeued from DataQueue: " . Dumper($data) ) if $logger->is_debug();
#         } ## end if ( $dataqueue_pending...)
#         elsif ( $dataqueue_pending == 0 ) {
#             my $logmsg = "$TID|DataQueue depth: $dataqueue_pending.  Sleeping: $queuechecktime second(s).  ";
#             $logmsg .= "Queue cycles remaining: $queuecycles";
#             $logger->info($logmsg);
#             $queuecycles--;
#             last if ( $queuecycles <= 0 );
#             sleep $queuechecktime;
#         } ## end elsif ( $dataqueue_pending...)
#         else {
#             $logger->error("$TID|DataQueue is in an unknown state. Leaving queue watch due to an unknown issue.");
#             last;
#         }
#     } ## end while (1)

#     $logger->info("$TID|DataQueue runner exiting");
# } ## end sub dataQueue_runner

# Assumptions:
#   $self->{configs}->{log4perlconf} is set
#   $self->{configs}->{logwatch_interval} is set
# These assumptions *should* be true because this is called from new()
sub setup_Logger() {
    my $self = shift;

    # Setup logging.  If there is an error, then log to STDOUT at DEBUG level with easy_init()
    my $log4perlconf      = $self->{configs}->{log4perlconf};
    my $logwatch_interval = $self->{configs}->{logwatch_interval};
    eval { Log::Log4perl->init_and_watch( $log4perlconf, $logwatch_interval ); };
    if ($@) {
        carp "Unable to initialize logging from config file >>$log4perlconf<<: $@";
        carp "Logging to STDOUT at DEBUG level\n";
        Log::Log4perl->easy_init($Log::Log4perl::DEBUG);
    }
    $logger = get_logger() || croak "Unable to get logger";
    if ( grep { $_ eq $self->{configs}->{loglevel} } qw/ DEBUG INFO WARN ERROR FATAL TRACE / ) {
        $logger->level( $self->{configs}->{loglevel} );
        $logger->info( "Log level set to " . $logger->level() );
    }

    # if ( $self->{configs}->{loglevel} ne 'Use value from log4perl.conf' ) {
    #     $logger->level( $self->{configs}->{loglevel} );
    #     $logger->info("Log level set to " . $logger->level());
    # }
    $logger->info("Logging initialized");

    return $logger;
} ## end sub setup_Logger

# Set lock file
#   Returns 1 if lock file is set, otherwise returns 0
#   This is very important to get right.  If the lock file is not set, then multiple instances of this script can 
#   cause problems.
#   Some of this is on the user but I'll try my best to make it so duplicate instances of this script can't run.
sub set_lockFile() {
    my $self = shift;

    if ( !$self->{configs}->{lockfile} ) {
        $logger->logdie("No lock file provided.  Unable to continue");
        return 0;
    }
    my $lockfile = $self->{configs}->{lockfile};

    # $self->{configs}->{lockfile} ||= $LOCKFILE;
    my $lf = $self->{configs}->{lockfile};
    $logger->debug("Lock file: $lf");

    if ( -e $lf ) {
        if ( $self->{configs}->{forceremovelockfile} ) {
            $logger->info("Removing lock file $lf because forceremovelockfile is set to 1 (true)");
            unlink $lf or $logger->logdie("Unable to remove lock file $lf: $!");
        }
        else {
            open my $fh, '<', $lf or ( $logger->logdie("Unable to open lock file $lf: $!") and return 0 );
            my @contents = <$fh>;
            close $fh;
            chomp(@contents);
            my $printable_contents = join( "\n", @contents );
            my $logmsg             = "Lock file $lf exists and contains the following: $printable_contents .";
            $logger->info($logmsg);
        } ## end else [ if ( $self->{configs}->...)]
    } ## end if ( -e $lf )

    -e $lf && $logger->logdie("Lock file $lf still exists.  Manually remove lock file. Exiting");

    # Create lock file (running pid file) or die
    $self->{lockmgr} = LockFile::Simple->make( -max => 1, -delay => 1, -hold => 0 );

    # $self->{lockmgr}->configure(  -delay => 1, -hold => 0, -max => 1  );
    $logger->debug( "Dumping lockmgr: " . Dumper( $self->{lockmgr} ) ) if ( $logger->is_debug() );
    $self->{lock} = $self->{lockmgr}->lock( 'lockhandle', $lf )
      || ( $logger->logdie("Can't create lock file at $lf .\n") and return 0 );
    $lock_obj = $self->{lock};

    $logger->info("Lock file created at $lf");
    return 1;
} ## end sub set_lockFile

## Description: Creates a thread for each log file to review
## Returns 1 or dies if thread can not be created
sub logger_thread() {
    my $self = shift;

    my $logstoreview = $self->{configs}->{logs_to_review};
    $logstoreview ||= {};

    # Create a thread for each log file to review
    foreach my $logtoreview ( sort keys %{$logstoreview} ) {
        $logger->info("Reviewing $logtoreview");
        my $logobj = $logstoreview->{$logtoreview};
        $logobj->{chain} = $logtoreview;    # Set the chain name to object value
                                            #  This is used in the create_iptables_commands() sub
        my $thr = threads->create( \&review_log, $self, $logobj ) or $logger->logdie("Unable to create thread");
        push( @$LoggerTIDS, $thr->tid() );
        $logger->debug( "Thread created for $logtoreview: " . $thr->tid() )                  if ( $logger->is_debug() );
        $logger->debug( "Thread id >>" . $thr->tid() . "<< state is " . $thr->is_running() ) if ( $logger->is_debug() );

        # $self->review_log( $logstoreview->{$log} );
    } ## end foreach my $logtoreview ( sort...)

    return 1;
} ## end sub logger_thread

sub prepare_directions() {
    my ( $self, $logobj ) = @_;
    my $TID = threads->tid;
    $TID = "TID: " . $TID;

    my @directions = $logobj->{directions} ? split( /\W+/, $logobj->{directions} ) : ();
    @directions = map  { lc($_) } @directions;
    @directions = grep { $_ eq 'source' || $_ eq 'destination' || $_ eq 'random' } @directions;
    @directions = ('random') if ( any { $_ eq 'random' } @directions );
    push @directions, 'source' unless @directions;
    return @directions;
} ## end sub prepare_directions

# This is called as a thread and runs a loop to check the log file for new entries
#   Prior to checking the log file, it creates a chain for the log file and adds it to the global chain
# This entire sub needs to be refactored. 
# It's easy to folllw but it is:
#  a) just too many lines for one sub
#  b) the for loops nesting is just too much
sub review_log() {
    my ( $self, $logobj ) = @_;
    my $TID = threads->tid;
    $TID = "TID: " . $TID;
    my $start_time = time();

    $logobj ||= {};
    my $chain = $self->{configs}->{chainprefix} . $logobj->{chain};
    $logger->info("$TID|Starting review of $logobj->{file} with chain $chain");
    $logger->debug( "$TID|Reviewing log object: " . Dumper($logobj) ) if ( $logger->is_debug() );

    # set file log values if exist, otherwise set to global values if exist else set to default values
    my $cycles          = $logobj->{cycles}     ||= LONG_MAX;
    my $cyclesleep      = $logobj->{cyclesleep} ||= 0.5;
    my $microcyclesleep = $cyclesleep * 1000000;

    $logger->info(
        "$TID|Reviewing $logobj->{file} for $logobj->{cycles} cycles with $logobj->{cyclesleep} seconds between cycles"
    );

    # Create the chain for the log file
    $logger->info("$TID|Trying to create >>$chain<< chain");
    $self->add_chain($chain);

    # Add rule for chain onto global chain
    my $globalchain = $self->{configs}->{globalchain};
    $logger->debug("$TID|Adding rule to iptablesqueue: -A $globalchain -j $chain");
    $self->iptablesqueue_enqueue( { options => "-A", rule => "$globalchain -j $chain" } ) || return 0;

    $self->add_logger_allow_deny_ips($logobj);

    # Set a few things
    my @directions = $self->prepare_directions($logobj);
    my @protocols  = $logobj->{protocols} ? split( /\W+/, $logobj->{protocols} ) : ();
    my $ports      = $logobj->{ports} || '';

    while ( $cycles > 0 ) {
        my $start_loop_time = time();
        $logger->info("$TID|$cycles cycles remaining for $logobj->{file}.");
        $logobj = $self->readlogfile($logobj);
        $logobj->{ips_to_block} = $self->_grep_regexps($logobj) if ( $logobj->{logcontents} );

        # $logobj                 = $self->clean_ips_to_block_allowdeny($logobj);

        $logger->debug( "$TID|IPs to potentially be blocked: " . Dumper( $logobj->{ips_to_block} ) )
          if ( $logger->is_debug() );

        my @rules;
        foreach my $ip ( keys %{ $logobj->{ips_to_block} } ) {
            $logger->debug("$TID|IP to potentially block: $ip");

            foreach my $direction (@directions) {
                my $direction_switch = $direction eq 'destination' ? '-d' : '-s';
                my $randval          = int( rand(2) );
                $direction_switch = int( rand(2) ) ? '-d' : '-s' if ( $direction eq 'random' );
                $logger->info("$TID|randval: $randval.  direction: $direction.  direction_switch: $direction_switch");
                my $base_rule = "$direction_switch $ip";
                $logger->debug("$TID|Base rule: $base_rule");

                if (@protocols) {
                    foreach my $protocol (@protocols) {
                        my $rule = $base_rule . " -p $protocol";
                        $logger->debug("$TID|Rule: $rule");
                        if ( $logobj->{ports} ) {

                            # As an example the following line looks something like:
                            # -m multiport --dports 80,443 -j DROP
                            $rule .= " -m multiport -$direction_switch" . "port $logobj->{ports}";
                        } ## end if ( $logobj->{ports} )
                        $logger->debug("$TID|Pushing rule: $rule");
                        push @rules, "$rule -j DROP";
                    } ## end foreach my $protocol (@protocols)
                } ## end if (@protocols)
                else {
                    $logger->debug("$TID|Pushing rule: $base_rule");
                    push @rules, "$base_rule -j DROP";
                }
            } ## end foreach my $direction (@directions)
        } ## end foreach my $ip ( keys %{ $logobj...})

        $logger->debug( "$TID|Potential rules to be added to iptablesqueue: " . Dumper( \@rules ) )
          if ( $logger->is_debug() );
        my $eject;
        foreach my $rule (@rules) {
            if ( $tracker->{iptables_rules}->{"$chain $rule"} ) {
                $logger->debug("$TID|Rule already exists in tracker: $chain $rule");
                next;
            }
            my $args = {
                options => "-w -A",
                rule    => "$chain $rule",
            };
            $logger->debug("$TID|Adding rule to iptablesqueue: -A $chain $rule");
            $tracker->{iptables_rules}->{"$chain $rule"}++;

            # Stop processing if iptablesqueue_enqueue() returns falsy
            $self->iptablesqueue_enqueue($args) || $eject++ && last;
        } ## end foreach my $rule (@rules)

        my $logmsg = "$TID|Exiting while loop for $chain. iptablesqueue_enqueue() returned falsy";
        $eject && $logger->info($logmsg) && last;

        $logobj->{ips_to_block} = {};    # Reset the ips_to_block hash

        # Check if iptables queue is still accepting commands.
        #  If not, then exit the loop
        $self->iptablesqueue_enqueue( { check_pending => 1 } ) || last;

        my $timediff = time() - $start_loop_time;
        $timediff = sprintf( "%.4f", $timediff );
        $logger->info("$TID| Review of $chain took $timediff seconds");

        last unless --$cycles;    # Break out of loop if $cycles is 0
        $logger->info("$TID|Sleeping for $cyclesleep seconds");
        usleep($microcyclesleep);
    } ## end while ( $cycles > 0 )

    my $runtime = time() - $start_time;
    $runtime = sprintf( "%.4f", $runtime );
    my $cycles_completed = $logobj->{cycles} - $cycles;
    my $logmsg           = "$TID|Finished reviewing $logobj->{file}.  Cycles completed: $cycles_completed.  ";
    $logmsg .= "  Total run time: $runtime seconds";
    $logger->info($logmsg);
    return 1;
} ## end sub review_log

# Logging is not yet setup at this point
sub load_configs {
    my $self        = shift;
    my $configsfile = $self->{configsfile};
    my $clargs      = $self->{clargs};        # Command line arguments

    if ( -r $configsfile ) {

        # $logger->info("Loading configs from $self->{configsfile}");
        $self->{configs} = Config::File::read_config_file( $self->{configsfile} );
        $self->{configs}{globalchain} = split( /,/, $self->{configs}{globalchain} )
          if ( $self->{configs}{globalchain} );

        # $logger->debug( "Configs loaded from $self->{configsfile}: " . Dumper( $self->{configs} ) );
    } ## end if ( -r $configsfile )
    else {
        my $msg = "Unable to read configs file $self->{configsfile}.  Using command line arguments and defaults. -- ";
        $msg .= "This is proably not what you want.  YMMV";
        $msg .= "The command line arguments are: " . Dumper($clargs);
        $msg .= "The defaults are: " . Dumper($DEFAULTS);
        $msg .= " ---  End of message.";
        carp($msg);
        warn($msg);
    } ## end else [ if ( -r $configsfile )]

    for my $config ( keys %{$DEFAULTS} ) {

        # Items sent in clargs (command line arguments) take precedence over configs file
        # Items sent in clargs but do not exist in the $DEFAULTS hash will be silently ignored
        $self->{configs}->{$config} =
            $clargs->{$config}
          ? $clargs->{$config}
          : $self->{configs}->{$config} || $DEFAULTS->{$config};
    } ## end for my $config ( keys %...)

    return $self->{configs};
} ## end sub load_configs

# Special helper function for clean_ips_to_block()
sub reverseMapHash() {
    my $self = shift;
    my $hash = shift;

    # $logger->debug("Hash to reverse map: " . Dumper($hash)) if ( $logger->is_debug() );

    my $new_hash = {};
    foreach my $key ( sort keys %{$hash} ) {
        $new_hash->{ $hash->{$key} }++;

        # delete $hash->{$key};
    }
    return $new_hash;
} ## end sub reverseMapHash

# Description: Combines the IPs from regex from the log to be blocked and the IPs from the allow/deny lists into
#               one hash
sub clean_ips_to_block_combined() {
    my $self   = shift;
    my $logobj = shift;
    my $TID    = threads->tid;
    $TID = "TID: " . $TID;

    local $Data::Dumper::Terse  = 1;    # Disable use of $VARn
    local $Data::Dumper::Indent = 0;    # Disable indentation

} ## end sub clean_ips_to_block_combined

# Description: Returns the logobj with ips_to_block set with the IPs to block from the allow/deny lists
#   There is a lot of logging available in this sub.
#   This sub is called from review_log()
sub clean_ips_to_block_allowdeny() {
    my $self   = shift;
    my $logobj = shift;
    my $TID    = threads->tid;
    $TID = "TID: " . $TID;

    local $Data::Dumper::Terse  = 1;    # Disable use of $VARn
    local $Data::Dumper::Indent = 0;    # Disable indentation

    # $logger->debug("Reviewing log object: " . Dumper($logobj)) if ( $logger->is_debug() );

    my $allowdeny        = $logobj->{allowdeny}          ||= $self->{configs}->{allowdeny} ||= "";
    my $logobj_allowlist = $logobj->{allowlist}          ||= $self->{configs}->{allowlist} ||= {};
    my $logobj_denylist  = $logobj->{denylist}           ||= $self->{configs}->{denylist}  ||= {};
    my $global_denylist  = $self->{configs}->{denylist}  ||= {};
    my $global_allowlist = $self->{configs}->{allowlist} ||= {};

    my $ips_to_block = $logobj->{ips_to_block} ||= {};

    # Due to the configs module, need to reverse map the allowlists and denylists
    $logobj_allowlist = $self->reverseMapHash($logobj_allowlist);
    $logobj_denylist  = $self->reverseMapHash($logobj_denylist);
    $global_allowlist = $self->reverseMapHash($global_allowlist);
    $global_denylist  = $self->reverseMapHash($global_denylist);

    # Some logging info:
    $logger->info("$TID|Allow/Deny: $allowdeny");
    $logger->debug( "$TID|Logobj allowlist: " . Dumper($logobj_allowlist) ) if ( $logger->is_debug() );
    $logger->debug( "$TID|Logobj denylist: " . Dumper($logobj_denylist) )   if ( $logger->is_debug() );
    $logger->debug( "$TID|Logobj ips_to_block: " . Dumper($ips_to_block) )  if ( $logger->is_debug() );
    $logger->debug( "$TID|Global allowlist: " . Dumper($global_allowlist) ) if ( $logger->is_debug() );
    $logger->debug( "$TID|Global denylist: " . Dumper($global_denylist) )   if ( $logger->is_debug() );

    # Combine global and logobj allowlist and denylist
    my $allowlist = { %{$global_allowlist}, %{$logobj_allowlist} };
    my $denylist  = { %{$global_denylist},  %{$logobj_denylist} };

    # More logging info:
    $logger->debug( "$TID|Combined allowlist: " . Dumper($allowlist) ) if ( $logger->is_debug() );
    $logger->debug( "$TID|Combined denylist: " . Dumper($denylist) )   if ( $logger->is_debug() );

    # Combine denylist with ips_to_block
    $denylist = { %{$denylist}, %{$ips_to_block} };

    # More logging info:
    $logger->debug( "$TID|Combined denylist with ips_to_block: " . Dumper($denylist) ) if ( $logger->is_debug() );

    # This is the meat of the function....
    ## If we Deny first then then no need to remove IPs from the denylist
    if ( $allowdeny eq 'Deny,Allow' ) {
        $logobj->{ips_to_block} = $denylist;
        $logger->debug( "$TID|Returning logobj with ips_to_block of: " . Dumper( $logobj->{ips_to_block} ) )
          if ( $logger->is_debug() );
        return $logobj;
    } ## end if ( $allowdeny eq 'Deny,Allow')
    ## If we Allow first then we need to remove IPs from the denylist
    ## The map below removes allowlist from denylist
    ## The || (or) is used to prevent undef errors
    map { delete $denylist->{$_} || $_ } keys %{$allowlist};
    $logobj->{ips_to_block} = $denylist;
    $logger->debug( "$TID|Returning logobj with ips_to_block of: " . Dumper( $logobj->{ips_to_block} ) )
      if ( $logger->is_debug() );
    return $logobj;
} ## end sub clean_ips_to_block_allowdeny

# Runs whatever parameters are passed to it against iptables
#  This is intended to be a one stop shop for running iptables out from a queue.
#  However, there are a few instances where it is called directly... especially when creating chains
#   This hopefully prevents excessive wait/locking on iptables
#   and helps to keep commands running in the order they are received.
# Arguments must be passed as a hash reference with (so far) the following keys:
#   rule:  The rule to run
#   options:  Any options to pass to iptables
#  Where it is ran like this:
#   iptables $options $rule 2>&1
# Future enhancement:
#   1. delete existing rule if it exists
# Take note this sub is intended (but not required) to be called from sub iptables_thread()
#  An error will happen if not called from sub iptables_thread(), but it will not stop the program
#  This is to encourage using the iptablesqueue_enqueue() sub instead of run_iptables() directly
#  So, to say this more clearly, if you want to run iptables commands, then call iptablesqueue_enqueue()
sub run_iptables() {
    my ( $self, $args ) = @_;
    my @caller_lst = caller(0);
    if ( $caller_lst[2] != $IPTABLESRUNLINE and $IPTABLESRUNLINE != 0 ) {
        my $logmsg =
            "Looks like the calling sub is not sub iptables_thread.  This is not good.  "
          . "Caller:\n"
          . Dumper(@caller_lst) . "\n"
          . "The calling sub was at line $caller_lst[2] and not at line $IPTABLESRUNLINE ."
          . "This will not be stopped but it should be investigated.  "
          . "Consider calling iptablesqueue_enqueue() instead of run_iptables().  "
          . "Maybe you meant to call \$self->iptablesqueue_enqueue(\$args) instead of \$self->run_iptables(\$args)";
        \$logger->error($logmsg);
    } ## end if ( $caller_lst[2] !=...)
    my $TID = threads->tid;
    $TID = "TID: " . $TID;

    # Preliminary checks
    exists $args->{rule}                || $logger->error("No rule passed to run_iptables()") && return 0;
    exists $self->{configs}->{iptables} || $logger->error("No iptables command set, this may cause problems");

    my $iptables = $self->{configs}->{iptables};
    my $rule     = $args->{rule};
    my $options  = $args->{options} ||= "";

    if ( $logger->is_debug() ) {
        $logger->debug(
            "$TID|Running run_iptables iptables command of: $iptables and with arguments: " . Dumper($args) );
    }

    # Future enhancement:  If deleteexisting is set to 1, then delete the existing rule
    # $args->{deleteexisting} ||= 0;
    # my $deleteexisting      = $args->{deleteexisting};

    # Setup value for allowdupes
    $args->{allowdupes} ||= 0;    # Default is to not allow duplicate rules
    my $allowdupes = $args->{allowdupes};

    if ( $allowdupes == 0 ) {
        $logger->debug("$TID|Checking if rule exists before adding: $options $rule");
        my $retval = $self->check_if_rule_exists($args);
        if ( $retval =~ /in tracker/ ) {
            my $logmsg = "$TID|Return value: $retval.  Rule is in the tracker.  Not adding rule: ";
            $logmsg .= "$iptables $options $rule";
            $logger->debug($logmsg);
            return 1;
        } ## end if ( $retval =~ /in tracker/)
        if ( $retval eq "rule exists" ) {

            #Since the rule exists and we are not allowing dupes, then we do not need to add the rule and
            # we return success
            $logger->debug("$TID|Rule exists.  Not adding rule: $iptables $options $rule");
            $tracker->{iptables_rules}->{$rule}++;
            return 1;
        } ## end if ( $retval eq "rule exists")
        elsif ( $retval eq "DNE" ) {
            $logger->debug("$TID|Rule does not exist.  Adding rule: $iptables $options $rule");
        }
        elsif (( $retval eq "create chain" )
            && ( $options =~ m/-N/ ) )
        {
            # Creating chains is a special case.  We just allow it to happen.
            $logger->debug("$TID|Trying to create chain: $iptables $options $rule");

            # We track the chains created so that we can remove them on exit
            $tracker->{chains_created}->{$rule}++;
        } ## end elsif ( ( $retval eq "create chain"...))
        elsif ( $retval eq "chain does not exist" ) {
            $logger->error("$TID|Chain does not exist for the rule.  Not creating rule: $iptables $options $rule");
            return 0;
        }
        elsif ( $retval eq "permission denied" ) {
            my $logmsg = "$TID|Permission denied (not root or sudo with user not set?).  ";
            $logmsg .= "Can't check if rule exists: $iptables $options $rule";
            $logger->error($logmsg);
            return 0;
        } ## end elsif ( $retval eq "permission denied")
        else {
            $logger->error( "$TID|Unknown return from check_if_rule_exists(): " . $retval );
            return 0;
        }
    } ## end if ( $allowdupes == 0 )

    my $command = "$iptables $options $rule 2>&1";
    $tracker->{iptables_rules}->{$rule}++;
    if ( $self->{configs}->{PRODMODE} ) {
        $logger->debug("$TID|Running $command");
        my $output = `$command`;
        $logger->debug("$TID|Output of iptables command: $output");
        return 1;
    } ## end if ( $self->{configs}->...)
    else {
        $logger->info("$TID|In test mode.  Would run: $command");
        return 1;
    }

    # Should not get here but by default return 0
    $logger->error("$TID|Should not get here but by default returning 0");
    return 0;
} ## end sub run_iptables

sub set_iptables_command() {
    my $self = shift;

    # If the iptables command is not set, then set it to the system location (if possible)
    $self->{configs}->{iptables} //= `which iptables`;
    chomp( $self->{configs}->{iptables} );
    $logger->info("The command to be used for iptables is $self->{configs}->{iptables}");
    return 1;
} ## end sub set_iptables_command

## Returns 0 if there is an unknown return value from running iptables
##          Otherwise returns a string
sub check_if_rule_exists {
    my ( $self, $args ) = @_;
    my $TID = threads->tid;
    $TID = "TID: " . $TID;

    # Preliminary checks
    $args->{rule}                or return $self->log_and_return("$TID|No rule passed to check_if_rule_exists");
    $self->{configs}->{iptables} or $logger->error("$TID|No iptables command set, this may cause problems");

    my $iptables = $self->{configs}->{iptables};
    my $rule     = $args->{rule};
    my $options  = $args->{options} // "";

    if ( $tracker->{chains_created}->{$rule} ) {
        $logger->debug("$TID|Chain $rule has already been ran. Returning >>chain in tracker<<");
        return "chain in tracker";
    }

    if ( $tracker->{iptables_rules}->{$rule} ) {
        $logger->debug("$TID|Rule $rule has already been ran. Returning >>rule in tracker<<");
        return "rule in tracker";
    }

    if ( $options =~ /-N/ ) {
        my $logmsg = "$TID|Rule is to create a chain.  No need to check if it exists; error will happen if it does ";
        $logmsg .= "exist and probably does not matter";
        $logger->debug($logmsg);
        return "create chain";
    } ## end if ( $options =~ /-N/ )

    my $checkrule_result = `$iptables -w -C $rule 2>&1`;
    if ( $? == 0 ) {
        $logger->debug("$TID|Rule appears to already exist. Returning >>rule exists<<");
        return "rule exists";
    }

    if ( $checkrule_result =~ /iptables: Bad rule.*does a matching rule exist in that chain.*/ ) {
        $logger->debug("$TID|Rule appears to not exist. Returning >>DNE<<");
        $logger->debug("$TID|Output of iptables: $checkrule_result");
        return "DNE";
    }

    if ( $checkrule_result =~ /iptables.*Chain.*does not exist*/ ) {
        $logger->debug("$TID|Chain does not appear to exist. Returning: >>chain does not exist<<");
        $logger->debug("$TID|Output of iptables: $checkrule_result");
        return "chain does not exist";
    }

    if ( $checkrule_result =~ /iptables.*Permission denied.*you must be root/ ) {
        $logger->debug("$TID|You do not have permmission to run iptables.  You must be root.");
        $logger->debug("$TID|Output of iptables: $checkrule_result");
        return "permission denied";
    }

    $self->log_and_return("$TID|Should not get here but by default returning 0. Output of iptables: $checkrule_result");
} ## end sub check_if_rule_exists

sub log_and_return {
    my ( $self, $error_message ) = @_;
    my $TID = threads->tid;
    $TID = "TID: " . $TID;
    $logger->error($error_message);
    return 0;
} ## end sub log_and_return

# Description: Creates the global chain and then adds a jump rule to the global chains.
#           With default values this means creating the global chain "IPBLOCKER_glopbal" and then
#           adding a jump rule to the INPUT, OUTPUT, and FORWARD tables to go to IPBLOCKER_global
# Dies if no chain prefix is set or if no global chains are set
#    Bassically, this dies if it is not called as class or correct configs are not set
# Returns 1 always
sub add_global_chain() {
    my ($self) = @_;
    my $TID = threads->tid;
    $TID = "TID: " . $TID;

    my $chain = $self->{configs}->{chainprefix} || $logger->logdie("$TID|No chain prefix set");
    $chain = $chain . "global";

    my $globalchains_str = $self->{configs}->{globalchains} || $logger->logdie("$TID|No global chains set");
    my @globalchains     = split( /,/, $globalchains_str );

    $logger->info("$TID|Adding global chain $chain");
    my $args = {
        options => "-w -N",
        rule    => "$chain",
    };
    $self->iptablesqueue_enqueue($args);

    $logger->info("$TID|Adding global chain $chain to @globalchains tables");
    for my $table (@globalchains) {
        my $args = {
            options => "-A",
            rule    => "$table -j $chain",
        };
        $self->iptablesqueue_enqueue($args);
    } ## end for my $table (@globalchains)

    return 1;
} ## end sub add_global_chain

# Description: Queues items onto the iptables queue
# Returns 1 if queue is allowing enqueuing
# Returns 0 if queue is not allowing enqueuing
sub iptablesqueue_enqueue() {
    my ( $self, $args ) = @_;
    my $TID = threads->tid;
    $TID = "TID: " . $TID;

    my $iptablesQueue_pending = eval { $IptablesQueue->pending() };
    if ( !defined $iptablesQueue_pending ) {
        my $logmsg = "$TID|IptablesQueue is in an undefined state. This is probably intentional. ";
        $logmsg .= "Returning 0";
        $logger->info($logmsg);
        return 0;
    } ## end if ( !defined $iptablesQueue_pending)
    return 1                                                                     if ( $args->{check_pending} );
    $logger->debug( "$TID|Enqueuing onto the iptables queue: " . Dumper($args) ) if ( $logger->is_debug() );
    $IptablesQueue->enqueue($args);
    return 1;
} ## end sub iptablesqueue_enqueue

# This function reads the log file into memory from the seek position (if it exists)
# The reading of a log file based on the seek position creates a big issue if the log file is rotated AND is larger than
#   the seek position
#   This is a tradeoff of reading the entire log file into memory and then grepping for the regexps
# Returns: $logobj
sub readlogfile {
    my ( $self, $logobj ) = @_;
    my $TID = threads->tid;
    $TID = "TID: " . $TID;

    # Check file is readable
    my $file = $logobj->{file} //= "/dev/null";    # Default to /dev/null if file is not set
    -r $file or ( $logger->error("Log file >>$logobj->{file}<< is not readable") && return $logobj );

    # If the readentirefile flag is set, then set the seek position to 0 to read the entire file
    $logobj->{seek} //= 0;    #It is possible the seek position is already set from a previous readlogfile() call
    $logobj->{seek} = 0 if ( -s $file < $logobj->{seek} );    #Can't seek past the end of the file
    $logobj->{readentirefile} //= $self->{configs}->{readentirefile} //= 0;
    $logobj->{seek} = 0 if ( $logobj->{readentirefile} );

    $logger->debug("$TID|Reading $file at byte position $logobj->{seek}");

    # Open and close the file handle as quickly as possible.
    # This has two major flaws:
    #   1.  If the file is rotated while open then someting bad may happen, maybe.
    #   2.  If the file is larger than we can handle in "memory", then something bad may happen, maybe.
    open my $fh, '<', $file or do {
        $logger->error("$TID|Can't open $file: $!");
        return $logobj;
    };
    seek( $fh, $logobj->{seek}, 0 );
    my @logcontents = <$fh>;
    $logobj->{seek} = tell($fh);
    close $fh;

    if ( scalar(@logcontents) ) {
        $logger->debug( "There are " . scalar(@logcontents) . " lines from $file to review" );
    }
    else {
        $logger->info("$TID|No new lines appear to be in $file");
        $logobj->{logcontents} = ();
    }

    chomp(@logcontents);
    $logobj->{logcontents} = \@logcontents;    #  Might be better to clone?  Hmmm, maybe not.

    $logger->debug( "$TID|The $file file has been read into memory.  " . scalar(@logcontents) . " lines read." );
    $logger->trace( "$TID|The $file contents: " . Dumper( $logobj->{logcontents} ) ) if ( $logger->is_trace() );

    return $logobj;
} ## end sub readlogfile

# Description:  Using the logobj, this greps against the log contents for matching lines and then gets the
#               IP address on each line.
# Returns:  Hash reference of IP addresses with count of how many times the IP address was found
sub _grep_regexps {
    my ( $self, $log ) = @_;
    my $TID = "TID: " . threads->tid;

    my $matches      = {};
    my @log_contents = @{ $log->{logcontents} };

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
} ## end sub _grep_regexps

# Description:  Adds the chain to iptables
sub add_chain() {
    my ( $self, $chain ) = @_;
    my $TID = "TID: " . threads->tid;

    $logger->info("$TID|Trying to add chain $chain");
    my $rule    = "$chain";
    my $options = "-w -N";
    my $args    = { rule => $rule, options => $options };
    $self->iptablesqueue_enqueue($args);
    $self->{chains_created}->{$chain}++;
    return 1;
} ## end sub add_chain

# Description:  Adds the IPs to DROP or ACCEPT to the chain provided
# Returns:  1
# Requires: $args to be a hash reference with the following optional keys:
#  chain:  The chain to add the rules to.  If no chain provided then the default is ipblocker_global
#  allowlist:  An array of IPs to allow
#  denylist:  An array of IPs to deny
#  allowdenyorder:  The order to add the allow and deny rules
sub add_allowdeny_ips() {
    my ( $self, $args ) = @_;
    my $TID = "TID: " . threads->tid;

    if ( ref $args ne 'HASH' ) {
        $logger->error("$TID|add_alldeny_ips() requires a hash reference as an argument");
        return 0;
    }
    my $chain = $args->{chain} ||= "ipblocker_global";

    my %ip_rules = (
        allow => $args->{allowlist} || [],
        deny  => $args->{denylist}  || []
    );

    my @allowdenyorder = qw / allow deny /;
    if ( $args->{allowdeny} eq 'Deny,Allow' ) {
        @allowdenyorder = qw / deny allow /;
    }

    $logger->debug( "$TID|IP rules: " . Dumper( \%ip_rules ) ) if $logger->is_debug();

    # foreach my $action (keys %ip_rules) {
    foreach my $action (@allowdenyorder) {
        $logger->debug("$TID|Adding $action rules to chain $chain");

        # my $chain = $args->{chain} . $action;
        my $chain       = $args->{chain};
        my $rule_action = $action eq 'allow' ? 'ACCEPT' : 'DROP';
        foreach my $ip ( sort @{ $ip_rules{$action} } ) {
            $logger->debug("$TID|Adding $action rule for IP $ip to chain $chain");
            foreach my $direction ( '-s', '-d' ) {
                my $rule = "$chain $direction $ip -j $rule_action";
                my $args = { rule => $rule, options => "-w -A" };
                $logger->debug("$TID|Adding >>-w -A $rule<< to iptables queue");
                $self->iptablesqueue_enqueue($args);
            } ## end foreach my $direction ( '-s'...)
        } ## end foreach my $ip ( sort @{ $ip_rules...})
    } ## end foreach my $action (@allowdenyorder)

    return 1;
} ## end sub add_allowdeny_ips

# Description:  Adds the IPs to block or accept from the configs global allowlist and global denylist to the global chain
# Returns:  1
sub add_global_allow_deny_ips() {
    my ($self) = @_;
    my $TID = "TID: " . threads->tid;

    $logger->debug("$TID|Adding global allow/deny IPs to global chains");
    my $chain     = $self->{configs}->{chainprefix} . "global";
    my @allowlist = ( map { $self->{configs}->{allowlist}->{$_} } sort keys %{ $self->{configs}->{allowlist} } );
    my @denylist  = ( map { $self->{configs}->{denylist}->{$_} } sort keys %{ $self->{configs}->{denylist} } );
    my $allowdeny = $self->{configs}->{allowdeny} ||= 'Allow,Deny';

    my $args = {
        chain     => $chain,
        allowlist => \@allowlist,
        denylist  => \@denylist,
        allowdeny => $allowdeny
    };

    $logger->debug( "$TID|Args to add_allowdeny_ips(): " . Dumper($args) ) if $logger->is_debug();

    return $self->add_allowdeny_ips($args);
} ## end sub add_global_allow_deny_ips

sub add_logger_allow_deny_ips() {
    my ( $self, $logobj ) = @_;
    my $TID = "TID: " . threads->tid;

    $logger->debug("$TID|Adding logger allow/deny IPs to logger chain $logobj");
    my $chain     = $self->{configs}->{chainprefix} . $logobj->{chain};
    my @allowlist = ( map { $logobj->{allowlist}->{$_} } sort keys %{ $logobj->{allowlist} } );
    my @denylist  = ( map { $logobj->{denylist}->{$_} } sort keys %{ $logobj->{denylist} } );
    my $allowdeny = $logobj->{allowdeny} ||= 'Allow,Deny';

    my $args = {
        chain     => $chain,
        allowlist => \@allowlist,
        denylist  => \@denylist,
        allowdeny => $allowdeny
    };

    $logger->debug( "$TID|Args to add_allowdeny_ips(): " . Dumper($args) ) if $logger->is_debug();

    return $self->add_allowdeny_ips($args);

} ## end sub add_logger_allow_deny_ips

# sub add_global_allow_deny_ips {
#     my ($self) = @_;
#     my $TID = "TID: " . threads->tid;
#     $logger->debug("$TID|Adding global allow/deny IPs to global chains");

#     my %ip_rules = (
#         allow => $self->{configs}->{allowlist} || {},
#         deny  => $self->{configs}->{denylist}  || {}
#     );

#     $logger->debug("$TID|IP rules: " . Dumper(\%ip_rules)) if $logger->is_debug();

#     foreach my $action (keys %ip_rules) {
#         my $chain = "ipblocker_global" . $action;
#         my $rule_action = $action eq 'allow' ? 'ACCEPT' : 'DROP';
#         foreach my $ruleorder (sort keys %{$ip_rules{$action}}) {
#             my $ip = $ip_rules{$action}{$ruleorder};
#             foreach my $direction ('-s', '-d') {
#                 # my $chain = $chain_prefix . ($direction eq '-s' ? '' : 'regex') . $action;
#                 my $rule = "$chain $direction $ip -j $rule_action";
#                 my $args = { rule => $rule, options => "-w -A" };

#                 $logger->debug("$TID|Adding >>-w -A $rule<< to iptables queue");
#                 $self->iptablesqueue_enqueue($args);
#             }
#         }
#     }

#     return 1;
# }

# Stops the module
#  Future enhancements:
#   Clear the thread queues
sub stop() {
    my ( $self, $args ) = @_;
    my $TID = threads->tid;
    $TID = "TID: " . $TID;
    $logger->info("Setting DataQueue and IptablesQueue to end");

    my $chains_created = $args->{chains_created} ||= {};
    $logger->debug( "$TID|Dump of tracker: " . Dumper($tracker) ) if $logger->is_debug();

    # Removing chains that were created (or tried to be created)
    if ( $self->{chains_created} || $chains_created ) {
        $logger->info("$TID|Removing chains that were created (or tried to be created)");
        foreach my $chain ( sort keys %{ $self->{chains_created} } ) {
            $logger->info("$TID|Removing chain $chain");
            $IptablesQueue->enqueue(
                {
                    options => qq/-w -X/,
                    rule    => qq/$chain/
                }
            );
        } ## end foreach my $chain ( sort keys...)
    } ## end if ( $self->{chains_created...})
    else {
        $logger->info("$TID|No list of chains to remove.  Maybe kill 3 was issued instead of a polite stop");
    }

    $logger->info("$TID|Clearing queues (error will be logged if there is an issue)");
    clear_queues() || $logger->error("Unable to clear queues");
    $logger->info("$TID|Waiting for threads to finish (join) (error will be logged if there is an issue)");
    join_threads() || $logger->error("Unable to join threads");

    $logger->info("$TID|Releasing lock");
    $lock_obj->release;
    $logger->info("$TID|Bye bye");
} ## end sub stop

# Joins all threads
#   Simple sub but really needs some rework
#   If a thread is taking a while to join then it will block the other threads from joining
#   Some of the threads could be reading a log file and if the log file is large then it could take a while or
#   if the log file is causing soem kind of blocking for reading then it could take a while.
#   This may be an issue, if an example, if trying to read a file across NFS or SSHFS and there is a network issue.
sub join_threads() {
    my $TID = threads->tid;
    $TID = "TID: " . $TID;
    $logger->debug("$TID|Waiting for threads to finish (join)");
    $_->join() for threads->list();
    return 1;
} ## end sub join_threads

# Clears the queues
sub clear_queues() {
    my $TID = threads->tid;
    $TID = "TID: " . $TID;
    $logger->debug("$TID|Clearing queues");
    $DataQueue->end();
    $IptablesQueue->end();
    while ( $DataQueue->pending() || $IptablesQueue->pending() ) {
        $DataQueue->pending()     && $logger->debug("Data still in DataQueue");
        $IptablesQueue->pending() && $logger->debug("Data still in IptablesQueue");
        sleep 1;
    }

    if ( $DataQueue->pending() || $IptablesQueue->pending() ) {
        $logger->error("$TID|Data still in queue.  This may be an issue.");
        return 0;
    }
    else {
        $logger->debug("$TID|No queued items in DataQueue or IptablesQueue");
        return 1;
    }
} ## end sub clear_queues

sub reload() {
    my $TID = threads->tid;
    $TID = "TID: " . $TID;
    $logger->info("$TID|Reloading not yet implemented.  Do a CTRL-C (SIG_INT) and restart the module");

    # Need to figure out how to bless(re-bless) the $self object so that configs are reloaded into $self->{configs}

    ##### Things that may or may noot work.......
    # clear_queues() || $logger->error("Unable to clear queues");
    # join_threads() || $logger->error("Unable to join threads");

    # $logger->info("Reloading configs");
    # $self->load_configs();
    # $logger->info("Reloading logging");
    # $self->setup_Logger();
    # $logger->info("Reloading iptables command");
    # $self->set_iptables_command();
    # $logger->info("Reloading lock file");
    # $self->set_lockFile();
    # $logger->info("Reloading global chains");
    # $self->add_global_chains_to_input_output();
    # $logger->info("Reloading log files");
    # $self->logger_thread();
    # $logger->info("Reloading iptables thread");
    # $self->iptables_thread();
    # $logger->info("Reloading dataQueue_runner");
    # $self->dataQueue_runner();
} ## end sub reload

#Description: This sub is run when signal interrupt is caught
#  This is ctrl-c (not yet fully implemented)
sub SIG_INT {
    $logger->info("Caught interrupt signal");
    stop();
    exit 0;
}

#Description: This sub is run when signal hup is caught
#  Request to reload configs (not yet fully implemented)
sub SIG_HUP {
    $logger->info("Caught HUP signal");
    reload();
}

#Description: This sub is run when signal term is caught
#  Request to gracefully quit  (not yet fully implemented)
sub SIG_TERM {
    $logger->info("Caught TERM signal");
    stop();
}

#Description: This sub is run when signal quit is caught
#  Request to less than gracefully quit  (not yet fully implemented)
sub SIG_QUIT {
    my $self = shift;
    stop();
}

sub set_signal_handler() {
    $logger->info("Setting signal handlers");

    $SIG{INT}  = \&SIG_INT;
    $SIG{TERM} = \&SIG_TERM;
    $SIG{HUP}  = \&SIG_HUP;
    $SIG{QUIT} = \&SIG_QUIT;
} ## end sub set_signal_handler

=head1 AUTHOR

Jeff Gardner, C<< <jeffreygiraffe at cpan.org> >>

=head1 BUGS

Please report any bugs or feature requests to C<bug-net-ipblocker at rt.cpan.org>, or through
the web interface at L<https://rt.cpan.org/NoAuth/ReportBug.html?Queue=Net-IPBlocker>.  I will be notified, and then you'll
automatically be notified of progress on your bug as I make changes.




=head1 SUPPORT

You can find documentation for this module with the perldoc command.

    perldoc Net::IPBlocker


You can also look for information at:

=over 4

=item * RT: CPAN's request tracker (report bugs here)

L<https://rt.cpan.org/NoAuth/Bugs.html?Dist=Net-IPBlocker>

=item * CPAN Ratings

L<https://cpanratings.perl.org/d/Net-IPBlocker>

=item * Search CPAN

L<https://metacpan.org/release/Net-IPBlocker>

=back


=head1 ACKNOWLEDGEMENTS


=head1 LICENSE AND COPYRIGHT

This software is Copyright (c) 2024 by Jeff Gardner.

This is free software, licensed under:

  The Artistic License 2.0 (GPL Compatible)


=cut

1; # End of Net::IPBlocker
