package Net::IPBlocker;

use 5.8.0;
use strict;
use warnings;
use POSIX qw(LONG_MAX);
use DateTime;
use File::Basename;
use List::Util qw(any);
use Time::HiRes qw(usleep gettimeofday time);
use Config::File;
use Carp;
use Log::Any qw($log);  # Allegedly handles lots of different logging modules
use Data::Dumper;
use Regexp::IPv6     qw($IPv6_re);
use LockFile::Simple qw(lock trylock unlock);
use File::Path       qw(make_path);
use lib;
# use Net::Ifconfig::Wrapper;  # Not yet implemented

# Thread setup
use threads;
# use threads::shared;
use Thread::Queue;
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
my $logger;     # This gets set in new() but is just set to $log from Log::Any
                # I wrote all this for Log::Log4perl and then realized Log::Any is the better path.
my $lock_obj;    # This is the lock object and is set in set_lockFile()
                 # Needs to be global because it is used in the signal interupts and those use prototyped subs.
## Regex for IPv4 and IPv6 capturing.
#   This is critical and needs be consistent across the entire module
#   Do not use "Regexp::IPv4 qw($IPv4_re);"  --- it does not work (or at least I couldn't get it to work) for grabbing
#   IPv4's in strings
my $REGEX_IPV4 = q/\b((?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?))\b/;
my $REGEX_IPV6      = q/\b($IPv6_re)\b/;
my $IPTABLESRUNLINE = 0;    #This is just an odd one.  It is used to track the line number of the sub iptables_thread()
                            #  where run_iptables() is called.  This is used in the signal interupts to print out the
                            #  line number of where the iptables command was run.  This is used for debugging.
                            #  This is set in the iptables_thread() sub.
our $tracker = {};          # Mostly chains added and rules added are stuffed in here for tracking purposes
                            # There has got to be a better way but for now it is just a global hash reference.

# Default configs.  Almost all of these can be set in a config file.
my $DEFAULTS = {
    allowdeny            => 'Allow,Deny',
    allowlist            => {},
    configsfile          => '/etc/ipblocker/ipblocker.conf',
    cycles               => LONG_MAX,   # How many times to check a log file.  LONG_MAX is the default.
    cyclesleep           => 0.5,        # How many seconds to sleep between checking a log file.
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
    logcontents          => {},
    # loglevel             => 'INFO',
    logs_to_review       => {},
    minlogentrytime      => 300,                                # This is the minimum time to put something in the logs to let you know
                                                                #  the module is still running.  This is in seconds.
    prodmode             => 0,
    queuechecktime       => 1,
    queuecycles          => LONG_MAX,
    readentirefile       => 0,
    totalruntime         => LONG_MAX,  # How long to run in seconds.  This is irrespective of any other cycle or queue 
                                    # cycle.  Nice for testing or maybe you want to run this for a certain amount of 
                                    # time and restart it out of cron or something.
};

=head1 NAME

Net::IPBlocker - Blocks IPs based on regex from specified log files

=head1 VERSION

Version 0.10

=cut

our $VERSION = '0.10';


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

=item * Add reload ability of configs

This will make it so a full stop and restart does not need to happen to reload configs.

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

This really findes the IPs on a network interface and adds them to the global allow list.
Usually,we don't want to accidentally block our own IPs.
Of course, this will mean adding an option to the configs file to turn this on or off.

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

Reads configs from a file if exists otherwise uses defaults.
Sets up a class and returns a blessed "object".
The sub go() is where the action starts.
The sub new() just gets a few things setup.

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
    ### All configs can be set via a hash reference
  };

  my $ipb    = IPblocker->new($args);

=head3 All arguments to new() and the defaults

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
None of my relationships lasted forever and I don't think you running this module should be indefinite. 

=head4 readentirefile

readentirefile    => 0,

This is a true/false value.  If set to 1 (true), then the entire log file is read.  If set to 0 (false), then only
new entries since the last run are read.
This can aslo be set per log file in the configs file.

=head4 totalruntime

totalruntime      => LONG_MAX,

How long to run in seconds.  This is irrespective of any other cycle or queue cycle.  Nice for testing or maybe you
want to run this for a certain amount of time and restart it out of cron or something.

=cut

# Description:  Creates a new class/object
# Returns:      A blessed reference "object"
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
    $logger = $log;  #From Log::Any
    $logger->context->{TID} = "Thread:main:tid:" . threads->tid;
    $logger->info("Logging initialized and ready to go");
    $logger->debug( "Dumping self: " . Dumper($self) ) if ( $logger->is_debug() ); 

    return $self;
} ## end sub new

# Description:  Recursively prints the configs in teh format of a config file
# Returns:      Nothing
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
As an example, if you have 5 files to watch, then there will be 5 threads watching those files + 1 thread to add commands to 
iptables.  Worst case scenario, you may need 1 CPU per thread (at most).  
However, that is very unlikely because the timing of processing will vary and it is not really a 1:1 ratio.

=cut

# Description:  Starts the module
# Requires:     $self
# Returns:      1 if able to stop gracefully, otherwise 0
sub go() {
    my ($self) = @_;
    my $start_time = time();
    $self->{configs}->{start_time} = $start_time;
    # local $logger->context->{TID} = "Thread:main:tid:" . threads->tid; 

    # If there are no log files to review, then there is nothing to do
    unless ( $self->{configs}->{logs_to_review} ) {
        $logger->error("No logs defined in configs to review");
        return 0;
    }

    # Set a few items
    $self->set_iptables_command() or $logger->error("Unable to set iptables command");
    $self->set_signal_handler();
    $self->{configs}->{globalchain} = $self->{configs}->{chainprefix} . "global";
    $self->set_lockFile() or $logger->fatal("Unable to set lock file") and return 0;

    # $self->add_ifconfig_ips_to_allowlist() if ( $self->{configs}->{ignoreinterfaceips} );  # Not yet implemented

    # Create iptables queueing and thread for commands to run against iptables
    my $iptables_thr = threads->create( \&iptables_thread, $self );

    # Create the global chain and add it to the global chains
    $self->add_global_chain();

    # Add the global allow and deny IPs to the global allow and deny chains
    $self->add_global_allow_deny_ips();

    # Create a thread for each logger watcher
    $logger->fatal("Unable to review logs") and die "Unable to review logs" unless ( $self->logger_thread() );

    # This sub just continually checks the queue and provides a small amount of logging  
    $self->_go_while();

    my $runtime = time() - $start_time;
    $runtime = sprintf( "%.4f", $runtime );
    $logger->info("Module runtime: $runtime second(s)");
    $logger->info("Trying to run a graceful stop....");
    my $args = {
        chains_created => $tracker->{chains_created},
    };
    $self->stop( $args ) && return 1;
    $logger->error("Unable to complete a graceful stop.  Exiting the hard way.");
    return 0;
} ## end sub go

# Description:  Just a sub for go() to continually check the queue and provide a small amount of logging
# Requires:     $self
# Returns:      1 when the queue is "end"ed or "totalruntime" is has reached 0.
sub _go_while {
    my $self = shift;
    my $start_time = $self->{configs}->{start_time};
    my $totalruntime = $self->{configs}->{totalruntime};
    my $timeleft     = $totalruntime;
    my $minlogentrytime = $self->{configs}->{minlogentrytime};
    while ( $timeleft ) {
        $timeleft--;
        $minlogentrytime--;
        sleep 1;
        my $queuestate = $IptablesQueue->pending();
        my $iptablesQueue_pending = eval { $IptablesQueue->pending() };
        if ( !defined $iptablesQueue_pending ) {
            my $logmsg = "IptablesQueue is in an undefined state. This is probably intentional. ";
            $logmsg .= "Exiting.";
            $logger->info($logmsg);
            return 1;
        } ## end if ( !defined $iptablesQueue_pending)
        if ( !$minlogentrytime ) {
            $minlogentrytime = $self->{configs}->{minlogentrytime};
            my $logmsg = "Maximum runtime remaining: $timeleft second(s).  ";
            $logmsg .= sprintf("Elapsed time: %0.3f second(s) out of %d second(s).  ", 
                        (time() - $start_time), $totalruntime 
                    );
            $logmsg .= "Queue length: " . $IptablesQueue->pending() . ".  ";
            $logmsg .= "Next entry in $minlogentrytime second(s).  ";
            $logger->info($logmsg);
        }        
    } ## end while ($cycles)    

    return 1;
}

# Description:  Manages an iptables queue in a continuous loop, handling queue items, logging status, and pausing 
#               based on configuration settings.
# Requires:     $self
sub iptables_thread() {
    my ($self) = @_;
    local $logger->context->{TID} = "Thread:queuewatcher:tid:" . threads->tid;

    $SIG{'KILL'} = sub { 
            $logger->info("IptablesQueue thread is being killed.  Exiting the thread.");
            threads->exit(); 
        };   # This needs to be much better.  A future enhancement

    my $cyclesleep = $self->{configs}->{queuechecktime};
    my $cycles     = $self->{configs}->{queuecycles};
    my $cyclesleft = $cycles;
    my $logmsg     = "Starting iptables queue watching thread with $cycles cycles and $cyclesleep seconds";
    $logmsg .= " between cycles";
    $logger->info($logmsg);

    while (1) {
        my $iptablesQueue_pending = eval { $IptablesQueue->pending() };
        if ( !defined $iptablesQueue_pending ) {
            my $logmsg = "IptablesQueue is in an undefined state. This is probably intentional. ";
            $logmsg .= "Exiting the IP Tables Thread.";
            $logger->info($logmsg);
            last;
        } ## end if ( !defined $iptablesQueue_pending)

        if ( $iptablesQueue_pending > 0 ) {
            $logger->debug("Queue length of IptablesQueue is $iptablesQueue_pending");
            my $data = $IptablesQueue->dequeue();
            $logger->debug( "Dequeued from IptablesQueue: " . Dumper($data) ) if $logger->is_debug();
            my $now = time();
            $self->run_iptables($data) || $logger->error( "Not successful running iptables command: " . Dumper($data) );
            $IPTABLESRUNLINE = __LINE__;               # See commentary way above about this variable
            $IPTABLESRUNLINE = $IPTABLESRUNLINE - 1;
            my $elapsed = time() - $now;
            $elapsed = sprintf( "%.4f", $elapsed );
            $logger->debug("Iptables command took $elapsed second(s) to run");
        } ## end if ( $iptablesQueue_pending...)
        elsif ( $iptablesQueue_pending == 0 ) {
            # This is a bit of extra logging but if we are at this point, speed is not an issue
            if ( $logger->is_debug() ) {
                my $logmsg = "IptablesQueue depth is 0 so sleeping for $cyclesleep second";
                $logmsg .= "s" if ( $cyclesleep != 1 );
                $logmsg .= ".";
                $logger->debug($logmsg);
            }
            usleep $cyclesleep * 1000000;
            $cyclesleft--;
            if ( $cyclesleft <= 0 ) {
                $logger->info("IptablesQueue thread has completed $cycles cycle(s). Setting queue to end.");
                $IptablesQueue->end();
            } ## end if ( $cyclesleft <= 0)            
        } ## end elsif ( $iptablesQueue_pending...)
        else {
            $logger->error("IptablesQueue queue is in an unknown state. Exiting due to an unknown issue.");
            last;
        }
    } ## end while (1)
} ## end sub iptables_thread

# Description:  Adds IPs on the local interfaces to the global allowlist
#               This does not work because it only handles IPv4 addresses and other issues
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

# Description:  Sets the lock file
#               This is very important to this module.  If the lock file is not set, then multiple instances of this
#               script can cause problems.
#               Some of this is on the user but I'll try my best to make it so duplicate instances of this script
#               can't run.
# Requires:     $self->{configs}->{lockfile}
# Returns:      1 if able to set lock file, otherwise die happens
sub set_lockFile() {
    my $self = shift;

    if ( !$self->{configs}->{lockfile} ) {
        $logger->fatal("No lock file provided.  Unable to continue");
        die "No lock file provided.  Unable to continue";
        return 0;
    }
    my $lockfile = $self->{configs}->{lockfile};

    # $self->{configs}->{lockfile} ||= $LOCKFILE;
    my $lf = $self->{configs}->{lockfile};
    $logger->debug("Lock file: $lf");

    if ( -e $lf ) {
        if ( $self->{configs}->{forceremovelockfile} ) {
            $logger->info("Removing lock file $lf because forceremovelockfile is set to 1 (true)");
            unlink $lf or $logger->fatal("Unable to remove lock file $lf: $!") and return 0;
        }
        else {
            open my $fh, '<', $lf or ( $logger->fatal("Unable to open lock file $lf: $!") and return 0 );
            my @contents = <$fh>;
            close $fh;
            chomp(@contents);
            my $printable_contents = join( "\n", @contents );
            my $logmsg             = "Lock file $lf exists and contains the following: $printable_contents .";
            $logger->info($logmsg);
        } ## end else [ if ( $self->{configs}->...)]
    } ## end if ( -e $lf )

    -e $lf && $logger->fatal("Lock file $lf still exists.  Manually remove lock file. Exiting") && return 0;

    # Create lock file (running pid file) or die
    $self->{lockmgr} = LockFile::Simple->make( -max => 1, -delay => 1, -hold => 0 );

    # $self->{lockmgr}->configure(  -delay => 1, -hold => 0, -max => 1  );
    $logger->debug( "Dumping lockmgr: " . Dumper( $self->{lockmgr} ) ) if ( $logger->is_debug() );
    $self->{lock} = $self->{lockmgr}->lock( 'lockhandle', $lf )
      || ( $logger->fatal("Can't create lock file at $lf .\n") and return 0 );
    $lock_obj = $self->{lock};

    $logger->info("Lock file created at $lf");
    return 1;
} ## end sub set_lockFile

# Description: Creates a thread for each log file to review
# Requires:    $self->{configs}->{logs_to_review}
# Returns:     1 or dies if thread can not be created
sub logger_thread() {
    my $self = shift;
    # local $logger->context->{TID} = "Thread:main:tid:" . threads->tid;

    my $logstoreview = $self->{configs}->{logs_to_review};
    $logstoreview ||= {};

    # Create a thread for each log file to review
    foreach my $logtoreview ( sort keys %{$logstoreview} ) {
        $logger->info("Reviewing $logtoreview");
        my $logobj = $logstoreview->{$logtoreview};
        $logobj->{chain} = $logtoreview;    # Set the chain name to object value
                                            #  This is used in the create_iptables_commands() sub
        my $args2reviewlog = { self => $self, logobj => $logobj, };
        my $thr = threads->create( \&review_log, $args2reviewlog ) or $logger->fatal("Unable to create thread");
        push( @$LoggerTIDS, $thr->tid() );
        $logger->debug( "Thread created for $logtoreview: " . $thr->tid() )                  if ( $logger->is_debug() );
        $logger->debug( "Thread id >>" . $thr->tid() . "<< state is " . $thr->is_running() ) if ( $logger->is_debug() );
    } ## end foreach my $logtoreview ( sort...)

    return 1;
} ## end sub logger_thread

# Description:  Sets the direction of using source or destination for the iptables rules
# Requires:     $self, $logobj->{directions}
# Returns:      @directions
sub prepare_directions() {
    my ( $self, $logobj ) = @_;

    my @directions = $logobj->{directions} ? split( /\W+/, $logobj->{directions} ) : ();
    @directions = map  { lc($_) } @directions;
    @directions = grep { $_ eq 'source' || $_ eq 'destination' || $_ eq 'random' } @directions;
    @directions = ('random') if ( any { $_ eq 'random' } @directions );
    push @directions, 'source' unless @directions;
    return @directions;
} ## end sub prepare_directions

# Description:  Gets the log review module or sets to the default
#               The log review module is the module that actually reads the log file and determisn what to do with IPs
#               It can do other things as well.  The LogReviewDefault module is the default module.
#               We do not use "use" because we don't want this to load at compile.  So, we use "require" instead.
# Requires:     $self, $logobj
# Returns:      $module
sub get_reviewlog_module {
    my ($self, $logobj) = @_;

    if ( $logobj->{libpath} ) {
        $logger->debug("Importing libpath: $logobj->{libpath}");
        lib->import($logobj->{libpath});
    }
    my $module = $logobj->{module} || 'Net::IPBlocker::ReviewLogDefault';

    $logger->debug("Trying to require $module");
    if ( $module =~ m/::/ ) {
        $logger->debug("Module has :: in it.  Trying to require $module");
        eval "require $module";
    } else {
        $logger->debug("Module does not have :: in it.  Trying to require $module");
        eval require $module;
    }

    if ($@) {
        $logger->error("Unable to require $module: $@");
        return 0;
    }
    $logger->info("Successfully required $module");

    if ( $module->can('new') ) {
        my $newargs = {
            logobj => $logobj,
            parentobjself => $self,
            iptablesqueue_enqueue => \&iptablesqueue_enqueue,
        };
        $module = $module->new($newargs);
        $logger->debug("Module >>$module<< has a sub called new.");
    } else {
        $logger->error("Module >>$module<< does not have a new sub.  This is not required but is encouraged.");
    }

    return $module
}

# Description:  Reads the log file and adds IPs to the iptables queue 
#               This is called as a thread and runs a loop to check the log file for new entries
#               Prior to checking the log file, it creates a chain for the log file and adds it to the global chain
# Future:       This entire sub needs to be refactored.
#               It's easy to follow but it is:
#                 a) just too many lines for one sub
#                 b) way too heavily nested!
# Requires:     $self, $logobj
# Returns:      1 (usually) but could return 0 if something goes wrong
sub review_log() {
    my $args = @_;
    my $self = $args->{self};
    my $logobj = $args->{logobj};
    local $logger->context->{TID} = "Thread:$logobj->{chain}:tid:" . threads->tid;
    $logger->info("Starting review_log for $logobj->{file}");

    $SIG{'KILL'} = $self->_handle_kill_signal_for_review_log($self, $args);

    my $start_time = time();

    # Get the right sub for reviewing the log
    my $reviewlogmodule = $self->get_reviewlog_module($logobj) or return 0;

    $logobj ||= {};
    my $chain = $self->{configs}->{chainprefix} . $logobj->{chain};

    # set file log values if exist, otherwise set to global values if exist else set to default values
    my $cycles          = $logobj->{cycles}     ||= ( $self->{configs}->{cycles} - 1 );
    $logger->info("Reviewing $logobj->{file} for $cycles cycles.");
    my $cyclesleft      = $cycles;
    my $cyclesleep      = $logobj->{cyclesleep} ||= $self->{configs}->{cyclesleep};
    my $microcyclesleep = $cyclesleep * 1000000;

    $self->add_chain($chain);

    # Add rule for chain onto global chain
    my $globalchain = $self->{configs}->{globalchain};
    $self->iptablesqueue_enqueue( { options => "-A", rule => "$globalchain -j $chain" } ) || return 0; 

    $self->add_logger_allow_deny_ips($logobj);

    # Set a few things
    my @directions = $self->prepare_directions($logobj);
    my @protocols  = $logobj->{protocols} ? split( /\W+/, $logobj->{protocols} ) : ();
    my $ports      = $logobj->{ports} || '';

    $self->_process_logfile( { 
        start_time          => $start_time, 
        logobj              => $logobj, 
        reviewlogmodule     => $reviewlogmodule, 
        chain               => $chain, 
        cyclesleft          => $cyclesleft, 
        cyclesleep          => $cyclesleep, 
        microcyclesleep     => $microcyclesleep, 
        directions          => \@directions, 
        protocols           => \@protocols, 
    } );
    # while ( $cyclesleft > 0 ) {
    #     my $start_loop_time = time();
    #     $logger->debug("$cyclesleft cycles remaining for $logobj->{file}.");
    #     $logobj = $self->readlogfile($logobj);
    #     $logobj->{ips_to_block} = $reviewlogmodule->grep_regexps($logobj) || {};

    #     my @rules;
    #     $self->_create_rules( { 
    #         logobj          => $logobj, 
    #         reviewlogmodule => $reviewlogmodule, 
    #         rules           => \@rules, 
    #         directions      => \@directions, 
    #         protocols       => \@protocols, 
    #     } );

    #     my $retval = $self->_enqueue_rules_from_review_log({
    #         logobj          => $logobj,
    #         tracker         => $tracker,
    #     });

    #     $retval || $logger->info("_enqueue_rules_from_review_log() returned falsy") && last;
    #     $self->iptablesqueue_enqueue( { check_pending => 1 } ) || last;

    #     $reviewlogmodule->can('post_enqueue') && $reviewlogmodule->post_enqueue($logobj);

    #     my $timediff = sprintf( "%.4f", time() - $start_loop_time );
    #     $logger->debug("Review of $chain took $timediff seconds");

    #     last unless --$cyclesleft;    # Break out of loop if $cyclesleft is 0
    #     $logger->debug("Sleeping for $cyclesleep seconds");
    #     usleep($microcyclesleep);
    # } ## end while ( $cyclesleft > 0 )

    my $runtime = time() - $start_time;
    $runtime = sprintf( "%.4f", $runtime );
    my $cycles_completed = $logobj->{cycles} - $cyclesleft;
    my $logmsg           = "Finished reviewing $logobj->{file}.  Cycles completed: $cycles_completed";
    $logmsg .= "  out of $cycles requested. Total run time: $runtime seconds";
    $logger->info($logmsg);
    return 1;
} ## end sub review_log 


sub _process_logfile() {
    my ($self, $args) = @_;
    my $start_time = $args->{start_time};
    my $logobj = $args->{logobj};
    my $reviewlogmodule = $args->{reviewlogmodule};
    my $chain = $args->{chain};
    my $cyclesleft = $args->{cyclesleft};
    my $cyclesleep = $args->{cyclesleep};
    my $microcyclesleep = $args->{microcyclesleep};
    my @directions = @{$args->{directions}};
    my @protocols = @{$args->{protocols}};

    while ( $cyclesleft > 0 ) {
        my $start_loop_time = time();
        $logger->debug("$cyclesleft cycles remaining for $logobj->{file}.");
        $logobj = $self->readlogfile($logobj);
        $logobj->{ips_to_block} = $reviewlogmodule->grep_regexps($logobj) || {};

        my @rules;
        @rules = $self->_create_rules( { 
                    logobj          => $logobj, 
                    reviewlogmodule => $reviewlogmodule, 
                    rules           => \@rules, 
                    directions      => \@directions, 
                    protocols       => \@protocols, 
                } );

$logger->logdie("jeff jeff jeff Rules: " . Dumper(\@rules));
die;
exit 0;

        my $retval = $self->_enqueue_rules_from_review_log({
            logobj          => $logobj,
            tracker         => $tracker,
        });

        $retval || $logger->info("_enqueue_rules_from_review_log() returned falsy") && last;
        $self->iptablesqueue_enqueue( { check_pending => 1 } ) || last;

        $reviewlogmodule->can('post_enqueue') && $reviewlogmodule->post_enqueue($logobj);

        my $timediff = sprintf( "%.4f", time() - $start_loop_time );
        $logger->debug("Review of $chain took $timediff seconds");

        last unless --$cyclesleft;    # Break out of loop if $cyclesleft is 0
        $logger->debug("Sleeping for $cyclesleep seconds");
        usleep($microcyclesleep);
    } ## end while ( $cyclesleft > 0 )

}

sub _enqueue_rules_from_review_log() {
    my ($self, $args) = @_;
    my $logobj = $args->{logobj};
    my $tracker = $args->{tracker};

    foreach my $rule (@{$logobj->{enqueued_rules}}) {
        $tracker->{iptables_rules}->{"$rule->{options} $rule->{rule}"} && next;
        $tracker->{iptables_rules}->{"$rule->{options} $rule->{rule}"}++;
        $self->iptablesqueue_enqueue($rule) || $logger->info("iptablesqueue_enqueue() returned falsy") && return 0;
    }

    return 1;
}

sub _create_rules() {
    my ( $self, $args ) = @_;
    my $logobj = $args->{logobj};
    my $reviewlogmodule = $args->{reviewlogmodule};
    my @rules = @{$args->{rules}};
    my @directions = @{$args->{directions}};
    my @protocols = @{$args->{protocols}};

    foreach my $ip ( keys %{ $logobj->{ips_to_block} } ) {
        foreach my $direction (@directions) {
            my $direction_switch = $direction eq 'destination' ? '-d' : '-s';
            $direction_switch = int( rand(2) ) ? '-d' : '-s' if ( $direction eq 'random' );
            my $base_rule = "$direction_switch $ip";

            scalar @protocols || push( @rules, "$base_rule -j DROP" ) && next;
            @rules = $self->_push_protocols( { 
                base_rule           => $base_rule, 
                direction_switch    => $direction_switch, 
                logobj              => $logobj, 
                protocols           => \@protocols, 
                rules               => \@rules,
                } 
            );
        } ## end foreach my $direction (@directions)
    } ## end foreach my $ip ( keys %{ $logobj...})
    return @rules;
}

sub _push_protocols() {
    my ( $self, $args ) = shift;
    my $base_rule = $args->{base_rule};
    my $direction_switch = $args->{direction_switch};
    my $logobj = $args->{logobj};
    my @protocols = @{$args->{protocols}};
    my @rules = @{$args->{rules}};

    foreach my $protocol (@protocols) {
        my $rule = $base_rule . " -p $protocol";
        $rule .= " -m multiport -$direction_switch" . "port $logobj->{ports}" if ( $logobj->{ports} );
        push @rules, "$rule -j DROP";
    } ## end foreach my $protocol (@protocols)
    return @rules;
}

sub _handle_kill_signal_for_review_log {
    my ($self, $args) = @_;
    $SIG{'KILL'} = sub {
        $self->{logger}->info("Review log thread is being killed. Exiting the thread right now.");
        threads->exit();
    };
}

# Description:  Reads the log file (if one exists) from $self->{configsfile}
#               If $args is passed to new(), then clargs (command line arguments) will override the configs file
# Requires:     $self
# Returns:      $configs (hash reference of the configs)
sub load_configs {
    my $self        = shift;
    my $configsfile = $self->{configsfile};
    my $clargs      = $self->{clargs};        # Command line arguments

    if ( -r $configsfile ) {
        # $logger->info("Loading configs from $self->{configsfile}");
        $self->{configs} = Config::File::read_config_file( $self->{configsfile} );
        $self->{configs}{globalchain} = split( /,/, $self->{configs}{globalchain} )
          if ( $self->{configs}{globalchain} );
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

# Description:  Runs iptables commands.  This is intended to be a one stop shop for running iptables out from a queue.
#               However, there are a few instances where it is called directly... especially when creating chains
#               This hopefully prevents excessive wait/locking on iptables and helps to keep commands running in the
#               order they are received.
#               If the calling sub is not sub iptables_thread, then an error is thrown but the program continues.
#               This is to encourage using the iptablesqueue_enqueue() sub instead of run_iptables() directly.
# Arguments:    $self, $args (hash reference)
#               $args->{rule} (string) - The rule to run
#               $args->{options} (string) - Any options to pass to iptables (like -N or -A)
# Returns:      1 if successful, otherwise 0
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
        $logger->error($logmsg);
    } ## end if ( $caller_lst[2] !=...)

    # Preliminary checks
    exists $args->{rule}                || $logger->error("No rule passed to run_iptables()") && return 0;
    exists $self->{configs}->{iptables} || $logger->error("No iptables command set, this may cause problems");

    my $iptables = $self->{configs}->{iptables};
    my $rule     = $args->{rule};
    my $options  = $args->{options} ||= "";

    if ( $logger->is_debug() ) {
        $logger->debug(
            "Running run_iptables iptables command of: $iptables and with arguments: " . Dumper($args) );
    }

    # Future enhancement:  If deleteexisting is set to 1, then delete the existing rule
    # $args->{deleteexisting} ||= 0;
    # my $deleteexisting      = $args->{deleteexisting};

    # Setup value for allowdupes
    $args->{allowdupes} ||= 0;    # Default is to not allow duplicate rules
    my $allowdupes = $args->{allowdupes};

    if ( $allowdupes == 0 ) {
        $logger->debug("Checking if rule exists before adding: $options $rule");
        my $retval = $self->check_if_rule_exists($args);
        if ( $retval =~ /in tracker/ ) {
            my $logmsg = "Return value: $retval.  Rule is in the tracker.  Not adding rule: ";
            $logmsg .= "$iptables $options $rule";
            $logger->debug($logmsg);
            $logger->info("Rule is in tracker.  Not adding rule: $iptables $options $rule");
            # The rule should already be in the tracker but we increment it for the heck of it
            $tracker->{iptables_rules}->{$rule}++;
            return 1;
        } ## end if ( $retval =~ /in tracker/)
        if ( $retval eq "rule exists" ) {
            # Since the rule exists and we are not allowing dupes, then we do not need to add the rule and
            # we return success
            $logger->info("Rule already exists in iptables.  Not adding rule: $iptables $options $rule");
            # But we do track it so that we can remove it on exit AND so that we can check if it exists later
            $tracker->{iptables_rules}->{$rule}++;
            return 1;
        } ## end if ( $retval eq "rule exists")
        elsif ( $retval eq "DNE" ) {
            $logger->info("Adding rule to iptables: $iptables $options $rule");
        }
        elsif (( $retval eq "create chain" ) && ( $options =~ m/-N/ ) )
        {
            # Creating chains is a special case.  We just allow it to happen.
            $logger->info("Trying to create chain: $iptables $options $rule");

            # We track the chains created so that we can remove them on exit
            $tracker->{chains_created}->{$rule}++;
        } ## end elsif ( ( $retval eq "create chain"...))
        elsif ( $retval eq "chain does not exist" ) {
            $logger->error("Chain does not exist for the rule.  Not creating rule: $iptables $options $rule");
            return 0;
        }
        elsif ( $retval eq "permission denied" ) {
            my $logmsg = "Permission denied (not root or sudo with user not set?).  ";
            $logmsg .= "Can't check if rule exists: $iptables $options $rule";
            $logger->error($logmsg);
            return 0;
        } ## end elsif ( $retval eq "permission denied")
        elsif ( $retval eq "delete rule" ) {
            $logger->debug("Rule is to delete a rule.  No need to check if it exists; error will happen if it does exist");
            $logger->info("Deleting rule: $iptables $options $rule");
        }
        else {
            $logger->error( "Unknown return from check_if_rule_exists(): " . $retval );
            return 0;
        }
    } ## end if ( $allowdupes == 0 )

    my $command = "$iptables $options $rule 2>&1";
    $tracker->{iptables_rules}->{$rule}++;
    if ( $self->{configs}->{PRODMODE} ) {
        $logger->debug("Running $command");
        my $output = `$command`;
        $logger->debug("Output of iptables command: $output");
        return 1;
    } ## end if ( $self->{configs}->...)
    else {
        $logger->info("In test mode.  Would run: $command");
        return 1;
    }

    # Should not get here but by default return 0
    $logger->error("Should not get here but by default returning 0");
    return 0;
} ## end sub run_iptables


# Description:  Finds the iptables command to use
# Returns:      1 always
sub set_iptables_command() {
    my $self = shift;

    # If the iptables command is not set, then set it to the system location (if possible)
    $self->{configs}->{iptables} //= `which iptables`;
    chomp( $self->{configs}->{iptables} );
    $logger->info("The command to be used for iptables is $self->{configs}->{iptables}");
    return 1;
} ## end sub set_iptables_command

# Description:  Checks if a command already exists in the iptables queue or in the tracker config
#               This is used to prevent duplicate rules from being added to the iptables queue
# Returns:      Multiple scalar strings returns with specific meanings.  See code for details
sub check_if_rule_exists {
    my ( $self, $args ) = @_;

    # Preliminary checks
    $args->{rule}                or return $self->error("No rule passed to check_if_rule_exists");
    $self->{configs}->{iptables} or $logger->error("No iptables command set, this may cause problems");

    my $iptables = $self->{configs}->{iptables};
    my $rule     = $args->{rule};
    my $options  = $args->{options} // "";

    if ( $tracker->{chains_created}->{$rule} ) {
        $logger->debug("Chain $rule has already been ran. Returning >>chain in tracker<<");
        return "chain in tracker";
    }

    if ( $options =~ /-A/ && $tracker->{iptables_rules}->{$rule} ) {
        $logger->debug("Rule $rule has already been added. Returning >>rule in tracker<<");
        return "rule in tracker";
    }

    if ( $options =~ /-D/ ) {
        $logger->debug("Rule is to delete a rule.  No need to check if it exists; error will happen if it does exist");
        return "delete rule";
    }

    if ( $options =~ /-N/ ) {
        my $logmsg = "Rule is to create a chain.  No need to check if it exists; error will happen if it does ";
        $logmsg .= "exist and probably does not matter";
        $logger->debug($logmsg);
        return "create chain";
    } ## end if ( $options =~ /-N/ )

    my $checkrule_result = `$iptables -w -C $rule 2>&1`;
    if ( $? == 0 ) {
        $logger->debug("Rule appears to already exist. Returning >>rule exists<<");
        return "rule exists";
    }

    if ( $checkrule_result =~ /iptables: Bad rule.*does a matching rule exist in that chain.*/ ) {
        $logger->debug("Rule appears to not exist. Returning >>DNE<<");
        $logger->debug("Output of iptables: $checkrule_result");
        return "DNE";
    }

    if ( $checkrule_result =~ /iptables.*Chain.*does not exist*/ ) {
        $logger->debug("Chain does not appear to exist. Returning: >>chain does not exist<<");
        $logger->debug("Output of iptables: $checkrule_result");
        return "chain does not exist";
    }

    if ( $checkrule_result =~ /iptables.*Permission denied.*you must be root/ ) {
        $logger->debug("You do not have permmission to run iptables.  You must be root.");
        $logger->debug("Output of iptables: $checkrule_result");
        return "permission denied";
    }

    $self->error("Should not get here but by default returning 0. Output of iptables: $checkrule_result");
} ## end sub check_if_rule_exists

# Description:  Creates the global chain and then adds jump rule(s) to the global chain.
#               With default values this means creating the global chain "IPBLOCKER_global" and then
#               adding a jump rule to the INPUT, OUTPUT, and FORWARD tables to go to IPBLOCKER_global
#               Actually, this enqueue's the commands via the iptablesqueue_enqueue() sub
# Returns:      1 if able to enqueue commands otherwise 0
sub add_global_chain() {
    my ($self) = @_;

    my $chain = $self->{configs}->{chainprefix} || $logger->fatal("No chain prefix set");
    $chain = $chain . "global";

    my $globalchains_str = $self->{configs}->{globalchains} || $logger->fatal("No global chains set");
    my @globalchains     = split( /,/, $globalchains_str );

    $logger->info("Adding global chain $chain");
    my $args = {
        options => "-w -N",
        rule    => "$chain",
    };
    $self->iptablesqueue_enqueue($args) || return 0;

    $logger->info("Adding global chain $chain to @globalchains tables");
    for my $table (@globalchains) {
        my $args = {
            options => "-A",
            rule    => "$table -j $chain",
        };
        $self->iptablesqueue_enqueue($args) || return 0;
    } ## end for my $table (@globalchains)

    return 1;
} ## end sub add_global_chain

# Description: Queues items onto the iptables queue
# Returns 1 if queue is allowing enqueuing
# Returns 0 if queue is not allowing enqueuing
sub iptablesqueue_enqueue() {
    my ( $self, $args ) = @_;

    my $iptablesQueue_pending = eval { $IptablesQueue->pending() };
    if ( !defined $iptablesQueue_pending ) {
        my $logmsg = "IptablesQueue is in an undefined state. This is probably intentional. ";
        $logmsg .= "Returning 0";
        $logger->info($logmsg);
        return 0;
    } ## end if ( !defined $iptablesQueue_pending)
    return 1 if ( $args->{check_pending} );
    $logger->debug( "Enqueuing onto the iptables queue: " . Dumper($args) ) if ( $logger->is_debug() );
    $IptablesQueue->enqueue($args);
    return 1;
} ## end sub iptablesqueue_enqueue

# This function reads the log file into memory from the seek position (if it exists)
# The reading of a log file based on the seek position creates a big issue if the log file is rotated AND is larger than
#   the seek position
#   This is a tradeoff of reading the entire log file into memory and then grepping for the regexps
# Returns: $logobj

# Description:  Reads the log file into memory based on whether or not the readentirefile flag is set
# Requires:     $self, $logobj
# Returns:      $logobj with the logcontents set
sub readlogfile {
    my ( $self, $logobj ) = @_;

    # Check file is readable
    my $file = $logobj->{file} //= "/dev/null";    # Default to /dev/null if file is not set
    -r $file or ( $logger->error("Log file >>$logobj->{file}<< is not readable") && return $logobj );

    # If the readentirefile flag is set, then set the seek position to 0 to read the entire file
    $logobj->{seek} //= 0;    #It is possible the seek position is already set from a previous readlogfile() call
    $logobj->{seek} = 0 if ( -s $file < $logobj->{seek} );    #Can't seek past the end of the file
    $logobj->{readentirefile} //= $self->{configs}->{readentirefile} //= 0;
    $logobj->{seek} = 0 if ( $logobj->{readentirefile} );

    $logger->debug("Reading $file at byte position $logobj->{seek}");

    # Open and close the file handle as quickly as possible.
    # This has two major flaws:
    #   1.  If the file is rotated while open then someting bad may happen, maybe.
    #   2.  If the file is larger than we can handle in "memory", then something bad may happen, maybe.
    open my $fh, '<', $file or do {
        $logger->error("Can't open $file: $!");
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
        $logger->debug("No new lines appear to be in $file");
        $logobj->{logcontents} = ();
    }

    chomp(@logcontents);
    $logobj->{logcontents} = \@logcontents;    #  Might be better to clone?  Hmmm, maybe not.

    $logger->debug( "The $file file has been read into memory.  " . scalar(@logcontents) . " lines read." );
    $logger->trace( "The $file contents: " . Dumper( $logobj->{logcontents} ) ) if ( $logger->is_trace() );

    return $logobj;
} ## end sub readlogfile

# Description:  Using the logobj, this greps against the log contents for matching lines and then gets the
#               IP address on each line.
# Requires:     $self, $log
# Returns:      Hash reference of IP addresses with count of how many times the IP address was found
# sub grep_regexps {
#     my ( $self, $log ) = @_;
#     my $TID = "TID: " . threads->tid;

#     my $matches      = {};
#     my @log_contents = @{ $log->{logcontents} };

#     return {} if ( !@log_contents );

#     # DO NOT SORT NUMERICALLY!  The info in the configs states the order is sorted alphabetically
#     foreach my $regex ( sort keys %{ $log->{regexpdeny} } ) {
#         my $pattern = $log->{regexpdeny}{$regex};
#         $logger->debug("$TID|Grep'ing for >>$pattern<< in $log->{file} from byte position $log->{seek}");

#         my @current_matches = grep { /$pattern/ } @log_contents;
#         $logger->debug( "$TID|Dumper of current matches: " . Dumper(@current_matches) ) if $logger->is_debug();

#         foreach my $line (@current_matches) {
#             chomp($line);
#             $logger->debug("$TID|Checking >>$line<< for IP address");

#             foreach my $ip_address ( $line =~ /$REGEX_IPV4/g, $line =~ /$REGEX_IPV6/g ) {
#                 $matches->{$ip_address}++;
#                 $logger->debug("$TID|Found IP address: $ip_address");
#             }
#         } ## end foreach my $line (@current_matches)
#     } ## end foreach my $regex ( sort keys...)

#     $logger->debug( "$TID|Dump of IP matches after all regex comparisons: " . Dumper($matches) ) if $logger->is_debug();

#     my $log_msg = "$TID|Matched IP addresses to be reviewed for potential blocking: ";
#     $log_msg .= join( ",", keys %{$matches} );
#     $logger->info($log_msg);

#     return $matches;
# } ## end sub grep_regexps

# Description:  Adds a chain to iptables
#               Also adds the chain to $tracker
# Returns:      1 if able to enqueue commands otherwise 0
sub add_chain() {
    my ( $self, $chain ) = @_;

    $logger->debug("Trying to add chain $chain");
    my $rule    = "$chain";
    my $options = "-w -N";
    my $args    = { rule => $rule, options => $options };
    $self->iptablesqueue_enqueue($args) || return 0;
    $tracker->{chains_created}->{$chain}++;
    return 1;
} ## end sub add_chain

# Description:  Adds IPs as DROP or ACCEPT to the chain provided
# Requires:     $self
#               $args to be a hash reference with the following optional keys:
#                   chain:  The chain to add the rules to.  If no chain provided then the 
#                           default is ipblocker_global
#                   allowlist:  An array of IPs to allow
#                   denylist:  An array of IPs to deny
#                   allowdenyorder:  The order to add the allow and deny rules
# Returns:      1 if able to enqueue commands otherwise 0
sub add_allowdeny_ips() {
    my ( $self, $args ) = @_;

    if ( ref $args ne 'HASH' ) {
        $logger->error("add_alldeny_ips() requires a hash reference as an argument");
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

    $logger->debug( "IP rules: " . Dumper( \%ip_rules ) ) if $logger->is_debug();

    # foreach my $action (keys %ip_rules) {
    foreach my $action (@allowdenyorder) {
        $logger->debug("Adding $action rules to chain $chain");

        # my $chain = $args->{chain} . $action;
        my $chain       = $args->{chain};
        my $rule_action = $action eq 'allow' ? 'ACCEPT' : 'DROP';
        foreach my $ip ( sort @{ $ip_rules{$action} } ) {
            $logger->debug("Adding $action rule for IP $ip to chain $chain");
            foreach my $direction ( '-s', '-d' ) {
                my $rule = "$chain $direction $ip -j $rule_action";
                my $args = { rule => $rule, options => "-w -A" };
                $logger->debug("Adding >>-w -A $rule<< to iptables queue");
                $self->iptablesqueue_enqueue($args) || return 0;
            } ## end foreach my $direction ( '-s'...)
        } ## end foreach my $ip ( sort @{ $ip_rules...})
    } ## end foreach my $action (@allowdenyorder)

    return 1;
} ## end sub add_allowdeny_ips

# Description:  Adds the IPs to block or accept from the configs global allowlist and global denylist 
#               to the global chain
# Requires:     $self->{configs}->{allowlist} to be a hash reference
#               $self->{configs}->{denylist} to be a hash reference
# Returns:      Returns the value returned by add_allowdeny_ips()
sub add_global_allow_deny_ips() {
    my ($self) = @_;

    $logger->debug("Adding global allow/deny IPs to global chains");
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

    $logger->debug( "Args to add_allowdeny_ips(): " . Dumper($args) ) if $logger->is_debug();

    return $self->add_allowdeny_ips($args);
} ## end sub add_global_allow_deny_ips

# Description:  Adds the IPs to block or accept from the logobj allowlist and logobj denylist
# Requires:     $logobj->{allowlist} to be a hash reference
#               $logobj->{denylist} to be a hash reference
# Returns:      Returns the value returned by add_allowdeny_ips()
sub add_logger_allow_deny_ips() {
    my ( $self, $logobj ) = @_;

    $logger->debug("Adding logger allow/deny IPs to logger chain $logobj");
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

    $logger->debug( "Args to add_allowdeny_ips(): " . Dumper($args) ) if $logger->is_debug();

    return $self->add_allowdeny_ips($args);

} ## end sub add_logger_allow_deny_ips

# Description:  Stops the module, gracefully (or at least tries to)
#               Removes the chains that were created (or tried to be created) and removes the iptables rules that were
#               added (or tried to be added)
# Requires:     $self
#               $args which is really a hash reference for $tracker
#                   $args->{chains_created} --> chains created (or tried to be created)
#                   $args->{iptables_rules} --> iptables rules that were added (or tried to be added)
# Returns:      1 if successful, otherwise 0
sub stop() {
    my ( $self, $args ) = @_;
    $logger->info("Setting IptablesQueue to end");

    my $chains_created = $args->{chains_created} ||= $tracker->{chains_created} ||= {};
    my $iptables_rules = $args->{iptables_rules} ||= $tracker->{iptables_rules} ||= {};
    # $logger->debug( "Dump of tracker: " . Dumper($tracker) ) if $logger->is_debug();

    # Removing chains that were created (or tried to be created)
    my @chains_to_remove = ();
    foreach ($self->{configs}->{logs_to_review}) {
        my $chain = $self->{configs}->{chainprefix} . $_;
        push @chains_to_remove, $chain;
    }
    push @chains_to_remove, $self->{configs}->{chainprefix} . "global";
   $logger->info("chains_to_remove: " . Dumper(@chains_to_remove)) if $logger->is_debug(); 
    if ( $self->{chains_created} || $chains_created ) {
        $logger->info("Removing chains that were created (or tried to be created)");
        foreach my $chain ( sort keys %{ $self->{chains_created} } ) {
            $logger->info("Removing chain $chain");
            $IptablesQueue->enqueue(
                {
                    options => qq/-w -X/,
                    rule    => qq/$chain/
                }
            );
        } ## end foreach my $chain ( sort keys...)
    } ## end if ( $self->{chains_created...})
    else {
        $logger->info("No list of chains to remove.  Maybe kill 3 was issued instead of a polite stop");
    }

    $logger->info("Clearing queues (error will be logged if there is an issue)");
    clear_queues() || $logger->error("Unable to clear queues");
    $logger->info("Waiting for threads to finish (join) (error will be logged if there is an issue)");
    join_threads() || $logger->error("Unable to join threads");

    $logger->info("Releasing lock");
    $lock_obj->release;
    $logger->info("Bye bye");

    return 1;
} ## end sub stop

# Joins all threads
#   Simple sub but really needs some rework
#   If a thread is taking a while to join then it will block the other threads from joining
#   Some of the threads could be reading a log file and if the log file is large then it could take a while or
#   if the log file is causing soem kind of blocking for reading then it could take a while.
#   This may be an issue, if an example, if trying to read a file across NFS or SSHFS and there is a network issue.


# Description:  Joins all threads
#               This needs some rework.
#               If a thread is taking a while to join then it will block the other threads from joining.
#               Some of the threads could be reading a log file and if the log file is large then it 
#               could take a while or if the log file is causing some kind of blocking for reading then it 
#               could take a while.
#               This may be an issue if trying to read a file across NFS or SSHFS and there is a network issue.
# Returns:      1 if successful.
sub join_threads() {
    $logger->debug("Waiting for threads to finish (join)");
    $_->join() for threads->list();
    return 1;
} ## end sub join_threads

# Description:  Clears the queues
# Returns:      1 if successful, otherwise 0
sub clear_queues() {
    $logger->debug("Clearing queues");
    $IptablesQueue->end();
    my $counter = 6;
    while ( $IptablesQueue->pending() && $counter-- ) {
        $IptablesQueue->pending() && $logger->debug("Data still in IptablesQueue (Trying $counter more times)");
        sleep 1;
    }
    if ( $IptablesQueue->pending() ) {
        $logger->error("Data still in queue.  This may be an issue.");
        $logger->error("Data still in queue: " . Dumper( $IptablesQueue) );
        return 0;
    }
    else {
        $logger->debug("No queued items in IptablesQueue");
        return 1;
    }
} ## end sub clear_queues


# Description:  Reloads the module
#               This is not yet implemented
sub reload() {
    $logger->info("Reloading not yet implemented.  Do a CTRL-C (SIG_INT) and restart the module");

    # Need to figure out how to bless(re-bless) the $self object so that configs are reloaded into $self->{configs}

    ##### Things that may or may not work.......
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
} ## end sub reload

#Description:   This sub is run when signal interrupt is caught
#               We try to do a graceful stop when ctrl-c/SIG-Interrupt- is pressed
sub SIG_INT {
    $logger->info("Caught interrupt signal");
    stop();
    exit 0;
}

#Description:   This sub is run when signal hup is caught
#               Not fully implemented because reload is not fully implemented
sub SIG_HUP {
    $logger->info("Caught HUP signal");
    reload();
}

#Description:   This sub is run when signal term is caught
#               Just calls stop()
sub SIG_TERM {
    $logger->info("Caught TERM signal");
    stop();
}

#Description:   This sub is run when signal quit is caught
#               Just calls stop()
sub SIG_QUIT {
    my $self = shift;
    stop();
}


# Description:  Sets the signal handlers
sub set_signal_handler() {
    $logger->info("Setting signal handlers");
    $SIG{INT}  = \&SIG_INT;
    $SIG{TERM} = \&SIG_TERM;
    $SIG{HUP}  = \&SIG_HUP;
    $SIG{QUIT} = \&SIG_QUIT;
} ## end sub set_signal_handler=head1 Sample config file

=head1 Sample config file

    Default location: /etc/ipblocker/ipblocker.conf

    # Lines that begin with a comment (#) are ignored
    # Think of each line as a a key:value setup in the following manner: key[sub-key][sub-sub-key][sub-sub-sub-key]=value
    # Duplicates are allowed.  The last one wins!
    # This is being used by perl so let's keep a few thigns in mind:
    #   1. False value is 0.  Period.  That's it.  0 (zero) is false.  Everything else is true.
    #   2. Regular expressions are PERL regular expressions.  So they are case sensitive and use PERL regular expressions.
    #   3. Unless otherwise noted, sorting is regular perl sorting.  So 1, 10, 11 come before 2, 20, 21, etc.


    ### Global settings 
    # The global settings are used for all log files unless overridden or combined by the individual log file settings.

    # iptables: Default value is `which iptables`
    #           Sets a different iptables command
    #           A simple check is done to verify the iptables command exists and is executable.
    #           Let's talk security!
    #               Running iptables as root is a bit of a security risk.  If possible set the iptables command to run as 
    #               a different user.
    #               A good method is to use a sudo command to run iptables as a different user.
    #               This also means setting up sudo to allow the user to run iptables as a different user in passwordless mode.
    #               As part of a sudo rule, be sure to allow "-N", "-A", "-D", and "-X"
    #               If you want to lock things down a bit, then you may want to set the sudo rule to only allow something like:
    #                   iptablesuser ALL=(ALL) NOPASSWD: /sbin/iptables -N *IPBLOCKER_*
    #                   iptablesuser ALL=(ALL) NOPASSWD: /sbin/iptables -A *IPBLOCKER_*
    #                   iptablesuser ALL=(ALL) NOPASSWD: /sbin/iptables -D *IPBLOCKER_*
    #                   iptablesuser ALL=(ALL) NOPASSWD: /sbin/iptables -X *IPBLOCKER_*
    #               This will allow the iptablesuser to create, add, delete, and delete the chain
    #               Take note "IPBLOCKER_" is the value of the "chainprefix".  If you change the chainprefix then you
    #               will need to change the sudo rule.
    #               General steps to setup sudo rule this:
    #                 1.  Create a user to run the iptables command.  For example, iptablesuser
    #                 2.  Create a group to run the iptables command.  For example, iptablesgroup
    #                 3.  Add the iptablesuser to the iptablesgroup
    #                 4.  Add the following line to the /etc/sudoers file:
    #                       iptablesuser ALL=(ALL) NOPASSWD: /sbin/iptables
    #                      Or, add the four lines above --- again the four lines are a guess and may not be correct.                        
    #                 5.  Set the iptables command to the following:
    #                       iptables=sudo -u iptablesuser /sbin/iptables
    #               Maybe in the future I'll figure out how to setup an APT/deb/Ubuntu package to do this for you.
    #                   Lord knows, I'll never setup a YUM package to do this!
    # iptables=sudo -u iptablesuser /sbin/iptables
    # iptables=/usr/sbin/iptables_some_other_location
    iptables=sudo /sbin/iptables

    # log4perlconf: Default value is /etc/ipblocker/log4perl.conf
    #               The location of the log4perl configuration file.
    # log4perlconf=/some/other/place/log4perl.conf

    # lockfile: Default is /var/run/iptables.run
    #           The location of the lock file
    #           The lock file is used to try to prevent multiple instances of this script from running at the same time.
    #           This is a bit better than "dumb" but not foolproof.  The module checks the PID in the lock file to see if
    #               that PID is still running.  If the PID is not running then the lock file is removed and the module 
    #               will continue.
    #           I realize this is a bit beyond the scope of a module but we are jacking around with iptables so let's try 
    #               to be a bit safe.
    # lockfile=/some/other/directory/iptables.run

    # queuechecktime:   Default value is 1
    #                   The number of seconds to wait to check to see if there are entries in the queue to process
    #                     Prevents the script from going CPU crazy and checking the queue as fast as possible.
    #                     You can set this to 0 to check the queue as fast as possible but I would not recommend it.
    #                   Once a queue entry is found then the queue is processed continuously until the queue is empty.
    #                   I see very little utility in having this set to 0 or even less than 1 second.
    queuechecktime=3

    # queuecycles:  Default value is LONG_MAX (usually 9223372036854775807)
    #               When the queue is empty, this integer is decremented every "queuechecktime" seconds.
    #               When this hits zero, the queue is set to end(), no other items are allowed on the queue, and the 
    #               module will end.
    #               This is nice to set for some testing and you want the script to end after a certain number of cycle 
    #               checks of the queue when the queue is empty.
    #               In normal operation, this should not be set and will default to LONG_MAX.
    # queuecycles=40

    # readentirefile:   Default value is 0 (false)
    #                   Whether or not the entire log file is read each time.  If set to 0 (false), then we only read 
    #                   from the end of the last read (or the beginning if it is the first read or if the log file has 
    #                   been allegedly rotated)
    #                   Reading from last read is faster, but if the log file is rotated AND the log file grows larger 
    #                   than the last read, then we may miss some entries.
    #                   For most situations, this should be left as the default of 0.
    #                   If you rotate your log files frequently AND get a lot of traffic, then you may want to 
    #                   set this to 1.
    #                   Future enhancement: This should be enhanced to check the inode, file size, last change time, etc.
    readentirefile = 0

    # cycles:   Default value is LONG_MAX (usually 9223372036854775807)
    #           This is how many times a log file will be reviewed.
    #           This is a global value and can be set for each log file individually.
    #           (Very bad naming of a variable, sorry)
    # cycles=25

    # cyclesleep:   Default is 0.5 seconds
    #               This is how many seconds to sleep between checking a log file.
    #               This is a global value and can be set for each log file individually.
    #                This gets a bit complex to decide but here goes:
    #                If you are always reviewing the entire log file, then this value is rather important.
    #                   Reviewing the entire log file means that you are not using the "readentirefile" setting.
    #               Usually, if you want to change this then you will want to change it for each log file individually.
    #               Example: If you want to read the auth.log file every 5 seconds then you would set this to 5.
    #               The module will seek to the last read position and then read the log file from there.  Of course, if
    #               "readentirefile" is set to 1 then the entire file is read each time.
    #               For those of you concerned about the performance of the system, this is a read action so it should be 
    #               pretty fast, even for "slow" systems.
    # cyclesleep=1

    # totalruntime: Default is LONG_MAX (usually 9223372036854775807) seconds
    #               This is the total amount of time that the script will run in seconds.
    #               This is nice to set if you have this ran out of cron and want it to gracefully die and reload like 
    #               once an hour or something.
    #               Also nice for testing.
    # totalruntime = 120

    # nice:     Default is 0
    #           Process nice level on the OS
    # nice=15  # Not yet implemented

    # PRODMODE: Default is 0 (false)
    #           Set this to a perl true value (1) to run in prod mode.
    #           Test mode is 0 (false) and will NOT run any iptable command but will log what it would have been done.
    PRODMODE=1

    # chainprefix:  Default is IPBLOCKER_
    #               This is the prefix for the iptables chain names.
    #               The chain names are created as follows:
    #                 ${chainprefix}${logname}
    #                All actions are performed from ${chainprefix}global
    #               The default is IPBLOCKER_ but you can change it if you want.
    #               When you do an 'iptables -nvL' you will see the chain prefix in the chain names.
    chainprefix=IPBLOCKER_

    # globalchains: Default is INPUT,OUTPUT,FORWARD
    #               These are the chains that {chainprefix}global will be added to.
    #               All other logger chains will be added as an iptables jump rule to {chainprefix}global
    #               The logger rules are then added to the logger chains.
    #               Instead of adding the rules to the INPUT,OUTPUT,FORWARD chains, you can
    #                 add them to a different chain.  For example, you could add them to a chain
    #                 called "MailServer" and then that chain would have to be added to the
    #                INPUT,OUTPUT,FORWARD chains (or whatever chains you want).
    #                This might be useful to change if you want to add the rules to a dummy chain but
    #                is not actually used.... maybe for pre-production testing or something.
    #                Or, maybe you only want rules acted on the INPUT chain and not the OUTPUT chain.
    #                Having FORWARD is a bit aggressive but to each their own.
    #                This value must be a comma separated.  No spaces.
    globalchains=INPUT,OUTPUT,FORWARD

    # denylist:  Deny these IPs, almost always.  The "allowdeny" value takes precedence.  See below.
    #            This denylist is added to the "chainprefix" global chain.
    denylist[01]=165.232.121.37
    denylist[02]=165.232.121.36

    # allowlist:    Allow these IPs, almost always.  The allowdeny value takes precedence.  See below.
    #               The allowlist is added to the "chainprefix" global chain.
    allowlist[01]=23.116.91.64/29
    allowlist[02]=127.0.0.0/8
    allowlist[03]=10.0.0.0/8
    allowlist[04]=192.168.0.0/16
    allowlist[05]=172.16.0.0/12


    # allowdeny:    Individual log file settings for this value take precedence over the general settings here
    #                Allow,Deny means that the allowlist is processed first and then the denylist is processed.
    #                   Items in the allowlist will be allowed even if they are in the denylist.
    #                Deny,Allow means that the denylist is processed first and then the allowlist is processed.
    #                   Items in the denylist will be denied even if they are in the allowlist.
    #               I would not change this unless you know what you are doing.  You have the potential to lock yourself out of your
    #               own system.
    allowdeny=Allow,Deny

    # minlogentry:   Default is 300 seconds
    #                This is the minimum amount of time in seconds to pass before the module will give some kind of
    #                INFO message.
    #                Details:  A queue is used for all the activity for iptables.  A while loop runs and checks the
    #                queue for entries every second.  If at least minlogentry seconds have passed since an entry then an 
    #                INFO message is logged.  
    #                This is to prevent the log from being filled with messages but still let you know that the script 
    #                is running.
    #                For systems with a lot of IPs to block then set this higher.  For systems with very few IPs to
    #                block then set this lower. 
    #                This is actually a very low hit to the system so I would not worry about it too much.
    minlogentrytime=10


    ### Not yet implemented....
    # ignoreinterfaceips:   Finds the IPs of each interface and adds them to the allow list.
    #                       Some logs have the IP of the interface in the log file.
    #                       This is a perl true/false value.  If it is set to 0 (false) then the IPs of each interface 
    #                       will be added to the allowlist.
    #                       If you keep allowdeny set  to Allow,Deny then this will keep you from blocking your own IPs.
    #                         Or, at least that is the idea!  This is totally based on Net::Ifconfig::Wrapper so... do 
    #                         some testing to make sure that it is working as expected.
    #                       I encourage leaving this as 0 (false) but it is here if you need it.  
    #                       The default value, if not set, is 0 (false)
    # ignoreinterfaceips=0  # Not yet implemented

    ### End of Global settings



    # Settings for each log file from here down

    ### The authlog settings:
    # The "logs_to_review" hash is a list of log files to review.  Each log file has a unique name.  The name is used 
    #   to reference the log file in other parts of the configuration file.
    #   In the exampple of "authlog", the string "authlog" could be any alphanumeric string.  It is just used for reference.

    # load: Default value is 1.
    #       If set to 1 (true) then the log file will be reviewed.
    #       This is just an easy way to keep configs in here but the script/module will not review or read the log file.
    #       Chain creation will still happen, though.
    logs_to_review[authlog][load] 				    = 1

    # file: The "file" value is the location of the log file to review.
    logs_to_review[authlog][file]				    = /home/gardner/var/log/auth.log

    # readentirefile:   Default value is global value of "readentirefile"
    #                   Whether or not the entire log file is read each time.  If set to 0 (false), then we only read 
    #                   from the end of the last read (or the beginning if it is the first read or if the log file has 
    #                   been allegedly rotated)
    #                   Reading from last read is faster, but if the log file is rotated AND the log file grows larger 
    #                   than the last read, then we may miss some entries.
    #                   For most situations, this should be left as the default of 0.
    #                   If you rotate your log files frequently AND get a lot of traffic, then you may want to 
    #                   set this to 1.
    #                   Future enhancement: This should be enhanced to check the inode, file size, last change time, etc.  
    #                   But for now, it is pretty dumb.
    logs_to_review[authlog][readentirefile]	    = 0

    # libpath:  Default value is null.
    #           This is an extra library path to require for modules for this log file (authlog).
    #           This value is used with the next setting of "module".
    #           Future Enhancement:  Let this be a comma separated list and be an array
    # logs_to_review[authlog][libpath]            = /home/gardner/git/ipblockerclassified/Net-IPBlocker/lib/

    # module:   Default value is Net::IPBlocker::ReviewLogDefault
    #           This is the module that is used to review the log file.
    #           This can be a "::" separated path to the module.  For example, Net::IPBlocker::ApacheLogs.
    #           This can also be a "/" separated path to the module.  For example, 
    #               /home/johnboy/git/ipblockerclassified/Net-IPBlocker/lib/ApacheLogs.pm
    #           This setting is expected to grow over time to accomodate different log files such as mail log, nginx/apache 
    #           logs, ftp logs, etc.
    #           Module Requirements:
    #               The module must be a class and must have a function called "new" to instantiate (bless) the class.
    #               The "new" function should be able to take a hash reference with the following keys:
    #                   logobj:   This is all the configs associated with the log file along with the log contents.
    #                   parentobjself: This is the object of the parent module.  This provides a lot of extra information.
    #                   iptablesqueue_enqueue: This is a reference to the iptablesqueue_enqueue function.  This is used to
    #                       add rules to the iptables queue to be ran.
    #               There must be at least one function called "grep_regexps" that takes a logobject as a 
    #               hash reference and returns a hash reference of IPs to block.  The IPs are a key and the value is 
    #               whatever you want.
    #               The module has access to the iptablesqueue_enqueue function and COULD set the queue directly and 
    #               always returns an empty hash.
    #               I do not reccomend setting the queue directly but it is possible.
    #               Doing that will bypass multiple settings such as ports, protocols, directions, etc.
    # logs_to_review[authlog][module] = Net::IPBlocker::ReviewLogSSH

    # cycles: Default is global value of "cycles"
    #   The number of times the log file will be reviewed.
    #   Once this value hits 0, the log file will not be reviewed anymore.
    # logs_to_review[authlog][cycles]                 = 10

    # cyclesleep:   Default is global value of "cyclesleep"
    #               The number of seconds to sleep between cycles.  Can be partial seconds.  So 0.5 is a half second.
    logs_to_review[authlog][cyclesleep] = 1.5

    # protocols:    Default is no protocol.
    #               This is the protocol(s) that will be blocked in the firewall.
    #               If the protocol is not set, then the default is no protocol.
    #               You do not have to set protocol unless you set ports.
    #               If you set ports but not protocol then the script will add the IP to the firewall but will not add 
    #                the protocol and thus no ports.  So, the entire IP will be blocked.
    #               There is no checking if the protocol is valid.  So if you set protocol=blah then the script will give 
    #                an error when the rule tries to be added to the firewall.
    #               Must be separated by non-alphanumeric-digit characters.  So tcp,udp is good.  tcp udp is good.  tcp-udp is good.
    #                The "_" character is not allowed.  So tcp_udp is not good.
    #                Most folks will use commas but whatever floats your boat.
    logs_to_review[authlog][protocols] = tcp,udp

    # ports:    Default is no ports
    #           This is the port(s) that will be matched for blocking of IPs in the log file.
    #           If the ports are not set, then the default is no ports.
    #           This is nice if you want to block IPs that are trying to connect to, for example, ssh but not to HTTP
    #           or HTTPS or etc etc.
    #           You do not have to set ports but if you do, then you must set protocol.
    #           Example:  ports=22,21,23 means that the script will block IPs that are trying to connect to 
    #            ports 22, 21, and 23.
    #           Must be separated by commas and ranges are accepted.  The iptables command has a maximum of 15 comma 
    #           separated values.
    #           Example 1:  logs_to_review[authlog][ports]                  = 22,21,23
    #           Example 2:  logs_to_review[authlog][ports]                  = 22,21,23,1000:2000,3000:4000
    #           Example 3:  logs_to_review[authlog][ports]                  = 22,21,23,1000:2000
    #           Bad ports will log as an error and the rule will not be added.
    #           If you set ports but no protocol then the entire IP will be blocked on the protocol.
    logs_to_review[authlog][ports] = 22

    # directions:   Default is source
    #               This is the direction(s) that will be blocked in the firewall.
    #                 If the direction is not set, then the default is source
    #                Must be separated by non-digit-alphanumeric characters.  So source,destination is good.  source destination is good.
    #                 source-destination is good.
    #                 The "_" character is not allowed.  So source_destination is not good.
    #                Most folks will use commas but whatever floats your boat.
    #                Accepted values are source, destination, random
    #               Example 1:  logs_to_review[authlog][direction]              = source,destination
    #               Example 2:  logs_to_review[authlog][direction]              = source
    #               Example 3:  logs_to_review[authlog][direction]              = destination
    #               Example 4:  logs_to_review[authlog][direction]              = source,destination,cool,blah,blah,blah
    #               In example 4, only source and destination will be used.  The values of cool,blah,blah,blah will be ignored.
    #               I think most folks will not set this or just use 'source' but I can see value in blocking the destination as well.
    #               If you want to screw with hackers a bit, then set this to 'destination' and then they will not get any response
    #               The "random" value will ignore (for now) any other value set.  If random is used then source or 
    #               destination will be randomly chosen for each IP rule.
    #               logs_to_review[authlog][directions]          = source,destination
    #               logs_to_review[authlog][directions]          = destination
    logs_to_review[authlog][directions] = source
    # logs_to_review[authlog][directions]          = random

    # allowdeny:    Default value is global value of "allowdeny"
    #               This is the order preference for whitelisted and blacklisted IPs.
    #               If the order is set to "Deny,Allow" then blacklisted IPs will ALWAYS be 
    #                 blocked (even if they are in the whitelisted hash)!
    #               If the order is set to "Allow,Deny" then whitelisted IPs will ALWAYS be 
    #                 allowed (even if they are in the blacklisted hash)!
    #               If the order is not set or is set incorrectly then the default is "Allow,Deny"
    #               When using authlog, I would reccomend setting the order to "Allow,Deny" so that whitelisted IPs are 
    #                 always allowed for ssh.
    #               The order is case insensitive.
    logs_to_review[authlog][allowdeny]          = Allow,Deny

    # allowlist:    List of IPs to allow just for this log file
    logs_to_review[authlog][allowlist][01]     =  127.0.0.0/8
    logs_to_review[authlog][allowlist][02]     =  23.116.91.65/29

    # denylist:     List of IPs to block just for this log file
    logs_to_review[authlog][denylist][01]      =  5.5.5.5
    logs_to_review[authlog][denylist][02]      =  6.6.6.6

    # regexpdeny:   Now comes the important part!  How to decide what to block?
    #               Each regular expression must have a unique value.  
    #               This is just typically indexed as 01, 02, 03, 04, etc.  But it can be any Alphanumeric
    #               The index is sorted in simple Perl sort.  So 1, 10, 11 come before 2, 20, 21, etc.
    #               Also, lowercase will come before uppercase.  So a, b, c, A, B, C.
    #               The sorting may matter because the regular expressions are applied in order.
    #               Regular expressions are case insensitive therefore "Failed" is the same as "fAiLed"
    #               Regular expressions are Perl regular expressions so you can do fancy *.?[]{}() stuff.
    logs_to_review[authlog][regexpdeny][01] = Failed password for root from
    logs_to_review[authlog][regexpdeny][02] = Failed password for invalid user  
    logs_to_review[authlog][regexpdeny][03] = Did not receive identification string from
    logs_to_review[authlog][regexpdeny][04] = not allowed because listed in DenyUsers

    # jailtime:     The default module is Net::IPBlocker::ReviewLogDefault which has a function post_enqueue().
    #               This is called after IPs are enqueued to be blocked (aka, jailed).  
    #               The default module will delete the IPs from the queue that have been jailed for
    #               longer than 1800 seconds.  This is a good default but you can change it if you want.
    #               Also, the entire ReviewLogDefault module can be overridden by setting the module key.
    #               If you override the module then the post process function post_enqueue() will not be called (unless you
    #               have one in your module).
    #               Value is seconds.
    logs_to_review[authlog][jailtime]            = 5

    # # Authlog has a special value of allowed usernames
    # logs_to_review[authlog][allowedusername][01]    = gardner
    # logs_to_review[authlog][allowedusername][02]    = jiggerboy
    # # Authlog has a special value of not-allowed usernames
    # logs_to_review[authlog][deniedusername][01] 	= root

    ## Now... an example without comments
    # The maillog settings:
    logs_to_review[maillog][load] 				= 0
    logs_to_review[maillog][file]				= /var/log/mail.log
    logs_to_review[maillog][libpath]            = /home/gardner/git/ipblockerclassified/Net-IPBlocker/lib
    logs_to_review[maillog][module]     	    = Net::IPBlocker::ReviewLogDefault
    logs_to_review[maillog][cycles]             = 10
    logs_to_review[maillog][cyclesleep]         = 1.45
    logs_to_review[maillog][order]              = Allow,Deny 
    logs_to_review[maillog][regexpdeny][1] 		= Relay access denied,Illegal address syntax from
    logs_to_review[maillog][regexpdeny][2]		= SASL LOGIN authentication failed
    logs_to_review[maillog][regexpdeny][3]		= SSL_accept error from
    logs_to_review[maillog][regexpdeny][4]		= lost connection after AUTH from unknown
    logs_to_review[maillog][regexpdeny][5]		= 503 5.5.1 Error: authentication
    logs_to_review[maillog][regexpdeny][6]		= disconnect from.* commands=0\/0
    logs_to_review[maillog][regexpdeny][7]		= non-SMTP command from unknown
    logs_to_review[maillog][regexpdeny][8]		= connect to.*:25: Connection refused

=head1 Example Script

    #!/usr/bin/perl -w

    use strict;
    use Net::IPBlocker;
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

=head1 Example log config

    There is no requirement to use Log4perl.  You can use any logging module you want compatible with Log::Any.
    
    This is just an example using log4perl which does a great job of handling threads.  
    Maybe other logging modules do as well. -\_O_/-

    I did testing only against log4perl so YMMV with other logging modules.

    Default location: /etc/ipblocker/log4perl.conf

    ###############################################################################
    #                              Log::Log4perl Conf                             #
    ###############################################################################
    # log4perl.rootLogger                                 = INFO, LOG1, Screen
    log4perl.rootLogger                                  = DEBUG, LOG1, Screen
    # log4perl.rootLogger                                  = INFO, LOG1
    # log4perl.rootLogger                                 = DEBUG, Syncer1, Screen
    # log4perl.rootLogger                                 = TRACE, LOG1, Screen
    # log4perl.appender.LOG1                              = Log::Log4perl::Appender::File
    log4perl.appender.LOG1                               = Log::Dispatch::FileRotate
    log4perl.appender.LOG1.size                          = 1024*1024*1024*1024
    log4perl.appender.LOG1.max                           = 40
    log4perl.appender.LOG1.DatePattern                   = yyyy-MM-dd
    log4perl.appender.LOG1.filename                      = /var/log/ipblocker/ipblocker.log
    # log4perl.appender.LOG1.filename                     = sub { my @now = localtime(); my $logfile = sprintf("/mnt/ramdrive/ipblocker/ipblocker_%04d%02d%02d.log", $now[5]+1900, $now[4]+1, $now[3] ); return $logfile }
    # log4perl.appender.LOG1.filename                     = sub { my @now = localtime(); my $logfile = sprintf("/home/gardner/var/log/ipblocker/ipblocker_%04d%02d%02d.log", $now[5]+1900, $now[4]+1, $now[3] ); return $logfile }
    # log4perl.appender.LOG1.mode                         = write
    log4perl.appender.LOG1.mode                          = append
    # log4perl.appender.LOG1.TZ                           = CST
    log4perl.appender.LOG1.layout                        = Log::Log4perl::Layout::PatternLayout
    # log4perl.appender.LOG1.layout.ConversionPattern      = %d|%p|%l|%m%n
    log4perl.appender.LOG1.layout.ConversionPattern      = %d|%p|%l|%X{TID}|%m{chomp}%n

    log4perl.appender.Screen                             = Log::Log4perl::Appender::Screen
    # log4perl.appender.Screen.mode                       = append
    log4perl.appender.Screen.layout                      = Log::Log4perl::Layout::PatternLayout
    log4perl.appender.Screen.layout.ConversionPattern    = %d|%p|%l|%X{TID}|%m{chomp}%n


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
