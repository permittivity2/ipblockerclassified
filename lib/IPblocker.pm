package IPblocker;

#### Future enhancements (bugs?):
### 1.  Add syynchronized appender logging:
###       https://metacpan.org/dist/Log-Log4perl/view/lib/Log/Log4perl/Appender/Synchronized.pm
### 2.  Fix the ability for Log4perl to re-read the "log4perl.conf" which seems to not work right now
### 3.  my $interfaces = Net::Ifconfig::Wrapper::Ifconfig('list', '', '', '');
###       This is a list of interfaces.  Need to figure out how to use this to get the IP address of the
###       interfaces.  Need to add those IPs to the global allow list.
### 4.  Fix sub add_ifconfig_ips_to_allowlist() to handle IPv4 and IPv6 addresses



####  Next items to work on:
### Setup authlog to remove IPs for usernames that are allowed to login

#### Description
# This module is designed to read log files and block IP addresses based on regular expressions or as otherwise noted
# in the conf file.
# Conf file is by default located at /etc/ipblocker/ipblocker.conf
# IP blocker sets up iptable chains in the following manner:
#   iptables -N ipblocker
#   iptables -A OUTPPUT -j ipblocker
#   iptables -A INPUT -j ipblocker
#   iptables -N ipblocker_globalallow
#   iptables -N ipblocker_globaldeny
#   iptables -N ipblocker_globalregexdeny
#   iptables -N ipblocker_globalregexallow
#   If the allowdeny is set to 'Allow,Deny' then the following is added:
#       iptables -I ipblocker 1 -j ipblocker_globalallow
#       iptables -I ipblocker 2 -j ipblocker_globalregexallow
#       iptables -I ipblocker 3 -j ipblocker_globaldeny
#       iptables -I ipblocker 4 -j ipblocker_globalregexdeny
#   If the allowdeny is set to 'Deny,Allow' then the following is added:
#       iptables -I ipblocker 1 -j ipblocker_globaldeny
#       iptables -I ipblocker 2 -j ipblocker_globalregexdeny
#       iptables -I ipblocker 3 -j ipblocker_globalallow
#       iptables -I ipblocker 4 -j ipblocker_globalregexallow
#   Each log file to review is setup as a chain.  As an example for /var/log/auth.log which (as an example) has a name
#    of "authlog" in the conf file):
#       iptables -N ipblocker_authlog
#       iptables -A ipblocker -j ipblocker_authlog_allow
#       iptables -A ipblocker -j ipblocker_authlog_regexallow
#       iptables -A ipblocker -j ipblocker_authlog_deny
#       iptables -A ipblocker -j ipblocker_authlog_regexdeny
#  That is a lot of chains but it is easy to see what is going on and easy to manage.
#   Of course, IPs to drop or accept are added to the appropriate chain.
#### Logging!
#   A separate config file is used for logging!
#   The config file for logging is by default located at /etc/ipblocker/log4perl.conf
#   The config file for logging is by default read every 3 seconds to allow for changes to the logging config file in
#       real time

use POSIX qw(LONG_MAX);
use strict;
use DateTime;
use File::Basename;

# use Getopt::Long;
# use File::Lockfile;
use strict;
use Time::HiRes qw(usleep);

# use Regexp::Common qw/ net number /;
# use NetAddr::IP::Util qw(inet_ntoa);
# use Net::DNS::Dig;
# use Term::ANSIColor;
use Config::File;
use Carp;
use Log::Log4perl qw(get_logger :nowarn :levels);
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
# my $REGEX_IPV6 = q/.*\b($IPv6_re)\b.*/;
my $REGEX_IPV6 = q/\b($IPv6_re)\b/;
my $DEFAULTS   = {
    allowdeny           => 'Allow,Deny',
    allowlist           => {},
    configsfile         => '/etc/ipblocker/ipblocker.conf',
    cycles              => LONG_MAX,
    cyclesleep          => 0.5,
    dumpconfigsandexit  => 0,
    denylist            => {},
    forceremovelockfile => 0,
    globalallowlist     => {},
    globalchain         => [
        qw / ipblocker_globalallow ipblocker_globalallowregex ipblocker_globaldeny
          ipblocker_globalregexdeny /
    ],
    globalchains         => [qw / INPUT OUTPUT FORWARD /],
    globaldenylist       => {},
    globalregexallowlist => {},
    globalregexdenylist  => {},
    ignoreinterfaceips   => 1,  #This adds the IPs from the interfaces to the allowlist
    iptables             => '/sbin/iptables',
    lockfile             => '/var/run/ipblocker.run.default',
    log4perlconf         => '/etc/ipblocker/log4perl.conf',
    loglevel             => 'Will use value from log4perl.conf',    # Can be set from calling script.
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

########################################################################################################################
##### Subs below here #####

# Reads configs, logging configs, sets up logging, sets up a class and returns a blessed object
#   The sub go() is where the action starts
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

## Recursive sub to print out a hash to STDOUT in a manner that matches "use Config::File;"
sub recursiveHashPrint {
    my ( $ref, $prefix ) = @_;
    $prefix = '' unless defined $prefix;    # Initialize prefix if not provided

    if ( ref($ref) eq 'HASH' ) {
        foreach my $key ( keys %{$ref} ) {

            # Concatenate the current key to the prefix for the next level
            my $new_prefix = $prefix ? "$prefix][$key" : "[$key";
            recursiveHashPrint( $ref->{$key}, $new_prefix );
        } ## end foreach my $key ( keys %{$ref...})
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

sub iptables_thread() {
    my ($self) = @_;
    my $TID = threads->tid;
    $TID = "TID: " . $TID;

    $logger->info("Starting iptables thread");

    while (1) {
        my $iptablesQueue_pending = eval { $IptablesQueue->pending() };
        unless ( defined $iptablesQueue_pending ) {
            my $logmsg = "$TID|IptablesQueue is in an undefined state. This is probably intentional. ";
            $logmsg .= "Exiting the loop.";
            $logger->info($logmsg);
            last;
        } ## end unless ( defined $iptablesQueue_pending)

        if ( $iptablesQueue_pending > 0 ) {
            $logger->info("$TID|Queue length of IptablesQueue is $iptablesQueue_pending");
            my $data = $IptablesQueue->dequeue();
            $logger->debug( "$TID|Dequeued from IptablesQueue: " . Dumper($data) ) if $logger->is_debug();
            $self->run_iptables($data) || $logger->error( "Not successful running iptables command: " . Dumper($data) );
        } ## end if ( $iptablesQueue_pending...)
        elsif ( $iptablesQueue_pending == 0 ) {
            $logger->info("$TID|IptablesQueue depth: $iptablesQueue_pending.  Sleeping for 1 second.");
            sleep 1;
        }
        else {
            $logger->error("$TID|IptablesQueue queue is in an unknown state. Exiting due to an unknown issue.");
            last;
        }
    } ## end while (1)
} ## end sub iptables_thread

# Creates two initial threads:
#   One for iptables commands to run.
#   Another to watch the log files
#       This in turn creates a thread for each log file to watch
# Also starts running the DataQueue queue which handles the data
sub go() {
    my $self = shift;

    # If there are no log files to review, then there is nothing to do
    unless ( $self->{configs}->{logs_to_review} ) {
        $logger->error("No logs defined in configs to review");
        return 0;
    }

    # Set a few items
    $self->{run_iptables_line} = 245;  # Line number of sub iptables_thread() where run_iptables() is called
    $self->set_iptables_command() or $logger->error("Unable to set iptables command");
    $self->set_signal_handler();
    $self->set_lockFile() or $logger->logdie("Unable to set lock file");
    # $self->add_ifconfig_ips_to_allowlist() if ( $self->{configs}->{ignoreinterfaceips} );  # Not yet implemented

    # Create iptables queueing and thread for commands to run against iptables
    my $iptables_thr = threads->create( \&iptables_thread, $self );

    # Create the global chains and add them to the INPUT, OUTPUT, and FORWARD chains
    $self->add_global_chains_to_input_output()
      or $logger->logdie("Unable to add global chains and global rules");

    # Create a thread for each logger watcher
    # my $logger_thr = threads->create( \&logger_thread, $self );
    $logger->logdie("Unable to review logs") unless ( $self->logger_thread() );

    # sleep 20 and die "death death death";

    # Call the dataQueue_runner() sub to run the DataQueue queue
    #   This is basically the end of main
    #   The dataQueue_runner() sub will run until the DataQueue queue is set to undef which
    #   can be done by multiple ways.
    $self->dataQueue_runner();
} ## end sub go

# Description:  Adds IPs on the local interfaces to the global allowlist
#  This does not work becasue it onkly handles IPv4 addresses
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

sub dataQueue_runner() {
    my ($self) = @_;
    my $TID = threads->tid;
    $TID = "TID: " . $TID;
    
    local $Data::Dumper::Terse  = 1;    # Disable use of $VARn
    local $Data::Dumper::Indent = 0;    # Disable indentation    

    $logger->info("$TID|DataQueue runner");
    my $queuechecktime = $self->{configs}->{queuechecktime};
    my $queuecycles    = $self->{configs}->{queuecycles};

    while (1) {
        my $dataqueue_pending = eval { $DataQueue->pending() };
        unless ( defined $dataqueue_pending ) {
            $logger->info("$TID|DataQueue is in an undefined state. This is probably intentional. Exiting the loop.");
            last;
        }

        if ( $dataqueue_pending > 0 ) {
            $logger->info("$TID|Queue length of DataQueue is $dataqueue_pending");
            my $data = $DataQueue->dequeue();
            ##### Need to add an 'if ( $data eq "stop" )' here to call sub stop() and gracefully exit
            $logger->debug( "$TID|Dequeued from DataQueue: " . Dumper($data) ) if $logger->is_debug();
        } ## end if ( $dataqueue_pending...)
        elsif ( $dataqueue_pending == 0 ) {
            my $logmsg = "$TID|DataQueue depth: $dataqueue_pending.  Sleeping: $queuechecktime second(s).  ";
            $logmsg .= "Queue cycles remaining: $queuecycles";
            $logger->info($logmsg);
            $queuecycles--;
            last if ( $queuecycles <= 0 );
            sleep $queuechecktime;
        } ## end elsif ( $dataqueue_pending...)
        else {
            $logger->error("$TID|DataQueue is in an unknown state. Leaving queue watch due to an unknown issue.");
            last;
        }
    } ## end while (1)

    $logger->info("$TID|DataQueue runner exiting");
} ## end sub dataQueue_runner

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
        $logobj->{chain} = $logtoreview;  # Set the chain name to object value
                                          #  This is used in the create_iptables_commands() sub
        my $thr    = threads->create( \&review_log, $self, $logobj ) or $logger->logdie("Unable to create thread");
        push( @$LoggerTIDS, $thr->tid() );
        $logger->debug( "Thread created for $logtoreview: " . $thr->tid() )                  if ( $logger->is_debug() );
        $logger->debug( "Thread id >>" . $thr->tid() . "<< state is " . $thr->is_running() ) if ( $logger->is_debug() );

        # $self->review_log( $logstoreview->{$log} );
    } ## end foreach my $logtoreview ( sort...)

    return 1;
} ## end sub logger_thread

# This is called as a thread and runs a loop to check the log file for new entries
#   Prior to checking the log file, it creates a chain for the log file and adds it to the global chain
sub review_log() {
    my ( $self, $logobj ) = @_;

    $logobj ||= {};
    my $TID = threads->tid;
    $TID = "TID: " . $TID;

    $logger->debug( "$TID|Reviewing log object: " . Dumper($logobj) ) if ( $logger->is_debug() );

    # set file log values if exist, otherwise set to global values if exist else set to default values
    $logobj->{cycles} ||= $self->{configs}->{cycles} ||= LONG_MAX;
    my $cycles = $logobj->{cycles};
    $logobj->{cyclesleep} ||= $self->{configs}->{cyclesleep} ||= 0.5;    # Default to 0.5 seconds between cycles
    my $cyclesleep = $logobj->{cyclesleep};
    $cyclesleep = $cyclesleep * 1000000;                                 # Convert to microseconds

    $logger->info(
        "$TID|Reviewing $logobj->{file} for $logobj->{cycles} cycles with $logobj->{cyclesleep} seconds between cycles"
    );

    # sleep 10 if ( $logger->is_debug() );

    # Create the chain for the log file
    my $chain = "ipblocker_" . $logobj->{chain};
    $logger->info("$TID|Creating >>$chain<< chain (this actually adds to a queue to be ran)");
    $self->create_iptables_chain($chain);

    # Add rule for chain to INPUT and OUTPUT chains
    $logger->info("$TID|Adding chain >>$chain<< to INPUT and OUTPUT chains");
    for my $table ( qw/ INPUT OUTPUT / ) {
        my $args = {
            options => "-A",
            rule    => "$table -j $chain",
        };
        $logger->info("$TID|Adding rule to iptablesqueue: -A $table -j $chain");
        $self->iptablesqueue_enqueue($args);
    }

    while ( $cycles > 0 ) {
        $logger->info("$TID|$cycles cycles remaining for $logobj->{file}.");
        $logobj                 = $self->readlogfile($logobj);
        $logobj->{ips_to_block} = $self->_grep_regexps($logobj) if ( $logobj->{logcontents} );
        $logobj                 = $self->clean_ips_to_block_allowdeny($logobj);
        # my $iptables_commands   = $self->iptables_ipblock_commands($logobj);

        # Future functions/subs
        # $self->already_blocked_ips();
        # $self->block_ips( $ips_to_block );

        # $logger->debug( "$TID|Adding log object to DataQueue: " . Dumper($logobj) ) if ( $logger->is_debug() );
        # $DataQueue->enqueue($logobj);

        for my $ip ( keys %{$logobj->{ips_to_block}} ) {
            $logger->info("$TID|Adding $ip to iptablesqueue");
            my $args = {
                options => "-A",
                rule    => "$chain -s $ip -j DROP",
            };
            $logger->debug("$TID|Adding rule to iptablesqueue: -A $chain -s $ip -j DROP");
            $self->iptablesqueue_enqueue($args);

            my $args = {
                options => "-A",
                rule    => "$chain -d $ip -j DROP",
            };
            $logger->debug("$TID|Adding rule to iptablesqueue: -A $chain -d $ip -j DROP");
            $self->iptablesqueue_enqueue($args);
        } ## end for my $ip ( keys $logobj...)

        last unless --$cycles;    # Break out of loop if $cycles is 0
        $logger->info("$TID|Sleeping for $cyclesleep microseconds");
        usleep($cyclesleep);
    } ## end while ( $cycles > 0 )

    $logger->info("$TID|Finished reviewing $logobj->{file}.  Cycles completed: $logobj->{cycles}");
    return 1;
} ## end sub review_log

# Description: takes the ips_to_block, ports, and protocols and creates the iptables commands to run
# Returns a hash of iptables commands to run
sub iptables_ipblock_commands() {
    my $self   = shift;
    my $logobj = shift;

    my $TID = threads->tid;
    $TID = "TID: " . $TID;

    $logobj ||= {};

    # $logger->debug( "$TID|Logobj: " . Dumper($logobj) ) if ( $logger->is_debug() );

    my $iptables_commands = {};

    # Create the iptables commands to run
    #   This is a hash of hashes
    #   The key is the chain name
    #   The value is a hash of hashes
    #       The key is the IP address
    #       The value is a hash of hashes
    #           The key is the port
    #           The value is a hash of hashes
    #               The key is the protocol
    #               The value is the iptables command to run
    my $ips_to_block = $logobj->{ips_to_block} ||= {};
    foreach my $chain ( sort keys %{$ips_to_block} ) {
        foreach my $ip ( sort keys %{ $ips_to_block->{$chain} } ) {
            foreach my $port ( sort keys %{ $ips_to_block->{$chain}->{$ip} } ) {
                foreach my $protocol ( sort keys %{ $ips_to_block->{$chain}->{$ip}->{$port} } ) {
                    my $iptables_command = $self->{iptables_command};
                    $iptables_command =~ s/<<CHAIN>>/$chain/g;
                    $iptables_command =~ s/<<IP>>/$ip/g;
                    $iptables_command =~ s/<<PORT>>/$port/g;
                    $iptables_command =~ s/<<PROTOCOL>>/$protocol/g;
                    $iptables_commands->{$chain}->{$ip}->{$port}->{$protocol} = $iptables_command;
                } ## end foreach my $protocol ( sort...)
            } ## end foreach my $port ( sort keys...)
        } ## end foreach my $ip ( sort keys...)
    } ## end foreach my $chain ( sort keys...)

    $logger->debug( "$TID|Iptables commands to run: " . Dumper($iptables_commands) ) if ( $logger->is_debug() );

    return $iptables_commands;
} ## end sub create_iptables_commands

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

}

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
        return $logobj;
    }
    ## If we Allow first then we need to remove IPs from the denylist
    ## The map below removes allowlist from denylist
    ## The || (or) is used to prevent undef errors
    map { delete $denylist->{$_} || $_ } keys %{$allowlist};
    $logobj->{ips_to_block} = $denylist;
    return $logobj;
} ## end sub clean_ips_to_block

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
sub run_iptables() {
    my ( $self, $args ) = @_;
    my @caller_lst = caller(0);
    my $goodcaller = $self->{run_iptables_line};
    if ( $caller_lst[2] != $goodcaller ) {
        my $logmsg = "Looks like the calling sub is not sub iptables_thread.  This is not good.  "
        . "Caller:\n" . Dumper(@caller_lst) . "\n"
        . "The calling sub was at line $caller_lst[2] and not at line $goodcaller ."
        . "This will not be stopped but it should be investigated.  "
        . "Consider calling iptablesqueue_enqueue() instead of run_iptables().  "
        . "Maybe you meant to call \$self->iptablesqueue_enqueue(\$args) instead of \$self->run_iptables(\$args)";\
        $logger->error($logmsg);
    }
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
        if ( $retval eq "rule exists" ) {

            #Since the rule exists and we are not allowing dupes, then we do not need to add the rule and
            # we return success
            $logger->debug("$TID|Rule exists.  Not adding rule: $iptables $options $rule");
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
            $self->{chains_created}->{$rule}++;
        } ## end elsif ( ( $retval eq "create chain"...))
        elsif ( $retval eq "chain does not exist" ) {
            $logger->error("$TID|Chain does not exist for the rule.  Not creating rule: $iptables $options $rule");
            return 0;
        }
        elsif ( $retval eq "permission denied" ) {
            $logger->error("$TID|Permission denied (not root?).  Can't check if rule exists: $iptables $options $rule");
            return 0;
        }
        else {
            $logger->error( "$TID|Unknown return from check_if_rule_exists(): " . $retval );
            return 0;
        }
    } ## end if ( $allowdupes == 0 )

    my $command = "$iptables $options $rule 2>&1";
    if ( $self->{configs}->{PRODMODE} ) {
        $logger->debug("$TID|Running $command");
        my $output = `$command`;
        $logger->debug("$TID|Output of iptables command: $output");
        return 1;
    }
    else {
        $logger->info("$TID|In test mode.  Would run: $command");
        return 1;
    }

    # Should not get here but by default return 0
    $logger->error("$TID|Should not get here but by default returning 0");
    return 0;
} ## end sub run_iptables

# Maybe an unnecessary sub but maybe some better checks down the road
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

# This is a one time event to add the global chains to the INPUT and OUTPUT chains
#   This is only called once when the module is first run
#   This is only called if the global rules do not exist
sub add_global_chains_to_input_output() {
    my $self = shift;

    # The order in which the global chains are added to the default chains
    my @allowdenyorder = qw /   ipblocker_globalallow   ipblocker_globalallowregex
      ipblocker_globaldeny    ipblocker_globalregexdeny /;

    # User chains setup from config if that exists, otherwise set to default values
    ## No checking of the chains to use as this is at user descretionx
    my @builtinchains = qw / INPUT OUTPUT FORWARD /;
    if ( ref $self->{configs}->{globalchains} eq 'ARRAY' ) {
        @builtinchains = @{ $self->{configs}->{globalchains} };
    }

    # @builtinchains ||= @{$self->{globalchains}};

    # if allow deny is set to Deny,Allow then change the order of the global chains
    $self->{configs}->{allowdeny} ||= 'Allow,Deny';
    @allowdenyorder = reverse @allowdenyorder if $self->{configs}->{allowdeny} eq 'Deny,Allow';

    # # Change the order of the global chains if allowdeny is set to Deny,Allow
    # if ( $self->{configs}->{allowdeny} eq 'Deny,Allow' ) {
    #     @allowdenyorder = qw /  ipblocker_globaldeny    ipblocker_globalregexdeny
    #       ipblocker_globalallow   ipblocker_globalallowregex /;
    # }

    # Create new chains and new rules if they do not exist
    for my $newchain (@allowdenyorder) {

        # Enqueue new chain to be added to iptables
        $IptablesQueue->enqueue(
            {
                options => qq/-w -N/,
                rule    => qq/$newchain/
            }
        );

        for my $builtinchain (@builtinchains) {
            my $arguments = qq/$builtinchain -j $newchain/;

            # Add new rule to the default chain
            #   This will make the default chain jump to the new chain
            # Example: iptables -w -A INPUT -j ipblocker_globalallow
            $IptablesQueue->enqueue(
                {
                    options        => qq/-w -A/,
                    rule           => qq/$arguments/,
                    allowdupes     => 0,
                    deleteexisting => 1
                }
            );
        } ## end for my $builtinchain (@builtinchains)
    } ## end for my $newchain (@allowdenyorder)

    return 1;

} ## end sub add_global_chains_to_input_output

# Create iptables chain
sub create_iptables_chain() {
    my ( $self, $name ) = @_;
    my $TID = threads->tid;

    $logger->info("TID: $TID|Trying to create iptables chain >>$name<<");
    if ( $name =~
        m/^(ipblocker_globalallow|ipblocker_globaldeny|ipblocker_globalregexdeny|ipblocker_globalregexallow)$/ )
    {
        $logger->error("TID: $TID|Chain name >>$name<< is a reserved name and cannot be used");
        return 0;
    } ## end if ( $name =~ ...)
    my $rule = "$name";
    my $options = "-w -N";
    my $args = { rule => $rule, options => $options };
    # Never directly run "run_iptables" --- always add to the queue
    $self->iptablesqueue_enqueue($args);
    return 1;
} ## end sub create_iptables_chain

sub iptablesqueue_enqueue() {
    my ( $self, $args ) = @_;
    my $TID = threads->tid;
    $TID = "TID: " . $TID;
    if ( $logger->is_debug() ) {
        my $lastqitem = $IptablesQueue->peek(-1);
        $logger->debug("TID: $TID|Last item in queue before enqueue: " . Dumper($lastqitem));
        $logger->debug("$TID|Enqueuing onto the iptables queue: " . Dumper($args));
    }
    $IptablesQueue->enqueue($args);
    if ( $logger->is_debug() ) {
        my $lastqitem = $IptablesQueue->peek(-1);
        $logger->debug("TID: $TID|Last item in queue after enqueue: " . Dumper($lastqitem));
    }    
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

    $logger->debug("$TID|Reading $file");

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

    if ( scalar(@logcontents) == 0 ) {
        $logger->info("$TID|No new lines appear to be in $file");
        $logobj->{logcontents} = ();
    }
    else {
        $logger->debug( "There are " . scalar(@logcontents) . " lines from $file to review" );
    }

    chomp(@logcontents);
    $logobj->{logcontents} = \@logcontents;    #  Might be better to clone?  Hmmm, maybe not.

    $logger->debug( "$TID|The $file file has been read into memory.  " . scalar(@logcontents) . " lines read." );
    $logger->trace( "$TID|The $file contents: " . Dumper( $logobj->{logcontents} ) ) if ( $logger->is_trace() );

    return $logobj;
} ## end sub readlogfile

# # This greps for multiple regexps and returns the matchedlines from logobj->{logcontents}
# # Returns an array reference of matched lines
# sub _grep_regexp() {
#     my ( $self, $logobj, $regexps ) = @_;
#     my @matchedlines = ();
#     foreach my $regexp ( sort keys %{$regexps} ) {

#         # my $value = $regexps->{$regexp};
#         my $value = ${$regexps}{$regexp};
#         $logger->info("Grep'ing for >>$value<< in $logobj->{file} from byte position $logobj->{seek}");

#         # @matchedlines = grep { /$value/ } @{ $logobj->{logcontents} };
#         push @matchedlines, grep { /$value/ } @{ $logobj->{logcontents} };
#         $logger->debug( "Dumper of current matches: " . Dumper(@matchedlines) ) if ( $logger->is_debug() );
#     } ## end foreach my $regexp ( sort keys...)

#     return \@matchedlines;
# } ## end sub _grep_regexp

# Description:  Using the logobj, this greps against the log contents for matching lines and then gets the 
#               IP address on each line.
# Returns:  Hash reference of IP addresses with count of how many times the IP address was found
sub _grep_regexps {
    my ($self, $log) = @_;
    my $TID = "TID: " . threads->tid;

    my $matches = {};
    my @log_contents = @{ $log->{logcontents} };

    # DO NOT SORT NUMERICALLY!  The info in the configs states the order is sorted alphabetically
    foreach my $regex (sort keys %{ $log->{regexpdeny} }) {
        my $pattern = $log->{regexpdeny}{$regex};
        $logger->info("$TID|Grep'ing for >>$pattern<< in $log->{file} from byte position $log->{seek}");
        
        my @current_matches = grep { /$pattern/ } @log_contents;
        $logger->debug("$TID|Dumper of current matches: " . Dumper(@current_matches)) if $logger->is_debug();

        foreach my $line (@current_matches) {
            chomp($line);
            $logger->debug("$TID|Checking >>$line<< for IP address");
            
            foreach my $ip_address ($line =~ /$REGEX_IPV4/g, $line =~ /$REGEX_IPV6/g) {
                $matches->{$ip_address}++;
                $logger->debug("$TID|Found IP address: $ip_address");
            }
        }
    }

    $logger->debug("$TID|Dump of IP matches after all regex comparisons: " . Dumper($matches)) if $logger->is_debug();

    my $log_msg = "$TID|Matched IP addresses to be reviewed for potential blocking: ";
    $log_msg .= join(",", keys %{$matches});
    $logger->info($log_msg);

    return $matches;
}
#### My original sub _grep_regexps() before refactor by chat gpt
# sub _grep_regexps() {
#     my ( $self, $logobj ) = @_;
#     my $TID = threads->tid;
#     $TID = "TID: " . $TID;

#     # my @matches = ( );
#     my $matches;

#     my @logcontents = @{ $logobj->{logcontents} };

#     my $IPs = {};

#     for my $regex ( sort keys %{ $logobj->{regexpdeny} } ) {
#         my $value = $logobj->{regexpdeny}{$regex};

#         # my $value = ${ $logobj->{regexpdeny} }{$regex};
#         $logger->info("$TID|Grep'ing for >>$value<< in $logobj->{file} from byte position $logobj->{seek}");
#         my @current_matches = grep { /$value/ } @logcontents;
#         $logger->debug( "$TID|Dumper of current matches: " . Dumper( \@current_matches ) ) if ( $logger->is_debug() );

#         my $array_size  = scalar(@current_matches);
#         my $array_index = 0;
#         for my $line (@current_matches) {
#             chomp($line);

#             # $logger->info("Checking array record $array_index of $array_size for IP address");
#             $array_index++;
#             $logger->debug("$TID|Checking >>$line<< for IP address");
#             # if (s/$REGEX_IPV4/$1/) {
#             #     $logger->debug("Found IPv4 address $1: ");
#             #     $matches{$1}++;
#             # }
#             my @ip_addresses = ();
#             push @ip_addresses, $line =~ /$REGEX_IPV4/g;
#             push @ip_addresses, $line =~ /$REGEX_IPV6/g;
#             map { $matches->{$_}++ && $logger->debug("Found IP address: $_ ") } @ip_addresses;
#             # if (s/$REGEX_IPV6/$1/) {
#             #     $logger->debug("$TID|Found IPv6 address $1: ");
#             #     $matches{$1}++;
#             # }
#             # my @ipv6_addresses = $_ =~ /$REGEX_IPV6/g;
#         } ## end for (@current_matches)
#     } ## end for my $regex ( sort keys...)

#     $logger->debug( "$TID|Dump of matches: " . Dumper( $matches ) ) if ( $logger->is_debug() );
#     my $logmsg = "$TID|Matched IP addresses to be reviewed for potential blocking: ";
#     $logmsg .= join( ",", sort keys %{$matches} );

#     # foreach ( sort keys %matches ) {
#     #     $logmsg .= "$_,";
#     # }
#     # chop $logmsg;
#     $logger->info($logmsg);
#     return $matches;
# } ## end sub _grep_regexps

# Stops the module
#  Future enhancements:
#   Clear the thread queues
sub stop() {
    my ($self) = @_;
    $logger->info("Setting DataQueue and IptablesQueue to end");

    # Removing chains that were created (or tried to be created)
    if ( $self->{chains_created} ) {
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
        $logger->info("Looks like kill 3 was issued instead of a polite stop");
    }

    $logger->info("Clearing queues (error will be logged if there is an issue)");
    clear_queues() || $logger->error("Unable to clear queues");
    $logger->info("Waiting for threads to finish (join) (error will be logged if there is an issue)");
    join_threads() || $logger->error("Unable to join threads");

    $logger->info("Releasing lock");
    $lock_obj->release;
    $logger->info("Bye bye");
} ## end sub stop

# Joins all threads
#   Simple sub but really needs some rework
#   If a thread is taking a while to join then it will block the other threads from joining
#   Some of the threads could be reading a log file and if the log file is large then it could take a while or
#   if the log file is causing soem kind of blocking for reading then it could take a while.
#   This may be an issue, if an example, if trying to read a file across NFS or SSHFS and there is a network issue.
sub join_threads() {
    $logger->debug("Waiting for threads to finish (join)");
    $_->join() for threads->list();
    return 1;
}

# Clears the queues
sub clear_queues() {
    $logger->debug("Clearing queues");
    $DataQueue->end();
    $IptablesQueue->end();
    while ( $DataQueue->pending() || $IptablesQueue->pending() ) {
        $DataQueue->pending()     && $logger->debug("Data still in DataQueue");
        $IptablesQueue->pending() && $logger->debug("Data still in IptablesQueue");
        sleep 1;
    }

    if ( $DataQueue->pending() || $IptablesQueue->pending() ) {
        $logger->error("Data still in queue.  This may be an issue.");
        return 0;
    }
    else {
        $logger->debug("No queued items in DataQueue or IptablesQueue");
        return 1;
    }
} ## end sub clear_queues

sub reload() {
    $logger->info("Reloading not yet implemented.  Do a CTRL-C (SIG_INT) and restart the module");

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

1;
