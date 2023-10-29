package IPblocker;

####  Next items to work on:
# Setup authlog to remove IPs for usernames that are allowed to login

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

use strict;
use DateTime;
use File::Basename;

# use Getopt::Long;
use File::Lockfile;
use strict;
use Time::HiRes qw(usleep);
use Regexp::Common qw/ net number /;
use NetAddr::IP::Util qw(inet_ntoa);
use Net::DNS::Dig;
use Term::ANSIColor;
use Config::File;
use Carp;
use Log::Log4perl qw(get_logger);

use Log::Log4perl::Level ();
use Data::Dumper;
use Regexp::IPv6 qw($IPv6_re);

# Thread setup
use threads;
use Thread::Queue;
my $DataQueue = Thread::Queue->new();
my $LoggerTIDS      = ();                     # Thread IDs for tracking or whatever
# Another queue for iptables commands
my $IptablesQueue = Thread::Queue->new();
my $IptablesTIDS  = ();                 # Thread IDs for tracking or whatever

# Data Dumper setup
$Data::Dumper::Sortkeys = 1;
$Data::Dumper::Indent   = 1;

# Not for sure this should be global, but it is for now
my $logger = get_logger();

# Regex for IPv4 and IPv6 capturing.
#   This is critical and needs be consistent across the entire module
my $REGEX_IPV4 = q/.*\b((?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?))\b.*/;
my $REGEX_IPV6 = q/.*\b($IPv6_re)\b.*/;

### Config files and variables
my $CONFIGSFILE       = '/etc/ipblocker/ipblocker.conf';
my $LOG4PERLCONF      = '/etc/ipblocker/log4perl.conf';
my $LOGWATCH_INTERVAL = 3;

### Global prod mode
#       This gets re-set from the configs file
my $PRODMODE = 0;    # 0 = not prod mode, 1 = prod mode

# Reads configs, logging configs, sets up logging, sets up a class and returns a blessed object
#   The sub go() is where the action starts
sub new {
    my $class = shift;
    my $args  = shift;

    if ( !$args ) {
        carp("No arguments passed to new()");
    }
    elsif ( ref($args) ne 'HASH' ) {
        croak("Arguments passed to new() are not a hash reference");
    }

    my $self = {
        configsfile       => $args->{configsfile}                  || $CONFIGSFILE,
        log4perlconf      => $args->{log4perlconf}                 || $LOG4PERLCONF,
        logwatch_interval => $args->{configs}->{logwatch_interval} || $LOGWATCH_INTERVAL,
    };

    if ( -r $self->{log4perlconf} ) {
        Log::Log4perl->init_and_watch( $self->{log4perlconf}, $self->{logwatch_interval} );
    }
    else {
        carp "Log4perl config file >>$self->{log4perlconf}<< is not readable!!!\n";
        carp "Logging to STDOUT at DEBUG level\n";
        Log::Log4perl->easy_init($Log::Log4perl::DEBUG);
    }

    my $logger = get_logger() || croak "Unable to get logger";
    $logger->debug("Logging initialized");

    bless $self, $class;

    $self->{configs} = $self->load_configs( $self->{configsfile} );

    $PRODMODE = $self->{configs}->{prodmode} ||= 0;
    return $self;
} ## end sub new


# Creates two initial threads:
#   One for iptables commands to be ran.
#   Another to watch the log files
#       This in turn creates a thread for each log file to watch
sub go() {
    my $self = shift;

    my $logger = get_logger() || croak "Unable to get logger";

    # If there are no log files to review, then there is nothing to do
    unless ( $self->{configs}->{logs_to_review} ) {
        $logger->error("No logs to review");
        return 0;
    }

    # Create iptables queueing and thread for commands to run against iptables
    my $iptables_thr = threads->create( \&iptables_thread, $self );

    # Create the global chains and add them to the INPUT, OUTPUT, and FORWARD chains
    add_global_chains_to_input_output() or die "Unable to add global chains and global rules";

    # Create a thread for each logger watcher
    my $logger_thr = threads->create( \&logger_thread, $self );

    while (1) {
        my $data = $DataQueue->dequeue();
        $logger->info( "Data from queue: " . Dumper($data) );
    }    

} ## end sub go

sub logger_thread() {
    my $self = shift;

    my $logstoreview = $self->{configs}->{logs_to_review};

    # Make sure the logs to review is a hash reference, if not then log an error and return 0 (false)
    ( ref $logstoreview eq 'HASH' ) or ( $logger->error("Logs to review is not a hash reference") and return 0 );

    # Create global chains and add them to the INPUT, OUTPUT, and FORWARD chains
    add_global_chains_to_input_output() or die "Unable to add global chains and global rules";

    # Create a thread for each log file to review
    foreach my $log ( sort keys %{$logstoreview} ) {
        $logger->info("Reviewing $log");
        my $logobj = $logstoreview->{$log};
        my $thr    = threads->create( \&review_log, $self, $logobj );
        push( @$LoggerTIDS, $thr->tid() );
        $logger->debug( "Thread created for $log: " . $thr->tid() )       if ( $logger->is_debug() );
        $logger->debug( $thr->tid() . " state is " . $thr->is_running() ) if ( $logger->is_debug() );

        # $self->review_log( $logstoreview->{$log} );
    } ## end foreach my $log ( sort keys...)
}

sub review_log() {
    my $self   = shift;
    my $logobj = shift;

    my $logger = get_logger() || croak "Unable to get logger";

    $logger->debug( "Reviewing log object: " . Dumper($logobj) ) if ( $logger->is_debug() );

    $logobj ||= {};

    # set file log values if exist, otherwise set to global values if exist else set to default values
    $logobj->{cycles} ||= $self->{configs}->{cycles} ||= 9007199254740991;
    my $cycles = $logobj->{cycles};
    $logobj->{cyclesleep} ||= $self->{configs}->{cyclesleep} ||= 0.5;  # Default to 0.5 seconds between cycles
    my $cyclesleep = $logobj->{cyclesleep};
    $cyclesleep = $cyclesleep * 1000000;    # Convert to microseconds

    $logger->info(
        "Reviewing $logobj->{file} for $logobj->{cycles} cycles with $logobj->{cyclesleep} seconds between cycles");

    # sleep 10 if ( $logger->is_debug() );

    while ( $cycles > 0 ) {
        $logger->info("$cycles cycles remaining for $logobj->{file}.");
        $logobj = $self->readlogfile($logobj);
        $logobj->{ips_to_block} = $self->_grep_regexps($logobj)
          if ( $logobj->{logcontents} );    # If there is more than 0 lines in the log file, grep for the regexps
        $logobj = $self->clean_ips_to_block($logobj);

        # Future functions/subs
        # $self->already_blocked_ips();
        # $self->block_ips( $ips_to_block );

        $DataQueue->enqueue($logobj);
        $logger->debug("Sleeping for $cyclesleep milliseconds") if ( $logger->is_debug() );
        usleep($cyclesleep);

        $cycles--;
    } ## end while ( $cycles > 0 )
} ## end sub review_log

sub load_configs {
    my $self        = shift;
    my $configsfile = shift;

    my $logger = get_logger() || croak "Unable to get logger";

    if ( -e $configsfile ) {
        $logger->info("Loading configs from $self->{configsfile}");
        $self->{configs} = Config::File::read_config_file( $self->{configsfile} );
        $self->{configs}{globalchain} = split(/,/, $self->{configs}{globalchain}) if ( $self->{configs}{globalchain} );
        $logger->debug( "Configs loaded from $self->{configsfile}: " . Dumper( $self->{configs} ) );
    }
    else {
        $logger->error("Config file $self->{configsfile} does not exist");
        exit 1;
    }

    return $self->{configs};
} ## end sub load_configs

# Special helper function for clean_ips_to_block()
sub reverseMapHash() {
    my $self = shift;
    my $hash = shift;

    my $logger = get_logger() || croak "Unable to get logger";

    # $logger->debug("Hash to reverse map: " . Dumper($hash)) if ( $logger->is_debug() );

    my $new_hash = {};
    foreach my $key ( sort keys %{$hash} ) {
        $new_hash->{ $hash->{$key} }++;

        # delete $hash->{$key};
    }
    return $new_hash;
} ## end sub reverseMapHash

sub clean_ips_to_block() {
    my $logger = get_logger() || croak "Unable to get logger";
    my $self   = shift;
    my $logobj = shift;

    # $logger->debug("Reviewing log object: " . Dumper($logobj)) if ( $logger->is_debug() );

    my $allowdeny        = $logobj->{allowdeny}          ||= $self->{configs}->{allowdeny} ||= "";
    my $logobj_allowlist = $logobj->{allowlist}          ||= $self->{configs}->{allowlist} ||= {};
    my $logobj_denylist  = $logobj->{denylist}           ||= $self->{configs}->{denylist}  ||= {};
    my $global_denylist  = $self->{configs}->{denylist}  ||= {};
    my $global_allowlist = $self->{configs}->{allowlist} ||= {};

    my $ips_to_block = $logobj->{ips_to_block} ||= {};

    # Due to configs, need to reverse map the allowlists and denylists
    $logobj_allowlist = $self->reverseMapHash($logobj_allowlist);
    $logobj_denylist  = $self->reverseMapHash($logobj_denylist);
    $global_allowlist = $self->reverseMapHash($global_allowlist);
    $global_denylist  = $self->reverseMapHash($global_denylist);

    # Some logging info:
    $logger->info("Allow/Deny: $allowdeny");
    $logger->debug( "Logobj allowlist: " . Dumper($logobj_allowlist) ) if ( $logger->is_debug() );
    $logger->debug( "Logobj denylist: " . Dumper($logobj_denylist) )   if ( $logger->is_debug() );
    $logger->debug( "Logobj ips_to_block: " . Dumper($ips_to_block) )  if ( $logger->is_debug() );
    $logger->debug( "Global allowlist: " . Dumper($global_allowlist) ) if ( $logger->is_debug() );
    $logger->debug( "Global denylist: " . Dumper($global_denylist) )   if ( $logger->is_debug() );

    # Combine global and logobj allowlist and denylist
    my $allowlist = { %{$global_allowlist}, %{$logobj_allowlist} };
    my $denylist  = { %{$global_denylist},  %{$logobj_denylist} };

    # More logging info:
    $logger->debug( "Combined allowlist: " . Dumper($allowlist) ) if ( $logger->is_debug() );
    $logger->debug( "Combined denylist: " . Dumper($denylist) )   if ( $logger->is_debug() );

    # Combine denylist with ips_to_block
    $denylist = { %{$denylist}, %{$ips_to_block} };

    # More logging info:
    $logger->debug( "Combined denylist with ips_to_block: " . Dumper($denylist) ) if ( $logger->is_debug() );

    # This is the meat of the function....
    if ( $allowdeny eq 'Deny,Allow' ) {
        $logobj->{ips_to_block} = $denylist;
        return $logobj;
    }

    # Remove allowlist from denylist
    map { delete $denylist->{$_} || $_ } keys %{$allowlist};
    $logobj->{ips_to_block} = $denylist;
    return $logobj;
} ## end sub clean_ips_to_block


# This is the thread for iptables
#   It does very little but what it does is very important
sub iptables_thread() {
    my $self = shift;
    $logger = get_logger() || croak "Unable to get logger";

    while (1) {
        my $data = $IptablesQueue->dequeue();
        $logger->info( "Data from queue: " . Dumper($data) );

        $self->run_iptables($data);
    }
}

# Runs whatever parameters are passed to it against iptables
#  This is intended to be a one stop shop for running
#   iptables out of a queue.  
#   This hopefully prevents excessive wait/locking on iptables
#   and helps to keep commands running in the order they are received.
# run_iptables( { iptables_opts => " -w -N SOMENEWCHAIN ", allowdupes => 0 })
sub run_iptables() {
    my $self = shift;
    my $args = shift;
    my $logger = get_logger() || croak "Unable to get logger";

    my $iptables = `which iptables`;  # might be excessive to run this every time.  hmmmmmm

    $logger->debug("Running run_iptables with arguments: " . Dumper($args)) if ( $logger->is_debug() );

    my $iptables_opts   = $args->{iptables} ||= "";

    $args->{allowdupes}     ||= 0;
    my $allowdupes             = $args->{allowdupes};

    $args->{deleteexisting} ||= 0;
    my $deleteexisting         = $args->{deleteexisting};

    if ( $allowdupes ) {
        my $command = "$iptables $iptables_opts";
        system($command) if ($self->{PRODMODE});
    }
    else {
        # Check if rule already exists
    }

}

# This is a one time event to add the global chains to the INPUT and OUTPUT chains
#   This is only called once when the module is first run
#   This is only called if the global rules do not exist
sub add_global_chains_to_input_output() {
    my $self     = shift;

    # The order in which the global chains are added to the default chains
    my @allowdenyorder = qw /   ipblocker_globalallow   ipblocker_globalallowregex
      ipblocker_globaldeny    ipblocker_globalregexdeny /;

    # User chains setup from config if that exists, otherwise set to default values
    ## No checking of the chains to use as this is at user descretionx
    my @builtinchains = qw / INPUT OUTPUT FORWARD /;
    @builtinchains ||= @{$self->{globalchains}};

    # if allow deny is set to Deny,Allow then change the order of the global chains
    if ( $self->{allowdeny} eq 'Deny,Allow' ) {
        @allowdenyorder = qw /  ipblocker_globaldeny    ipblocker_globalregexdeny
          ipblocker_globalallow   ipblocker_globalallowregex /;
    }

    # Create new chains and new rules if they do not exist
    for my $newchain (@allowdenyorder) {
        # Enqueue new chain to be added to iptables
        $IptablesQueue->enqueue( { iptables => '-w -N $newchain' } );

        for my $builtinchain (@builtinchains) {
            my $arguments = qq/$builtinchain -j $newchain/;

            # Add new rule to the default chain
            #   This will make the default chain jumpt to the new chain
            # Example: iptables -w -A INPUT -j ipblocker_globalallow
            $IptablesQueue->enqueue( { iptables => "-w -A $arguments", allowdupes => 0, deleteexisting => 1 } );
        } ## end for my $builtinchain (@builtinchains)
    } ## end for my $newchain (@allowdenyorder)

    return 1;

} ## end sub add_global_chains_to_input_output

# Create iptables chain
sub create_iptables_chain {
    my $self = shift;
    my $name = shift;

    my $logger = get_logger() || croak "Unable to get logger";

    $logger->info("Creating iptables chain $name");
    if ( $name =~
        m/^(ipblocker_globalallow|ipblocker_globaldeny|ipblocker_globalregexdeny|ipblocker_globalregexallow)$/ )
    {
        $logger->error("Chain name >>$name<< is a reserved name and cannot be used");
        return 0;
    } ## end if ( $name =~ ...)
    system("iptables -w -N $name");
    return 1;
} ## end sub create_iptables_chain

# This function reads the log file into memory from the seek position (if it exists)
# The reading of a log file based on the seek position creates a big issue if the log file is rotated AND is larger than
#   the seek position
#   This is a tradeoff of reading the entire log file into memory and then grepping for the regexps
# Returns: $logobj
sub readlogfile {
    my $self   = shift;
    my $logobj = shift;

    my $logger = get_logger() || croak "Unable to get logger";

    # Check file is readable
    -r $logobj->{file} or ( $logger->error("Log file >>$logobj->{file}<< does not exist") && return $logobj );

    my $file = $logobj->{file};

    # If the readentirefile flag is set, then set the seek position to 0 to read the entire file
    $logobj->{seek} ||= 0;    #It is possible the seek position is already set from a previous readlogfile() call
    $logobj->{seek} = 0 if ( -s $file < $logobj->{seek} );    #Can't seek past the end of the file
    $logobj->{readentirefile} ||= $self->{configs}->{readentirefile} ||= 0;
    $logobj->{seek} = 0 if ( $logobj->{readentirefile} );

    $logger->debug("Reading $file");

    # Open and close the file handle as quickly as possible.
    open my $fh, '<', $file or ( carp "Can't open $file: $!" && return $logobj );
    seek( $fh, $logobj->{seek}, 0 );
    my @logcontents = <$fh>;
    $logobj->{seek} = tell($fh);
    close $fh;

    if ( scalar(@logcontents) == 0 ) {
        $logger->info("No new lines appear to be in $file");
        $logobj->{logcontents} = ();
    }
    else {
        $logger->info( "There are " . scalar(@logcontents) . " lines from $file to review" );
    }

    chomp(@logcontents);
    $logobj->{logcontents} = \@logcontents;

    $logger->info( "The $file file has been read into memory.  " . scalar(@logcontents) . " lines read." );
    $logger->debug( "The $file contents: " . Dumper( $logobj->{logcontents} ) ) if ( $logger->is_debug() );

    return $logobj;
} ## end sub readlogfile

# #This greps for a single regexp and returns the matches
# #   I moved this to a single function for possible later enhancements
# sub _grep_regexp {
#     my $self = shift;
#     my $logobj = shift;
#     my $regex = shift;

#     my @matches = grep { /$regex/ } @{$logobj->{logcontents}};
#     $logger->info("Grep'ing for >>$regex<< in $logobj->{file} from byte position $logobj->{seek} found " . scalar(@matches) . " matches");
#     $logger->debug("Grep'ing for >>$regex<< in $logobj->{file} from byte position $logobj->{seek} found the following matches: " . Dumper(\@matches));

#     return \@matches;
# }

# This greps for multiple regexps and returns the matchedlines from logobj->{logcontents}
# Returns an array reference of matched lines
sub _grep_regexp() {
    my $self    = shift;
    my $logobj  = shift;
    my $regexps = shift;
    my $logger  = get_logger() || croak "Unable to get logger";

    my @matchedlines = ();
    foreach my $regexp ( sort keys %{$regexps} ) {
        my $value = ${$regexps}{$regexp};
        $logger->info("Grep'ing for >>$value<< in $logobj->{file} from byte position $logobj->{seek}");
        @matchedlines = grep { /$value/ } @{ $logobj->{logcontents} };
        $logger->debug( "Dumper of current matches: " . Dumper(@matchedlines) ) if ( $logger->is_debug() );
    } ## end foreach my $regexp ( sort keys...)

    return \@matchedlines;
} ## end sub _grep_regexp

# This handles multiple regular expressions on the log object
sub _grep_regexps {
    my $self   = shift;
    my $logobj = shift;

    my $logger = get_logger() || croak "Unable to get logger";

    # my @matches = ( );
    my %matches;

    my @logcontents = @{ $logobj->{logcontents} };

    my $IPs = {};

    foreach my $regex ( sort keys %{ $logobj->{regexpdeny} } ) {
        my $value = ${ $logobj->{regexpdeny} }{$regex};
        $logger->info("Grep'ing for >>$value<< in $logobj->{file} from byte position $logobj->{seek}");
        my @current_matches = grep { /$value/ } @logcontents;
        $logger->debug( "Dumper of current matches: " . Dumper( \@current_matches ) ) if ( $logger->is_debug() );

        my $array_size  = scalar(@current_matches);
        my $array_index = 0;
        foreach (@current_matches) {
            chomp($_);

            # $logger->info("Checking array record $array_index of $array_size for IP address");
            $array_index++;
            $logger->debug("Checking >>$_<< for IP address");
            if (s/$REGEX_IPV4/$1/) {
                $logger->debug("Found IPv4 address $1: ");
                $matches{$1}++;
            }
            if (s/$REGEX_IPV6/$1/) {
                $logger->debug("Found IPv6 address $1: ");
                $matches{$1}++;
            }
        } ## end foreach (@current_matches)
    } ## end foreach my $regex ( sort keys...)

    $logger->debug( "Dump of matches: " . Dumper( \%matches ) ) if ( $logger->is_debug() );
    my $logmsg = "Matched IP addresses to be reviewed for potential blocking: ";
    foreach ( sort keys %matches ) {
        $logmsg .= "$_,";
    }
    chop $logmsg;
    $logger->info($logmsg);
    return \%matches;
} ## end sub _grep_regexps

1;
