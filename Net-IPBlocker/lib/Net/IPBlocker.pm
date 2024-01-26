package Net::IPBlocker;

use 5.006;
use strict;
use warnings;

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
The default config file is /etc/ipblocker/ipblocker.conf but you can set it to another file.
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
Or, possibly just a file with the IPs and the time they are to be unblocked.

=item * Add syynchronized appender logging:
      
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

=head2 function1

=cut

sub function1 {
}

=head2 function2

=cut

sub function2 {
}

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
