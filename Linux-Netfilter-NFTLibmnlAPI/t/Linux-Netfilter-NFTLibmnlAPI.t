# Before 'make install' is performed this script should be runnable with
# 'make test'. After 'make install' it should work as 'perl Linux-Netfilter-NFTLibmnlAPI.t'

#########################

# change 'tests => 1' to 'tests => last_test_to_print';

use strict;
use warnings;

use Test::More tests => 5;
# use FindBin;
# use lib "$FindBin::Bin/../lib/";
use lib "/home/gardner/git/ipblockerclassified/Linux-Netfilter-NFTLibmnlAPI/lib/";
BEGIN { use_ok('Linux::Netfilter::NFTLibmnlAPI::API') };

#########################

# Insert your test code below, the Test::More module is use()ed here so read
# its man page ( perldoc Test::More ) for help writing this test script.
ok my $rand = Linux::Netfilter::NFTLibmnlAPI::API::rand(), 'rand()';
like $rand, qr/^\d+$/, 'rand() returns a number';

ok !defined Linux::Netfilter::NFTLibmnlAPI::API::srand(5), 'srand()';
ok $rand ne Linux::Netfilter::NFTLibmnlAPI::API::rand(), 'after srand, rand returns different number';
done_testing;

