#!perl
use 5.006;
use strict;
use warnings;
use Test::More;

plan tests => 1;

BEGIN {
    use_ok( 'Net::IPBlocker' ) || print "Bail out!\n";
}

diag( "Testing Net::IPBlocker $Net::IPBlocker::VERSION, Perl $], $^X" );
