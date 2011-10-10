#!perl -T

use Test::More tests => 1;

BEGIN {
    use_ok( 'Dancer::Plugin::Auth::Htpasswd' ) || print "Bail out!
";
}

diag( "Testing Dancer::Plugin::Auth::Htpasswd $Dancer::Plugin::Auth::Htpasswd::VERSION, Perl $], $^X" );
