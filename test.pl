# Before `make install' is performed this script should be runnable with
# `make test'. After `make install' it should work as `perl test.pl'

use strict;
use warnings;

use Getopt::Long;
use Test::More tests => 6;

BEGIN {
    use_ok('Authen::Radius');
}

require_ok('Authen::Radius');

my $interactive = 0;
my $verbose     = 0;

GetOptions( "interactive!" => \$interactive, "verbose+" => \$verbose );

SKIP: {
    skip( "Non-interactive mode", 3 ) unless ($interactive);

    print "Make sure this machine is in your Radius clients file!\n";

    print "Enter hostname[:port] of your Radius server: ";
    chomp( my $host = <STDIN> );

    print "Enter shared-secret of your Radius server: ";
    chomp( my $secret = <STDIN> );

    print "Enter a username to be validated: ";
    chomp( my $user = <STDIN> );

    print "Enter this user's password: ";
    chomp( my $pwd = <STDIN> );

    my $r = new_ok(
        'Authen::Radius' => [
            Host   => $host,
            Secret => $secret,
            Debug  => $verbose,
        ],
    );

    # Authen::Radius->load_dictionary();

    my $result = $r->check_pwd( $user, $pwd );
    ok($result);

    my @attributes = $r->get_attributes();
    cmp_ok( $#attributes, '!=', -1 );
}

# Convert each two-digit hex number back to an ASCII character.
sub hex_to_ascii {
    my $str = shift;
    return $str unless ( defined $str );
    $str =~ s/([a-fA-F0-9]{2})/chr(hex $1)/eg;
    return $str;
}

my $key  = "Jefe";
my $data = "what do ya want for nothing?";

my $etalon_digest = hex_to_ascii("750c783e6ab0b503eaa86e310a5db738");

my $digest = Authen::Radius::hmac_md5( undef, $data, $key );
cmp_ok( $digest, 'eq', $etalon_digest );
