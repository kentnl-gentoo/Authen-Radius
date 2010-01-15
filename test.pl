# 	$Id: test.pl,v 1.8 2009/12/31 13:18:47 psv Exp $
# Before `make install' is performed this script should be runnable with
# `make test'. After `make install' it should work as `perl test.pl'

######################### We start with some black magic to print on failure.

# Change 1..1 below to 1..last_test_to_print .
# (It may become useful if the test is moved to ./t subdirectory.)

BEGIN {print "1..5\n";}
END {print "not ok 1\n" unless $loaded;}
use Authen::Radius;
$loaded = 1;
print "ok 1\n";

######################### End of black magic.

# Insert your test code below (better if it prints "ok 13"
# (correspondingly "not ok 13") depending on the success of chunk 13
# of the test code):

print "Make sure this machine is in your Radius clients file!\n";
print "Enter hostname[:port] of your Radius server: "; chomp ($host = <STDIN>);
print "Enter shared-secret of your Radius server: "; chomp ($secret = <STDIN>);
print "Enter a username to be validated: "; chomp ($user = <STDIN>);
print "Enter this user's password: "; chomp ($pwd = <STDIN>);

$t = 2;
if ($host ne '') {
	$r = new Authen::Radius(Host => $host, Secret => $secret, Debug => 1);
	print defined($r) ? "" : "not ", "ok $t\n"; $t++;
	#Authen::Radius->load_dictionary;
	print $r->check_pwd($user, $pwd) ? "" : "not ", "ok $t\n"; $t++;
	@a = $r->get_attributes;
	print $#a != -1 ? "" : "not ", "ok $t\n"; $t++;
	#for $a (@a) {
	#	print "attr: name=$a->{'Name'} value=$a->{'Value'}\n";
	#}
} else {
	foreach my $t (2..4) {
		print "skipped $t\n";
	}
}

sub hex_to_ascii
{
	## Convert each two-digit hex number back to an ASCII character.
	(my $str = shift) =~ s/([a-fA-F0-9]{2})/chr(hex $1)/eg;
	return $str;
}
my $key = "Jefe";
my $data = "what do ya want for nothing?";
my $etalon_digest = hex_to_ascii("750c783e6ab0b503eaa86e310a5db738");
my $digest = Authen::Radius::hmac_md5(undef, $data, $key);
if ($etalon_digest eq $digest) {
	print "ok 5\n";
} else {
	print "not ok 5\n";
}

exit;

