#############################################################################
#                                                                           #
# Radius Client module for Perl 5                                           #
#                                                                           #
# Written by Carl Declerck <carl@miskatonic.inbe.net>, (c)1997              #
# All Rights Reserved. See the Perl Artistic License for copying & usage    #
# policy.                                                                   #
#                                                                           #
# See the file 'Changes' in the distrution archive.                         #
#                                                                           #
#############################################################################

package Authen::Radius;

use FileHandle;
use IO::Socket;
use IO::Select;
use MD5;

use vars qw($VERSION @ISA @EXPORT);

require Exporter;
require AutoLoader;

@ISA = qw(Exporter AutoLoader);
@EXPORT = qw(ACCESS_REQUEST ACCESS_ACCEPT ACCESS_REJECT);
$VERSION = '0.04';

my (%dict_id, %dict_name, %dict_val);
my ($request_id) = $$ & 0xff;	# probably better than starting from 0
my ($radius_error) = 'ENONE';

#
# we'll need to predefine these attr types so we can do simple password
# verification without having to load a dictionary
#

$dict_id{1}{'type'} = 'string';	# set 'username' attr type to string
$dict_id{2}{'type'} = 'string';	# set 'password' attr type to string

sub ACCESS_REQUEST { 1; }
sub ACCESS_ACCEPT  { 2; }
sub ACCESS_REJECT  { 3; }

sub new {
	my $class = shift;
	my %h = @_;
	my ($host, $port);
	my $self = {};

	bless $self, $class;

	$self->set_error;

	return $self->set_error('ENOHOST') unless $h{'Host'};
	($host, $port) = split(/:/, $h{'Host'});

	$port = getservbyname('radius', 'udp') unless $port;
	$port = 1645 unless $port;

	$self->{'timeout'} = $h{'TimeOut'} ? $h{'TimeOut'} : 5;
	$self->{'secret'} = $h{'Secret'};
	$self->{'sock'} = new IO::Socket::INET(
				PeerAddr => $host,
				PeerPort => $port,
				Type => SOCK_DGRAM,
				Proto => 'udp',
				TimeOut => $self->{'timeout'}
	) or return $self->set_error('ESOCKETFAIL');

	$self;
}

sub send_packet {
	my ($self, $type) = @_;
	my ($data);

	$self->set_error;

	$self->gen_authenticator unless defined $self->{'authenticator'};
	$data = pack('C C n', $type, $request_id, 20 + length($self->{'attributes'}))
				. $self->{'authenticator'} . $self->{'attributes'};
	$request_id = ($request_id + 1) & 0xff;

	$self->{'sock'}->send ($data) || $self->set_error('ESENDFAIL');
}

sub recv_packet {
	my ($self) = @_;
	my ($data, $type, $id, $length, $auth, $sh);

	$self->set_error;

	$sh = new IO::Select($self->{'sock'}) or return $self->set_error('ESELECTFAIL');
	$sh->can_read($self->{'timeout'}) or return $self->set_error('ETIMEOUT');

	$self->{'sock'}->recv ($data, 65536) or return $self->set_error('ERECVFAIL');
	($type, $id, $length, $auth, $self->{'attributes'}) = unpack('C C n a16 a*', $data);
	return $self->set_error('EBADAUTH') if $auth ne $self->calc_authenticator($type, $id, $length);

	$type;
}

sub check_pwd {
	my ($self, $name, $pwd) = @_;

	$self->clear_attributes;
	$self->add_attributes (
		{ Name => 1, Value => $name },
		{ Name => 2, Value => $pwd }
	);

	$self->send_packet (ACCESS_REQUEST) && $self->recv_packet == ACCESS_ACCEPT;
}

sub clear_attributes {
	my ($self) = @_;

	$self->set_error;

	delete $self->{'attributes'};

	1;
}

sub get_attributes {
	my ($self) = @_;
	my ($id, $length, $value, $type, $rawvalue, @a);
	my ($attrs) = $self->{'attributes'};

	$self->set_error;	

	while (length($attrs)) {
		($id, $length, $attrs) = unpack('C C a*', $attrs);
		($rawvalue, $attrs) = unpack('a' . ($length - 2) . ' a*', $attrs);
		$type = $dict_id{$id}{'type'};
		if ($type eq "string") {
			$value = $rawvalue;
		} elsif ($type eq "integer") {
			$value = unpack('N', $rawvalue);
			$value = $dict_val{$id}{$value} if defined $dict_val{$id}{$value};
		} elsif ($type eq "ipaddr") {
			$value = inet_ntoa($rawvalue);
		}
		push (@a, {	'Name' => defined $dict_id{$id}{'name'} ? $dict_id{$id}{'name'} : $id,
					'Code' => $id,
					'Value' => $value,
					'RawValue' => $rawvalue }
		);
	}

	@a;
}

sub add_attributes {
	my ($self, @a) = @_;
	my ($a, $id, $type, $value);

	$self->set_error;

	for $a (@a) {
		$id = defined $dict_name{$a->{'Name'}}{'id'} ? $dict_name{$a->{'Name'}}{'id'} : int($a->{'Name'});
		$type = defined $a->{'Type'} ? $a->{'Type'} : $dict_id{$id}{'type'};
		if ($type eq "string") {
			$value = $a->{'Value'};
			if ($id == 2) {
				$self->gen_authenticator;
				$value = $self->encrypt_pwd($value);
			}
		} elsif ($type eq "integer") {
			$value = pack('N', int($a->{'Value'}));
		} elsif ($type eq "ipaddr") {
			$value = inet_aton($a->{'Value'});
		} else {
			next;
		}

		$self->{'attributes'} .= pack('C C', $id, length($value) + 2) . $value;
	}

	1;
}

sub calc_authenticator {
	my ($self, $type, $id, $length) = @_;
	my ($hdr, $ct);

	$self->set_error;

	$hdr = pack('C C n', $type, $id, $length);
	$ct = new MD5;
	$ct->reset ();
	$ct->add ($hdr, $self->{'authenticator'}, $self->{'attributes'}, $self->{'secret'});

	$ct->digest();
}

sub gen_authenticator {
	my ($self) = @_;
	my ($ct);

	$self->set_error;

	$ct = new MD5;
	$ct->reset ();
	# the following could be improved a lot
	$ct->add (sprintf("%08x%04x", time, $$), $self->{'attributes'});

	$self->{'authenticator'} = $ct->digest();
}

sub encrypt_pwd {
	my ($self, $pwd) = @_;
	my ($i, $ct, @pwdp, @xor);

	$self->set_error;

	# this only works for passwords <= 16 chars, anyone use longer passwords?
	@pwdp = unpack('C16', pack('a16', $pwd));
	$ct = new MD5;
	$ct->reset ();
	$ct->add ($self->{'secret'}, $self->{'authenticator'});
	@xor = unpack('C16', $ct->digest());
	for $i (0..15) {
		$pwdp[$i] ^= $xor[$i];
	}

	pack('C' . length($pwd), @pwdp);
}

sub load_dictionary {
	shift;
	my ($file) = @_;
	my ($fh, $cmd, $name, $id, $type);

	$file = "/etc/raddb/dictionary" unless $file;
	$fh = new FileHandle($file) or die "Can't open dictionary '$file' ($!)\n";

	while (<$fh>) {
		chomp;
		($cmd, $name, $id, $type) = split(/\s+/);
		next if (!$cmd || $cmd =~ /^#/);
		if ($cmd =~ /^attribute$/i) {
			$dict_id{$id}{'name'} = $name;
			$dict_id{$id}{'type'} = $type;
			$dict_name{$name}{'id'} = $id;
			$dict_name{$name}{'type'} = $type;
		} elsif ($cmd =~ /^value$/i) {
			$dict_val{$dict_name{$name}{'id'}}{$type} = $id;
		}
	}
	$fh->close;

	1;
}

sub set_error {
	my ($self, $error) = @_;

	$radius_error = $self->{'error'} = defined $error ? $error : 'ENONE';

	undef;
}

sub get_error {
	my ($self) = @_;

	$self->{'error'};
}

sub strerror {
	my ($self, $error) = @_;

	my %errors = (
		'ENONE',		'none',
		'ESELECTFAIL',	'select creation failed',
		'ETIMEOUT',		'timed out waiting for packet',
		'ESOCKETFAIL',	'socket creation failed',
		'ENOHOST',		'no host specified',
		'EBADAUTH',		'bad response authenticator',
		'ESENDFAIL',	'send failed',
		'ERECVFAIL',	'receive failed'
	);

	return $errors{$radius_error} unless ref($self);
	$errors{defined $error ? $error : $self->{'error'}};
}

	

1;
__END__

=head1 NAME

Authen::Radius - provide simple Radius client facilities

=head1 SYNOPSIS

  use Authen::Radius;
  
  $r = new Authen::Radius(Host => 'myserver', Secret => 'mysecret');
  print "auth result=", $r->check_pwd('myname', 'mypwd'), "\n";

  $r = new Authen::Radius(Host => 'myserver', Secret => 'mysecret');
  Authen::Radius->load_dictionary;
  $r->add_attributes (
  		{ Name => 'User-Name', Value => 'myname' },
  		{ Name => 'Password', Value => 'mypwd' }
  );
  $r->send_packet (1) and $type = $r->recv_packet;
  print "server response type = $type\n";
  for $a ($r->get_attributes) {
  	print "attr: name=$a->{'Name'} value=$a->{'Value'}\n";
  }

=head1 DESCRIPTION

The C<Authen::Radius> module provides a simple class that allows you to 
send/receive Radius requests/responses to/from a Radius server.

=head1 CONSTRUCTOR

=over 4

=item new ( Host => HOST, Secret => SECRET [, TimeOut => TIMEOUT] )

Creates & returns a blessed reference to a Radius object, or undef on
failure.  Error status may be retrieved with C<Authen::Radius::get_error> 
(errorcode) or C<Authen::Radius::strerror> (verbose error string).

=back

=head1 METHODS

=over 4

=item load_dictionary ( [ DICTIONARY ] )

Loads the definitions in the specified Radius dictionary file (standard 
Livingston radiusd format). Tries to load 'C</etc/raddb/dictionary>' when no 
argument is specified, or dies.

=item check_pwd ( USERNAME, PASSWORD )

Checks with the Radius server if the specified C<PASSWORD> is valid for user 
C<USERNAME>. This method is actually a wrapper for subsequent calls to
C<clear_attributes>, C<add_attributes>, C<send_packet> and C<recv_packet>. It 
returns 1 if the C<PASSWORD> is correct, or undef otherwise.

=item add_attributes ( { Name => NAME, Value => VALUE [, Type => TYPE] }, ... )

Adds any number of Radius attributes to the current Radius object. Attributes
are specified as a list of anon hashes. They may be C<Name>d with their 
dictionary name (provided a dictionary has been loaded first), or with 
their raw Radius attribute-type values. The C<Type> pair should be specified 
when adding attributes that are not in the dictionary (or when no dictionary 
was loaded). Values for C<TYPE> can be 'C<string>', 'C<integer>' or 'C<ipaddr>'.

=item get_attributes

Returns a list of references to anon hashes with the following key/value
pairs : { Name => NAME, Code => RAWTYPE, Value => VALUE, RawValue =>
RAWVALUE }. Each hash represents an attribute in the current object. The 
C<Name> and C<Value> pairs will contain values as translated by the 
dictionary (if one was loaded). The C<Code> and C<RawValue> pairs always 
contain the raw attribute type & value as received from the server.

=item clear_attributes

Clears all attributes for the current object.

=item send_packet ( REQUEST_TYPE )

Packs up a Radius packet based on the current secret & attributes and
sends it to the server with a Request type of C<REQUEST_TYPE>. Exported
C<REQUEST_TYPE> methods are 'C<ACCESS_REQUEST>', 'C<ACCESS_ACCEPT>' 
and 'C<ACCESS_REJECT>'. Returns the number of bytes sent, or undef on failure.

=item recv_packet

Receives a Radius reply packet. Returns the Radius Reply type (see possible
values for C<REQUEST_TYPE> in method C<send_packet>) or undef on failure. Note 
that failure may be due to a failed recv() or a bad Radius response 
authenticator. Use C<get_error> to find out.

=item get_error

Returns the last C<ERRORCODE> for the current object. Errorcodes are one-word
strings always beginning with an 'C<E>'.

=item strerror ( [ ERRORCODE ] )

Returns a verbose error string for the last error for the current object, or
for the specified C<ERRORCODE>.

=back

=head1 AUTHOR

Carl Declerck <carl@miskatonic.inbe.net>

=cut

