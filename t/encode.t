use strict;
use warnings;
use Test::More;

BEGIN { use_ok('Authen::Radius') };

use constant NoVendor => 'not defined';
use constant VendorCisco => 9;

ok( Authen::Radius->load_dictionary('raddb/dictionary'), 'load dictionary');

is( Authen::Radius->_encode_value(NoVendor, 'Called-Station-Id', 'string', 'Called-Station-Id', '163512412'), '163512412', 'string - as-is');
is( Authen::Radius->_encode_value(NoVendor, 'Session-Timeout', 'integer', 'Session-Timeout', 300), "\x00\x00\x01\x2c", 'integer');
is( Authen::Radius->_encode_value(NoVendor, 'NAS-IP-Address', 'ipaddr', 'NAS-IP-Address', "10.20.30.40"), "\x0a\x14\x1e\x28", 'IPv4');
is( Authen::Radius->_encode_value(NoVendor, 'NAS-IPv6-Address', 'ipv6addr', 'NAS-IPv6-Address', "fe80::5cee:a6ff:fe1c:f204"),
    "\xfe\x80\x00\x00\x00\x00\x00\x00\x5c\xee\xa6\xff\xfe\x1c\xf2\x04", 'IPv6');

is( Authen::Radius->_encode_value(NoVendor, 'Framed-IPv6-Prefix', 'ipv6prefix', 'Framed-IPv6-Prefix', "2001:db8:3c4d::/48"),
    "\x00\x30\x20\x01\x0d\xb8\x3c\x4d\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00", 'IPv6 prefix');

is( Authen::Radius->_encode_value(NoVendor, 'Framed-Interface-Id', 'ifid', 'Framed-Interface-Id', "1111:2211:3311:4411"),
    "\x11\x11\x22\x11\x33\x11\x44\x11", 'ifid');

is( Authen::Radius->_encode_value(VendorCisco, 'h323-ivr-in', 'avpair', 'session-protocol', "SIP"), 'session-protocol=SIP', 'avpair');

is( Authen::Radius->_encode_value(NoVendor, 'Digest-Attributes', 'sublist', 'Method', {Method => 'REGISTER'}), "\x03\x0AREGISTER", 'sublist');

is( Authen::Radius->_encode_value(NoVendor, 'NNN-Octets', 'octets', 'NNN-Octets', "0x3cc93c4aa70d4a"), '0x3cc93c4aa70d4a', 'octets');

is( Authen::Radius->_encode_value(NoVendor, 'NNN-Byte', 'byte', 'NNN-Byte', 10), "\x0a", 'byte');
is( Authen::Radius->_encode_value(NoVendor, 'NNN-Short', 'short', 'NNN-Short', 10), "\x00\x0a", 'short');
is( Authen::Radius->_encode_value(NoVendor, 'NNN-Signed', 'signed', 'NNN-Signed', -10), "\xff\xff\xff\xf6", 'signed');
is( Authen::Radius->_encode_value(NoVendor, 'NNN-Signed', 'signed', 'NNN-Signed', 535), "\x00\x00\x02\x17", 'signed');

is( Authen::Radius->_encode_value(NoVendor, 'NNN-Combo', 'combo-ip', 'NNN-Combo', '10.20.30.40'), "\x0a\x14\x1e\x28", 'combo-ip v4');
is( Authen::Radius->_encode_value(NoVendor, 'NNN-Combo', 'combo-ip', 'NNN-Combo', 'fe80::16da:e9ff:feef:ae06'), undef , 'combo-ip v6 not supported');

is( Authen::Radius->_encode_value(NoVendor, 'WiMAX-Capability', 'tlv', 'WiMAX-Capability', [
      {Name => 'WiMAX-Release', Value => '5.0'},
      {Name => 'WiMAX-Hotlining-Capabilities', Value => 'IP-Redirection' },
    ]), "\x01\x05\x35\x2E\x30\x03\x03\x08" , 'TLV');

is( Authen::Radius->_encode_value(NoVendor, 'NNN-Byte', 'none', 'NNN-Byte', 10), undef, 'unknown type');

is( Authen::Radius->_encode_value(NoVendor, 'NNN-Int64', 'integer64', 'NNN-Int64', 12345), "\x00\x00\x00\x00\x00\x00\x30\x39", 'integer64');

is( Authen::Radius->_encode_value(NoVendor, 'NNN-Date', 'date', 'NNN-Date', 1479994575), "\x58\x36\xec\xcf", 'date (the same as integer)');
is( Authen::Radius->_encode_value(NoVendor, 'NNN-Time', 'time', 'NNN-Time', 1479994576), "\x58\x36\xec\xd0", 'time (the same as integer)');

done_testing();
