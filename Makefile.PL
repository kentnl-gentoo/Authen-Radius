use ExtUtils::MakeMaker;
# See lib/ExtUtils/MakeMaker.pm for details of how to influence
# the contents of the Makefile that is written.
WriteMakefile(
			  'NAME'	=> 'Authen::Radius',
			  'VERSION_FROM' => 'Radius.pm', # finds $VERSION
			  'PREREQ_PM' => {
							  'MD5' => 1.7,
							  'IO' => 1.12,
							  'Data::Dumper' => 1,
							  'Data::HexDump' => 0.02
							 }
);
