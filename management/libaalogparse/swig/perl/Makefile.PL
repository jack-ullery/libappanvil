use ExtUtils::MakeMaker;

use vars qw($CCFLAGS $OBJECT $VERSION $OPTIMIZE);

WriteMakefile(
	'NAME'			=>	'AppArmorLogRecordParser',
	'MAKEFILE'		=>	'Makefile.perl',
	'FIRST_MAKEFILE'	=>	'Makefile.perl',
	);
