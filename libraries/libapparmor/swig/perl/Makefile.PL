use ExtUtils::MakeMaker;

use vars qw($CCFLAGS $OBJECT $VERSION $OPTIMIZE);

WriteMakefile(
	'NAME'			=>	'LibAppArmor',
	'MAKEFILE'		=>	'Makefile.perl',
	'FIRST_MAKEFILE'	=>	'Makefile.perl',
	);
