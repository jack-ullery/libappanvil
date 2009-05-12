AC_DEFUN([PROG_POD2MAN],[
   AC_CHECK_PROG(POD2MAN,pod2man,pod2man,no)
   if test "$POD2MAN" = "no"; then
      AC_MSG_ERROR([
The pod2man program was not found in the default path.  pod2man is part of
Perl, which can be retrieved from:

    http://www.perl.com/

The latest version at this time is 5.6.1; it is available packaged as the
following archive:

    http://www.perl.com/CPAN/src/stable.tar.gz
])
   fi
])
