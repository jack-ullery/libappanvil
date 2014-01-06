m4_define([__apparmor_version], m4_sinclude(common/Version))
m4_ifdef(__apparmor_version, , m4_define([__apparmor_version], m4_sinclude(../../common/Version)))
m4_define([__aalen], decr(len(__apparmor_version)))
m4_define([apparmor_version], m4_substr(__apparmor_version, 0, __aalen))

AC_INIT(configure.ac)

AM_INIT_AUTOMAKE(libapparmor1, apparmor_version)

AM_PROG_LEX
AC_PROG_YACC
AC_PROG_SED
PKG_PROG_PKG_CONFIG

AC_PATH_PROG([SWIG], [swig])

sinclude(m4/ac_pod2man.m4)
PROG_POD2MAN

AC_MSG_CHECKING([whether python bindings are enabled])
AC_ARG_WITH(python,
[  --with-python           enable the python wrapper  [[default=no]]],
[AC_MSG_RESULT($withval)], [AC_MSG_RESULT(no)])
if test "$with_python" = "yes"; then
   test -z "$SWIG" && AC_MSG_ERROR([swig is required when enabling python bindings])
   AC_PATH_PROG(PYTHON, python)
   test -z "$PYTHON" && AC_MSG_ERROR([python is required when enabling python bindings])
   sinclude(m4/ac_python_devel.m4)
   AC_PYTHON_DEVEL
   AM_PATH_PYTHON
fi

AC_MSG_CHECKING([whether perl bindings are enabled])
AC_ARG_WITH(perl,
[ --with-perl           enable the perl wrapper [[default=no]]],
[AC_MSG_RESULT($withval)], [AC_MSG_RESULT(no)])
if test "$with_perl" = "yes"; then
   test -z "$SWIG" && AC_MSG_ERROR([swig is required when enabling perl bindings])
   AC_PATH_PROG(PERL, perl)
   test -z "$PERL" && AC_MSG_ERROR([perl is required when enabling perl bindings])
   perl_includedir="`$PERL -e 'use Config; print $Config{archlib}'`/CORE"
   AC_CHECK_FILE($perl_includedir/perl.h, enable_perl=yes, enable_perl=no)
fi


AC_MSG_CHECKING([whether ruby bindings are enabled])
AC_ARG_WITH(ruby,
[ --with-ruby           enable the ruby wrapper [[default=no]]],
[AC_MSG_RESULT($withval)], [AC_MSG_RESULT(no)])
if test "$with_ruby" = "yes"; then
   test -z "$SWIG" && AC_MSG_ERROR([swig is required when enabling ruby bindings])
   AC_PATH_PROG([RUBY], [ruby])
   test -z "$RUBY" && AC_MSG_ERROR([ruby is required when enabling ruby bindings])
fi


AM_CONDITIONAL(HAVE_PYTHON, test x$with_python = xyes)
AM_CONDITIONAL(HAVE_PERL, test x$with_perl = xyes) 
AM_CONDITIONAL(HAVE_RUBY, test x$with_ruby = xyes)

AC_HEADER_STDC
AC_CHECK_HEADERS(unistd.h stdint.h)

AC_CHECK_FUNCS(asprintf)

AM_PROG_CC_C_O
AC_C_CONST
AM_PROG_LIBTOOL

AC_OUTPUT(
Makefile
doc/Makefile
src/Makefile
swig/Makefile
swig/perl/Makefile
swig/perl/Makefile.PL
swig/python/Makefile
swig/python/setup.py
swig/python/test/Makefile
swig/ruby/Makefile
testsuite/Makefile
testsuite/config/Makefile
testsuite/libaalogparse.test/Makefile
testsuite/lib/Makefile
include/Makefile
include/sys/Makefile
)
