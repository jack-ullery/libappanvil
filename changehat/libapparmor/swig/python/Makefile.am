if HAVE_PYTHON

BUILT_SOURCES = libapparmor_wrap.c

SWIG_SOURCES = ../SWIG/libapparmor.i

pkgpython_PYTHON = LibAppArmor.py
pkgpyexec_LTLIBRARIES = _libapparmor.la
_libapparmor_la_SOURCES = libapparmor_wrap.c $(SWIG_SOURCES)
_libapparmor_la_CPPFLAGS = $(SWIG_PYTHON_CFLAGS) -I$(top_srcdir)/src -I/usr/include/python
_libapparmor_la_LDFLAGS = -module
_libapparmor_la_LIBADD = ../../src/.libs/libapparmor.so

libapparmor_wrap.c: $(SWIG_SOURCES)
	$(SWIG) -python -I$(top_srcdir)/src -o $@ $<

endif 
