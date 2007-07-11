if HAVE_PYTHON

BUILT_SOURCES = aalogrecordparse_wrap.c

SWIG_SOURCES = ../SWIG/libaalogparse.i

pkgpython_PYTHON = AppArmorLogRecordParser.py
pkgpyexec_LTLIBRARIES = _aalogrecordparse.la
_aalogrecordparse_la_SOURCES = aalogrecordparse_wrap.c $(SWIG_SOURCES)
_aalogrecordparse_la_CPPFLAGS = $(SWIG_PYTHON_CFLAGS) -I$(top_srcdir)/src -I/usr/include/python
_aalogrecordparse_la_LDFLAGS = -module
_aalogrecordparse_la_LIBADD = ../../src/.libs/libaalogparse.so

aalogrecordparse_wrap.c: $(SWIG_SOURCES)
	$(SWIG) -python -I$(top_srcdir)/src -o $@ $<

endif 
