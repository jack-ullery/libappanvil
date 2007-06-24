RUBY_MAKEFILE = Makefile.ruby

WRAPPER_FILES = AppArmorLogRecordParser_wrap.* AppArmorLogRecordParser.so extension.mak .build-stamp

BUILT_SOURCES = AppArmorLogRecordParser_wrap.c

if HAVE_RUBY

all-local: .build-stamp

.build-stamp: AppArmorLogRecordParser_wrap.c
	CFLAGS="$(CFLAGS) -I../../src" $(RUBY) extconf.rb build
	touch .build-stamp

install-exec-local: .build-stamp
	make -f $(RUBY_MAKEFILE) install

endif

AppArmorLogRecordParser_wrap.c: ../SWIG/*.i
	$(SWIG) -ruby -I../SWIG -I../../src -o ./AppArmorLogRecordParser_wrap.c libaalogparse.i

EXTRA_DIST = extconf.rb $(BUILT_SOURCES) examples/*.rb

