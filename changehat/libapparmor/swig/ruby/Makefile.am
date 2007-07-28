if HAVE_RUBY

RUBY_MAKEFILE = Makefile.ruby

WRAPPER_FILES = LibAppArmor_wrap.* LibAppArmor.so extension.mak .build-stamp

BUILT_SOURCES = LibAppArmor_wrap.c

all-local: .build-stamp

.build-stamp: LibAppArmor_wrap.c
	CFLAGS="$(CFLAGS) -I../../src" $(RUBY) extconf.rb build
	touch .build-stamp

install-exec-local: .build-stamp
	make -f $(RUBY_MAKEFILE) install

LibAppArmor_wrap.c: ../SWIG/*.i
	$(SWIG) -ruby -I../SWIG -I../../src -o ./LibAppArmor_wrap.c libapparmor.i

endif 

EXTRA_DIST = extconf.rb $(BUILT_SOURCES) examples/*.rb

