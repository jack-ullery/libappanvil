if HAVE_PERL

PERL_MAKEFILE = Makefile.perl

WRAPPER_SOURCE = libaalogparse_wrap.c AppArmorLogRecordParser.pm

all-local: .build-stamp

.build-stamp: $(WRAPPER_SOURCE) $(PERL_MAKEFILE)
	make -f $(PERL_MAKEFILE)
	touch .build-stamp

check-local: .build-stamp
	make -f $(PERL_MAKEFILE) test

install-exec-local: .build-stamp
	make -f $(PERL_MAKEFILE) install_vendor

clean-local: $(PERL_MAKEFILE)
	make -f $(PERL_MAKEFILE) clean
	rm -f $(PERL_MAKEFILE).old
	rm -rf build

$(PERL_MAKEFILE): Makefile.PL
	$(PERL) Makefile.PL VERSION="0.1" OBJECT="../../src/.libs/libaalogparse.so libaalogparse_wrap.o" CCFLAGS="-I../../src -D_REENTRANT -D_GNU_SOURCE -DTHREADS_HAVE_PIDS -fno-strict-aliasing -pipe -Wdeclaration-after-statement" OPTIMIZE="$(CFLAGS) -shared -I$(includedir) -D_REENTRANT -D_GNU_SOURCE -DTHREADS_HAVE_PIDS -fno-strict-aliasing -pipe -Wdeclaration-after-statement"


$(WRAPPER_SOURCE): ../SWIG/*.i
	$(SWIG) -perl -I../../src -I../SWIG -o libaalogparse_wrap.c libaalogparse.i

endif

EXTRA_DIST = Makefile.PL $(WRAPPER_SOURCE) examples/*.pl

