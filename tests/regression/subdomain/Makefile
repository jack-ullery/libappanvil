# $Id: Makefile 6285 2006-02-24 22:24:47Z steve $
#
#	Copyright (C) 2002-2005 Novell/SUSE
#
#	This program is free software; you can redistribute it and/or
#	modify it under the terms of the GNU General Public License as
#	published by the Free Software Foundation, version 2 of the
#	License.

SRC=access.c \
    changehat.c \
    changehat_fork.c \
    changehat_misc.c \
    changehat_misc2.c \
    changehat_twice.c \
    changehat_fail.c \
    changehat_wrapper.c \
    changehat_pthread.c \
    chdir.c \
    chgrp.c \
    chmod.c \
    chown.c \
    deleted.c \
    exec.c \
    exec_qual.c \
    exec_qual2.c \
    fork.c \
    link.c \
    mmap.c \
    mkdir.c \
    mount.c \
    named_pipe.c \
    net_raw.c \
    open.c \
    pipe.c \
    ptrace.c \
    ptrace_helper.c \
    pwrite.c \
    rename.c \
    readdir.c \
    rw.c \
    syscall_mknod.c \
    swap.c \
    syscall_chroot.c \
    syscall_mlockall.c \
    syscall_ptrace.c \
    syscall_reboot.c \
    syscall_setpriority.c \
    syscall_sethostname.c \
    syscall_setdomainname.c \
    syscall_setscheduler.c \
    syscall_sysctl.c \
    tcp.c \
    unix_fd_client.c \
    unix_fd_server.c \
    unlink.c \
    xattrs.c

#only do the ioperm/iopl tests for x86 derived architectures
ifneq (,$(findstring $(shell uname -i),i386 i486 i586 i686 x86 x86_64))
SRC+=syscall_ioperm.c syscall_iopl.c
endif

# Suck, Fedora Core 3 no longer includes /sbin/kernelversion
KERNELVERSION:=$(shell if [ -x /sbin/kernelversion ] ; then \
				/sbin/kernelversion ; \
		       else \
		       		uname -r ; \
		       fi )
KERNELMAJOR:=$(shell echo ${KERNELVERSION} | cut -d. -f1)
KERNELMINOR:=$(shell echo ${KERNELVERSION} | cut -d. -f2)
CHANGEHAT_FLAGS=$(shell if [ ! -f /usr/include/sys/apparmor.h ] ; then \
        			if [ -f /usr/include/sys/immunix.h ] ; then \
					echo -DUSE_COMPAT_IMMUNIX_H ; \
				else \
					(echo -DCHANGEHAT_NOT_IN_LIBRARY; \
					[ $(KERNELMAJOR) -eq 2 ] && \
	  				if [ $(KERNELMINOR) -eq 4 ] ; then \
						echo -DCHANGEHAT_2_4_KERNEL ; \
	  				elif [ $(KERNELMINOR) -eq 2 ] ; then \
						echo -DCHANGEHAT_2_2_KERNEL ;\
	       				fi ) \
	  			fi ;\
			fi )

LIBIMMUNIX:=$(shell	if [ -f /usr/lib/libapparmor.so -o -f /usr/lib64/libapparmor.so ] ; then \
				echo -lapparmor ; \
			elif [ -f /lib/libimmunix.so.1 -o -f /lib64/libimmunix.so ] ; then \
				echo -limmunix ; \
			fi )

CFLAGS+=$(CHANGEHAT_FLAGS) $(LIBIMMUNIX) -Wall -Wstrict-prototypes

EXEC=$(SRC:%.c=%)

TESTS=access \
      capabilities \
      changehat \
      changehat_fork \
      changehat_misc \
      chdir \
      deleted \
      exec \
      exec_qual \
      fork \
      i18n \
      link \
      mkdir \
      mmap \
      mount \
      mult_mount \
      named_pipe \
      net_raw \
      open pipe \
      ptrace \
      pwrite \
      regex \
      rename \
      readdir \
      rw \
      swap \
      sd_flags \
      setattr \
      syscall \
      unix_fd_server \
      unlink\
      xattrs

all: $(EXEC) changehat.h
	# This is sadly needed for buildbot, which has a restrictive umask.
	chmod 755 . ${EXEC}

changehat_pthread: changehat_pthread.c changehat.h
	${CC} ${CFLAGS} -lpthread -o $@ $<

ptrace_helper: ptrace_helper.c
	$(CC) -o $@ $<

tests: all
	@if [ `whoami` == "root" ] ;\
	then \
		for i in $(TESTS) ;\
		do \
			echo ;\
			echo "running $$i" ;\
			sh $$i.sh ;\
		done ;\
	else \
		echo "must be root to run tests" ;\
	fi

clean:
	rm -f $(EXEC)

regex.sh: open exec

cvsignore:
	echo -n "" > .cvsignore ; \
		for i in $(EXEC) ; do echo $$i >> .cvsignore ; done
