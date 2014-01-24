#	Copyright (C) 2002-2005 Novell/SUSE
#	Copyright (C) 2013 Canonical, Ltd
#
#	This program is free software; you can redistribute it and/or
#	modify it under the terms of the GNU General Public License as
#	published by the Free Software Foundation, version 2 of the
#	License.

ifdef USE_SYSTEM
  # use the system libapparmor headers and library
  LIBAPPARMOR = $(shell if pkg-config --exists libapparmor ; then \
				pkg-config --silence-errors --libs libapparmor ; \
			elif ldconfig -p | grep -q libapparmor\.so$$ ; then \
				echo -lapparmor ; \
			fi )
  ifeq ($(strip $(LIBAPPARMOR)),)
    ERROR_MESSAGE = Unable to find libapparmor installed on this system; either \
	    install libapparmor devel packages, set the LIBAPPARMOR variable \
	    manually, or build against in-tree libapparmor)
  endif # LIBAPPARMOR not set
  LDLIBS += $(LIBAPPARMOR)

else # !USE_SYSTEM
  # use in-tree versions
  LIBAPPARMOR_SRC := ../../../libraries/libapparmor/
  LIBAPPARMOR_INCLUDE = $(LIBAPPARMOR_SRC)/include
  LIBAPPARMOR_PATH := $(LIBAPPARMOR_SRC)/src/.libs/
  ifeq ($(realpath $(LIBAPPARMOR_PATH)/libapparmor.a),)
    ERROR_MESSAGE = $(LIBAPPARMOR_PATH)/libapparmor.a is missing; either build against \
	    the in-tree libapparmor by building it first and then trying again \
	    (see the top-level README for help) or build against the system \
	    libapparmor by adding USE_SYSTEM=1 to your make command.)
  endif

  CFLAGS += -L$(LIBAPPARMOR_PATH) -I$(LIBAPPARMOR_INCLUDE)
  LDLIBS += -Wl,-Bstatic -lapparmor -Wl,-Bdynamic -lpthread
endif # USE_SYSTEM

CFLAGS += -Wall -Wstrict-prototypes

SRC=access.c \
    introspect.c \
    changeprofile.c \
    onexec.c \
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
    clone.c \
    coredump.c \
    dbus_eavesdrop.c \
    dbus_message.c \
    dbus_service.c \
    deleted.c \
    environ.c \
    env_check.c \
    exec.c \
    exec_qual.c \
    exec_qual2.c \
    fchdir.c \
    fchgrp.c \
    fchmod.c \
    fchown.c \
    fd_inheritance.c \
    fd_inheritor.c \
    fork.c \
    link.c \
    link_subset.c \
    mmap.c \
    mkdir.c \
    mount.c \
    named_pipe.c \
    net_raw.c \
    open.c \
    openat.c \
    pipe.c \
    ptrace.c \
    ptrace_helper.c \
    pwrite.c \
    query_label.c \
    rename.c \
    readdir.c \
    rw.c \
    symlink.c \
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
    sysctl_proc.c \
    tcp.c \
    unix_fd_client.c \
    unix_fd_server.c \
    unix_socket_file.c \
    unix_socket_file_client.c \
    unlink.c \
    xattrs.c

#only do the ioperm/iopl tests for x86 derived architectures
ifneq (,$(findstring $(shell uname -i),i386 i486 i586 i686 x86 x86_64))
SRC+=syscall_ioperm.c syscall_iopl.c
endif

EXEC=$(SRC:%.c=%)

TESTS=access \
      introspect \
      capabilities \
      changeprofile \
      onexec \
      changehat \
      changehat_fork \
      changehat_misc \
      chdir \
      clone \
      coredump \
      dbus_eavesdrop \
      dbus_message \
      dbus_service \
      deleted \
      environ \
      exec \
      exec_qual \
      fchdir \
      fd_inheritance \
      fork \
      i18n \
      link \
      link_subset \
      mkdir \
      mmap \
      mount \
      mult_mount \
      named_pipe \
      net_raw \
      open \
      openat \
      pipe \
      ptrace \
      pwrite \
      query_label \
      regex \
      rename \
      readdir \
      rw \
      swap \
      sd_flags \
      setattr \
      symlink \
      syscall \
      tcp \
      unix_fd_server \
      unix_socket_file \
      unlink\
      xattrs\
      longpath

# Tests that can crash the kernel should be placed here
RISKY_TESTS=

.PHONY: libapparmor_check
.SILENT: libapparmor_check
libapparmor_check:
	@if [ -n "$(ERROR_MESSAGE)" ] ; then \
		echo "$(ERROR_MESSAGE)" 1>&2 ; \
		return 1 ; \
	fi

all: libapparmor_check $(EXEC) changehat.h

changehat_pthread: changehat_pthread.c changehat.h
	${CC} ${CFLAGS} ${LDFLAGS} $< -o $@ ${LDLIBS} -pthread

dbus_common.o: dbus_common.c dbus_common.h
	${CC} ${CFLAGS} ${LDFLAGS} $< -c ${LDLIBS} $(shell pkg-config --cflags --libs dbus-1)

dbus_eavesdrop: dbus_eavesdrop.c dbus_common.o
	${CC} ${CFLAGS} ${LDFLAGS} $^ -o $@ ${LDLIBS} $(shell pkg-config --cflags --libs dbus-1)

dbus_message: dbus_message.c dbus_common.o
	${CC} ${CFLAGS} ${LDFLAGS} $^ -o $@ ${LDLIBS} $(shell pkg-config --cflags --libs dbus-1)

dbus_service: dbus_message dbus_service.c dbus_common.o
	${CC} ${CFLAGS} ${LDFLAGS} $(filter-out dbus_message, $^) -o $@ ${LDLIBS} $(shell pkg-config --cflags --libs dbus-1)

tests: all
	@if [ `whoami` = "root" ] ;\
	then \
		rc=0; \
		for i in $(TESTS) ;\
		do \
			echo ;\
			echo "running $$i" ;\
			bash $$i.sh ;\
			if [ $$? -ne 0 ] ; then \
				rc=1;\
			fi;\
		done ;\
		exit $$rc;\
	else \
		echo "must be root to run tests" ;\
		exit 1;\
	fi

alltests: all
	@if [ `whoami` = "root" ] ;\
	then \
		rc=0; \
		for i in $(TESTS) $(RISKY_TESTS) ;\
		do \
			echo ;\
			echo "running $$i" ;\
			bash $$i.sh ;\
			if [ $$? -ne 0 ] ; then \
				rc=1;\
			fi;\
		done ;\
		exit $$rc;\
	else \
		echo "must be root to run tests" ;\
		exit 1;\
	fi

clean:
	rm -f $(EXEC) dbus_common.o

regex.sh: open exec
