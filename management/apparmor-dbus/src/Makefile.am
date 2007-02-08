bin_PROGRAMS = aadbus
aadbus_SOURCES = aadbus.c

# set the include path found by configure
INCLUDES= $(all_includes) -I$(includedir)/dbus-1.0 -I$(libdir)/dbus-1.0/include -I/usr/include/dbus-1.0 -I/usr/lib/dbus-1.0/include

# the library search path.
aadbus_LDFLAGS = $(all_libraries) -laudit -lpcre -ldbus-1

