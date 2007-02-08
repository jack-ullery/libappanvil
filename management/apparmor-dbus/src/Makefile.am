bin_PROGRAMS = aadbus
aadbus_SOURCES = aadbus.c

# set the include path found by configure
INCLUDES= $(all_includes) `$(PKG_CONFIG) --cflags dbus-1`

# the library search path.
aadbus_LDFLAGS = $(all_libraries)  -laudit -lpcre `$(PKG_CONFIG) --libs dbus-1`

