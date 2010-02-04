# these are the headers for your project
noinst_HEADERS = ProfileDirectoryTraverser.h ProfileTextCtrl.h Preferences.h \
	AboutDialog.h opensuse_logo.xpm SearchAllProfiles.h Configuration.h

#########################################################################
# APPLICATION SECTION
#########################################################################
# this is the program that gets installed.  it's name is used for all
# of the other Makefile.am variables
bin_PROGRAMS = profileeditor

# the application source, library search path, and link libraries
profileeditor_SOURCES = ProfileTextCtrl.cpp Preferences.cpp AboutDialog.cpp \
	SearchAllProfiles.cpp Configuration.cpp profileeditor.cpp
profileeditor_LDFLAGS = $(WX_LIBS) 



SUBDIRS = wxStyledTextCtrl
profileeditor_LDADD =\
	$(top_builddir)/src/wxStyledTextCtrl/libAppArmorStyledTextCtrl.a

AM_CXXFLAGS = \
	-DHELP_FILE_LOCATION=\"$(datadir)/doc/@PACKAGE@/AppArmorProfileEditor.htb\"
