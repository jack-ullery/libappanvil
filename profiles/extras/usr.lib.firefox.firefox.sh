# vim:syntax=apparmor
# Last Modified: Fri Feb 17 17:45:24 2006
# ------------------------------------------------------------------
#
#    Copyright (C) 2002-2005 Novell/SUSE
#
#    This program is free software; you can redistribute it and/or
#    modify it under the terms of version 2 of the GNU General Public
#    License published by the Free Software Foundation.
#
# ------------------------------------------------------------------

#include <tunables/global>

/usr/lib/firefox/firefox.sh {
  #include <abstractions/base>
  #include <abstractions/bash>
  #include <abstractions/consoles>
  #include <abstractions/user-tmp>

  /bin/basename ixr,
  /bin/bash ix,
  /bin/gawk ixr,
  /bin/grep ixr,
  /etc/magic r,
  /usr/bin/aoss ux,
  /usr/bin/file ixr,
  /usr/bin/which ixr,
  /usr/lib/firefox/* r,
  /usr/lib/firefox/firefox-bin px,
  /usr/lib/firefox/firefox.sh rix,
  /usr/lib/firefox/mozilla-xremote-client px,
  /usr/share/misc/magic.mgc r,
}
