# Last Modified: Wed Aug 15 10:56:18 2007
#include <tunables/global>
/usr/lib/cups/backend/ipp  {
  #include <abstractions/base>
  #include <abstractions/nameservice>


  /usr/lib/cups/backend/ipp mr,
  /var/run/avahi-daemon/socket w,
  /var/spool/cups/* r,
}
