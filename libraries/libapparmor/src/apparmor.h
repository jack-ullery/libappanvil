/*   $Id$

     Copyright (c) 2003-2007 Novell, Inc. (All rights reserved)

     The libapparmor library is licensed under the terms of the GNU
     Lesser General Public License, version 2.1. Please see the file
     COPYING.LGPL.
*/

#ifndef _SYS_APPARMOR_H_
#define _SYS_APPARMOR_H	1

__BEGIN_DECLS

/* Prototype for change_hat as defined by the AppArmor project
   <http://forge.novell.com/modules/xfmod/project/?apparmor>
   Please see the change_hat(2) manpage for information. */

extern int (change_hat)(const char *subprofile, unsigned int magic_token);
extern int aa_change_hat(const char *subprofile, unsigned long magic_token);
extern int aa_change_profile(const char *profile);
extern int aa_change_onexec(const char *profile);

#define change_hat(X, Y) aa_change_hat((X), (Y))

__END_DECLS

#endif	/* sys/apparmor.h */
