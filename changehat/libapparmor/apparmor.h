/*   $Id: apparmor.h 6203 2006-02-02 22:03:41Z steve $

     Copyright (c) 2003, 2004, 2005, 2006 Novell, Inc. (All rights reserved)

     The libapparmor library is licensed under the terms of the GNU
     Lesser General Public License, version 2.1. Please see the file
     COPYING.LGPL.
*/

#ifndef _SYS_APPARMOR_H_
#define _SYS_APPARMOR_H	1

__BEGIN_DECLS

/* Prototype for change_hat as defined by the AppArmor project
 * <http://forge.novell.com/modules/xfmod/project/?apparmor> */
extern int change_hat(const char *subprofile, unsigned int magic_token);

__END_DECLS

#endif	/* sys/apparmor.h */
