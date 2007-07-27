/*
 *	Copyright (c) 1999, 2000, 2001, 2002, 2004, 2005, 2006, 2007
 *	NOVELL (All rights reserved)
 *
 *	Immunix AppArmor LSM
 *
 *	This program is free software; you can redistribute it and/or
 *	modify it under the terms of the GNU General Public License as
 *	published by the Free Software Foundation, version 2 of the
 *	License.
 *
 *	This program is distributed in the hope that it will be useful,
 *	but WITHOUT ANY WARRANTY; without even the implied warranty of
 *	MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *	GNU General Public License for more details.
 *
 *	You should have received a copy of the GNU General Public License
 *	along with this program; if not, contact Novell, Inc.
 */

#ifndef _IMMUNIX_H
#define _IMMUNIX_H

/*
 * Modeled after MAY_READ, MAY_WRITE, MAY_EXEC in the kernel. The value of
 * AA_MAY_EXEC must be identical to MAY_EXEC, etc.
 */
#define AA_MAY_EXEC			(1 << 0)
#define AA_MAY_WRITE			(1 << 1)
#define AA_MAY_READ			(1 << 2)
#define AA_MAY_APPEND			(1 << 3)
#define AA_MAY_LINK			(1 << 4)
#define AA_EXEC_INHERIT 		(1 << 5)
#define AA_EXEC_UNCONSTRAINED		(1 << 6)
#define AA_EXEC_PROFILE			(1 << 7)
#define AA_EXEC_MMAP			(1 << 8)
#define AA_EXEC_UNSAFE			(1 << 9)
#define AA_EXEC_MODIFIERS		(AA_EXEC_INHERIT | \
					 AA_EXEC_UNCONSTRAINED | \
					 AA_EXEC_PROFILE)

#define AA_CHANGE_PROFILE		(1 << 31)

/* Network subdomain extensions.  */
#define AA_TCP_CONNECT			(1 << 16)
#define AA_TCP_ACCEPT			(1 << 17)
#define AA_TCP_CONNECTED		(1 << 18)
#define AA_TCP_ACCEPTED			(1 << 19)
#define AA_UDP_SEND			(1 << 20)
#define AA_UDP_RECEIVE			(1 << 21)

/* logging only */
#define AA_LOGTCP_SEND			(1 << 22)
#define AA_LOGTCP_RECEIVE		(1 << 23)

#define AA_HAT_SIZE	975	/* Maximum size of a subdomain
					 * ident (hat) */
#define AA_IP_TCP			0x0001
#define AA_IP_UDP			0x0002
#define AA_IP_RDP			0x0004
#define AA_IP_RAW			0x0008
#define AA_IPV6_TCP			0x0010
#define AA_IPV6_UDP			0x0020
#define AA_NETLINK			0x0040

enum pattern_t {
	ePatternBasic,
	ePatternTailGlob,
	ePatternRegex,
	ePatternInvalid,
};

#define HAS_MAY_READ(mode)		((mode) & AA_MAY_READ)
#define HAS_MAY_WRITE(mode)		((mode) & AA_MAY_WRITE)
#define HAS_MAY_APPEND(mode)		((mode) & AA_MAY_APPEND)
#define HAS_MAY_LINK(mode)		((mode) & AA_MAY_LINK)
#define HAS_MAY_EXEC(mode)		((mode) & AA_MAY_EXEC)
#define HAS_EXEC_INHERIT(mode)		((mode) & AA_EXEC_INHERIT)
#define HAS_EXEC_PROFILE(mode)		((mode) & AA_EXEC_PROFILE)
#define HAS_EXEC_UNCONSTRAINED(mode)	((mode) & AA_EXEC_UNCONSTRAINED)
#define HAS_EXEC_MMAP(mode) 		((mode) & AA_EXEC_MMAP)
#define HAS_EXEC_UNSAFE(mode) 		((mode) & AA_EXEC_UNSAFE)
#define HAS_CHANGE_PROFILE(mode)	((mode) & AA_CHANGE_PROFILE)

#define SINGLE_BIT_SET(X) (!((X) & ((X) - 1)))
#define AA_EXEC_SINGLE_MODIFIER_SET(X) SINGLE_BIT_SET(((X) & AA_EXEC_MODIFIERS))
#endif				/* ! _IMMUNIX_H */
