/*
 *	Copyright (C) 2000, 2001, 2004, 2005 Novell/SUSE
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

/* start of system offsets */
#define POS_AA_FILE_MIN			0
#define POS_AA_MAY_EXEC			POS_AA_FILE_MIN
#define POS_AA_MAY_WRITE		(POS_AA_MAY_EXEC + 1)
#define POS_AA_MAY_READ			(POS_AA_MAY_WRITE + 1)
/* not used by Subdomain */
#define POS_AA_MAY_APPEND		(POS_AA_MAY_READ + 1)
/* end of system offsets */

#define POS_AA_MAY_LINK			(POS_AA_MAY_APPEND + 1)
#define POS_AA_EXEC_INHERIT		(POS_AA_MAY_LINK + 1)
#define POS_AA_EXEC_UNCONSTRAINED	(POS_AA_EXEC_INHERIT + 1)
#define POS_AA_EXEC_PROFILE		(POS_AA_EXEC_UNCONSTRAINED + 1)
#define POS_AA_EXEC_MMAP		(POS_AA_EXEC_PROFILE + 1)
#define POS_AA_EXEC_UNSAFE		(POS_AA_EXEC_MMAP + 1)
#define POS_AA_FILE_MAX			POS_AA_EXEC_UNSAFE

#define POS_AA_NET_MIN			(POS_AA_FILE_MAX + 1)
#define POS_AA_TCP_CONNECT		POS_AA_NET_MIN
#define POS_AA_TCP_ACCEPT		(POS_AA_TCP_CONNECT + 1)
#define POS_AA_TCP_CONNECTED		(POS_AA_TCP_ACCEPT + 1)
#define POS_AA_TCP_ACCEPTED		(POS_AA_TCP_CONNECTED + 1)
#define POS_AA_UDP_SEND			(POS_AA_TCP_ACCEPTED + 1)
#define POS_AA_UDP_RECEIVE		(POS_AA_UDP_SEND + 1)
#define POS_AA_NET_MAX			POS_AA_UDP_RECEIVE

/* logging only */
#define POS_AA_LOGTCP_SEND		(POS_AA_NET_MAX + 1)
#define POS_AA_LOGTCP_RECEIVE		(POS_AA_LOGTCP_SEND + 1)

/* Absolute MAX/MIN */
#define POS_AA_MIN			(POS_AA_FILE_MIN
#define POS_AA_MAX			(POS_AA_NET_MAX

/* Invalid perm permission */
#define POS_AA_INVALID_POS		31

/* Modeled after MAY_READ, MAY_WRITE, MAY_EXEC def'ns */
#define AA_MAY_EXEC		(0x01 << POS_AA_MAY_EXEC)
#define AA_MAY_WRITE		(0x01 << POS_AA_MAY_WRITE)
#define AA_MAY_READ		(0x01 << POS_AA_MAY_READ)
#define AA_MAY_LINK		(0x01 << POS_AA_MAY_LINK)
#define AA_EXEC_INHERIT 	(0x01 << POS_AA_EXEC_INHERIT)
#define AA_EXEC_UNCONSTRAINED	(0x01 << POS_AA_EXEC_UNCONSTRAINED)
#define AA_EXEC_PROFILE		(0x01 << POS_AA_EXEC_PROFILE)
#define AA_EXEC_MMAP		(0x01 << POS_AA_EXEC_MMAP)
#define AA_EXEC_UNSAFE		(0x01 << POS_AA_EXEC_UNSAFE)
#define AA_EXEC_MODIFIERS		(AA_EXEC_INHERIT | \
					 AA_EXEC_UNCONSTRAINED | \
					 AA_EXEC_PROFILE)
#define KERN_EXEC_MODIFIERS(X)	(X & AA_EXEC_MODIFIERS)

/* Network subdomain extensions.  */
#define AA_TCP_CONNECT		(0x01 << POS_AA_TCP_CONNECT)
#define AA_TCP_ACCEPT		(0x01 << POS_AA_TCP_ACCEPT)
#define AA_TCP_CONNECTED	(0x01 << POS_AA_TCP_CONNECTED)
#define AA_TCP_ACCEPTED		(0x01 << POS_AA_TCP_ACCEPTED)
#define AA_UDP_SEND		(0x01 << POS_AA_UDP_SEND)
#define AA_UDP_RECEIVE		(0x01 << POS_AA_UDP_RECEIVE)

#define AA_LOGTCP_SEND		(0x01 << POS_AA_LOGTCP_SEND)
#define AA_LOGTCP_RECEIVE	(0x01 << POS_AA_LOGTCP_RECEIVE)
#define AA_INVALID_PERM		(0x01 << POS_AA_INVALID_POS)

#define AA_HAT_SIZE	975	/* Maximum size of a subdomain
					 * ident (hat) */

enum pattern_t {
	ePatternBasic,
	ePatternTailGlob,
	ePatternRegex,
	ePatternInvalid,
};

#define HAS_MAY_READ(mode)		((mode) & AA_MAY_READ)
#define HAS_MAY_WRITE(mode)		((mode) & AA_MAY_WRITE)
#define HAS_MAY_LINK(mode)		((mode) & AA_MAY_LINK)
#define HAS_MAY_EXEC(mode)		((mode) & AA_MAY_EXEC)
#define HAS_EXEC_INHERIT(mode)		((mode) & AA_EXEC_INHERIT)
#define HAS_EXEC_PROFILE(mode)		((mode) & AA_EXEC_PROFILE)
#define HAS_EXEC_UNCONSTRAINED(mode)	((mode) & AA_EXEC_UNCONSTRAINED)
#define HAS_EXEC_MMAP(mode) 		((mode) & AA_EXEC_MMAP)
#define HAS_EXEC_UNSAFE(mode) 		((mode) & AA_EXEC_UNSAFE)

#define AA_NOXMODS_PERM_MASK		(AA_MAY_EXEC | AA_MAY_WRITE | \
					 AA_MAY_READ | AA_MAY_LINK | \
					 AA_EXEC_MMAP)
#define AA_VALID_PERM_MASK		((1 << (POS_AA_MAX + 1)) - 1)

#define SINGLE_BIT_SET(X) (!((X) & ((X) - 1)))
#define AA_EXEC_SINGLE_MODIFIER_SET(X) SINGLE_BIT_SET(((X) & AA_EXEC_MODIFIERS))
#endif				/* ! _IMMUNIX_H */
