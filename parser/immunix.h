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
#define POS_KERN_COD_FILE_MIN		0
#define POS_KERN_COD_MAY_EXEC		POS_KERN_COD_FILE_MIN
#define POS_KERN_COD_MAY_WRITE		(POS_KERN_COD_MAY_EXEC + 1)
#define POS_KERN_COD_MAY_READ		(POS_KERN_COD_MAY_WRITE + 1)
/* not used by Subdomain */
#define POS_KERN_COD_MAY_APPEND		(POS_KERN_COD_MAY_READ + 1)
/* end of system offsets */

#define POS_KERN_COD_MAY_LINK		(POS_KERN_COD_MAY_APPEND + 1)
#define POS_KERN_COD_EXEC_INHERIT	(POS_KERN_COD_MAY_LINK + 1)
#define POS_KERN_COD_EXEC_UNCONSTRAINED (POS_KERN_COD_EXEC_INHERIT + 1)
#define POS_KERN_COD_EXEC_PROFILE	(POS_KERN_COD_EXEC_UNCONSTRAINED + 1)
#define POS_KERN_COD_FILE_MAX		POS_KERN_COD_EXEC_PROFILE

#define POS_KERN_COD_NET_MIN		(POS_KERN_COD_FILE_MAX + 1)
#define POS_KERN_COD_TCP_CONNECT	POS_KERN_COD_NET_MIN
#define POS_KERN_COD_TCP_ACCEPT		(POS_KERN_COD_TCP_CONNECT + 1)
#define POS_KERN_COD_TCP_CONNECTED	(POS_KERN_COD_TCP_ACCEPT + 1)
#define POS_KERN_COD_TCP_ACCEPTED	(POS_KERN_COD_TCP_CONNECTED + 1)
#define POS_KERN_COD_UDP_SEND		(POS_KERN_COD_TCP_ACCEPTED + 1)
#define POS_KERN_COD_UDP_RECEIVE	(POS_KERN_COD_UDP_SEND + 1)
#define POS_KERN_COD_NET_MAX		POS_KERN_COD_UDP_RECEIVE

/* logging only */
#define POS_KERN_COD_LOGTCP_SEND	(POS_KERN_COD_NET_MAX + 1)
#define POS_KERN_COD_LOGTCP_RECEIVE	(POS_KERN_COD_LOGTCP_SEND + 1)

/* Absolute MAX/MIN */
#define POS_KERN_COD_MIN		(POS_KERN_COD_FILE_MIN
#define POS_KERN_COD_MAX		(POS_KERN_COD_NET_MAX

/* Modeled after MAY_READ, MAY_WRITE, MAY_EXEC def'ns */
#define KERN_COD_MAY_EXEC    	(0x01 << POS_KERN_COD_MAY_EXEC)
#define KERN_COD_MAY_WRITE   	(0x01 << POS_KERN_COD_MAY_WRITE)
#define KERN_COD_MAY_READ    	(0x01 << POS_KERN_COD_MAY_READ)
#define KERN_COD_MAY_LINK	(0x01 << POS_KERN_COD_MAY_LINK)
#define KERN_COD_EXEC_INHERIT 	(0x01 << POS_KERN_COD_EXEC_INHERIT)
#define KERN_COD_EXEC_UNCONSTRAINED	(0x01 << POS_KERN_COD_EXEC_UNCONSTRAINED)
#define KERN_COD_EXEC_PROFILE	(0x01 << POS_KERN_COD_EXEC_PROFILE)
#define KERN_EXEC_MODIFIERS(X)	(X & (KERN_COD_EXEC_INHERIT | \
				      KERN_COD_EXEC_UNCONSTRAINED | \
				      KERN_COD_EXEC_PROFILE))
/* Network subdomain extensions.  */
#define KERN_COD_TCP_CONNECT    (0x01 << POS_KERN_COD_TCP_CONNECT)
#define KERN_COD_TCP_ACCEPT     (0x01 << POS_KERN_COD_TCP_ACCEPT)
#define KERN_COD_TCP_CONNECTED  (0x01 << POS_KERN_COD_TCP_CONNECTED)
#define KERN_COD_TCP_ACCEPTED   (0x01 << POS_KERN_COD_TCP_ACCEPTED)
#define KERN_COD_UDP_SEND       (0x01 << POS_KERN_COD_UDP_SEND)
#define KERN_COD_UDP_RECEIVE    (0x01 << POS_KERN_COD_UDP_RECEIVE)

#define KERN_COD_LOGTCP_SEND    (0x01 << POS_KERN_COD_LOGTCP_SEND)
#define KERN_COD_LOGTCP_RECEIVE (0x01 << POS_KERN_COD_LOGTCP_RECEIVE)

#define KERN_COD_HAT_SIZE	975	/* Maximum size of a subdomain
					 * ident (hat) */

enum pattern_t {
	ePatternBasic,
	ePatternTailGlob,
	ePatternRegex,
	ePatternInvalid,
};

#endif				/* ! _IMMUNIX_H */
