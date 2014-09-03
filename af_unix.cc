/*
 *   Copyright (c) 2014
 *   Canonical, Ltd. (All rights reserved)
 *
 *   This program is free software; you can redistribute it and/or
 *   modify it under the terms of version 2 of the GNU General Public
 *   License published by the Free Software Foundation.
 *
 *   This program is distributed in the hope that it will be useful,
 *   but WITHOUT ANY WARRANTY; without even the implied warranty of
 *   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *   GNU General Public License for more details.
 *
 *   You should have received a copy of the GNU General Public License
 *   along with this program; if not, contact Novell, Inc. or Canonical
 *   Ltd.
 */

#include <stdlib.h>
#include <string.h>
#include <sys/apparmor.h>

#include <iomanip>
#include <string>
#include <iostream>
#include <sstream>

#include "network.h"
#include "parser.h"
#include "profile.h"
#include "af_unix.h"

int parse_unix_mode(const char *str_mode, int *mode, int fail)
{
	return parse_X_mode("unix", AA_VALID_NET_PERMS, str_mode, mode, fail);
}


static struct supported_cond supported_conds[] = {
	{ "addr", true, false, false, either_cond },
	{ NULL, false, false, false, local_cond },	/* sentinal */
};

void unix_rule::move_conditionals(struct cond_entry *conds)
{
	struct cond_entry *ent;

	list_for_each(conds, ent) {

		if (!cond_check(supported_conds, ent, false, "unix") &&
		    !move_base_cond(ent, false)) {
			yyerror("unix rule: invalid conditional '%s'\n",
				ent->name);
			continue;
		}
		if (strcmp(ent->name, "addr") == 0) {
			move_conditional_value("unix socket", &addr, ent);
			if (addr[0] != '@' && strcmp(addr, "none") != 0)
				yyerror("unix rule: invalid value for addr='%s'\n", addr);
		}

		/* TODO: add conditionals for
		 *   listen queue length
		 *   attrs that can be read/set
		 *   ops that can be read/set
		 * allow in on
		 *   type, protocol
		 * local label match, and set
		 */
	}
}

void unix_rule::move_peer_conditionals(struct cond_entry *conds)
{
	struct cond_entry *ent;

	list_for_each(conds, ent) {
		if (!cond_check(supported_conds, ent, true, "unix") &&
		    !move_base_cond(ent, true)) {
			yyerror("unix rule: invalid peer conditional '%s'\n",
				ent->name);
			continue;
		}
		if (strcmp(ent->name, "addr") == 0) {
			move_conditional_value("unix", &peer_addr, ent);
			if (peer_addr[0] != '@' && strcmp(peer_addr, "none") != 0)
				yyerror("unix rule: invalid value for addr='%s'\n", peer_addr);
		}
	}
}

unix_rule::unix_rule(unsigned int type_p, bool audit_p, bool denied):
	af_rule("unix"), addr(NULL), peer_addr(NULL)
{
	if (type_p != 0xffffffff) {
		sock_type_n = type_p;
		sock_type = strdup(net_find_type_name(type_p));
		if (!sock_type)
			yyerror("socket rule: invalid socket type '%d'", type_p);
	}
	mode = AA_VALID_NET_PERMS;
	audit = audit_p ? AA_VALID_NET_PERMS : 0;
	deny = denied;
}

unix_rule::unix_rule(int mode_p, struct cond_entry *conds,
		     struct cond_entry *peer_conds):
	af_rule("unix"), addr(NULL), peer_addr(NULL),
	audit(0), deny(0)
{
	move_conditionals(conds);
	move_peer_conditionals(peer_conds);

	if (mode_p) {
		mode = mode_p;
		if (mode & ~AA_VALID_NET_PERMS)
			yyerror("mode contains invalid permissions for unix socket rules\n");
		else if ((mode & AA_NET_BIND) &&
			 ((mode & AA_PEER_NET_PERMS) || has_peer_conds()))
			/* Do we want to loosen this? */
			yyerror("unix socket 'bind' access cannot be used with message rule conditionals\n");
		else if ((mode & AA_NET_LISTEN) &&
			 ((mode & AA_PEER_NET_PERMS) || has_peer_conds()))
			/* Do we want to loosen this? */
			yyerror("unix socket 'listen' access cannot be used with message rule conditionals\n");
		else if ((mode & AA_NET_ACCEPT) &&
			 ((mode & AA_PEER_NET_PERMS) || has_peer_conds()))
			/* Do we want to loosen this? */
			yyerror("unix socket 'accept' access cannot be used with message rule conditionals\n");
	} else {
		mode = AA_VALID_NET_PERMS;
	}

	free_cond_list(conds);
	free_cond_list(peer_conds);

}

ostream &unix_rule::dump_local(ostream &os)
{
	af_rule::dump_local(os);
	if (addr)
		os << "addr='" << addr << "'";
	return os;
}

ostream &unix_rule::dump_peer(ostream &os)
{
	af_rule::dump_peer(os);
	if (peer_addr)
		os << "addr='" << peer_addr << "'";
	return os;
}


int unix_rule::expand_variables(void)
{
	int error = af_rule::expand_variables();
	if (error)
		return error;
	error = expand_entry_variables(&addr);
	if (error)
		return error;
	error = expand_entry_variables(&peer_addr);
	if (error)
		return error;

	return 0;
}

/* do we want to warn once/profile or just once per compile?? */
static void warn_once(const char *name, const char *msg)
{
	static const char *warned_name = NULL;

	if (warned_name != name) {
		cerr << "Warning from profile " << name << " (";
		if (current_filename)
			cerr << current_filename;
		else
			cerr << "stdin";
		cerr << "): " << msg << "\n";
		warned_name = name;
	}
}

static void warn_once(const char *name)
{
	warn_once(name, "extended network unix socket rules not enforced");
}

std::ostringstream &writeu16(std::ostringstream &o, int v)
{
	u16 tmp = htobe16((u16) v);
	u8 *byte1 = (u8 *)&tmp;
	u8 *byte2 = byte1 + 1;

	o << "\\x" << std::setfill('0') << std::setw(2) << std::hex << static_cast<unsigned int>(*byte1);
	o << "\\x" << std::setfill('0') << std::setw(2) << std::hex << static_cast<unsigned int>(*byte2);
	return o;
}

#define CMD_ADDR	1
#define CMD_LISTEN	2
#define CMD_ACCEPT	3
#define CMD_OPT		4

void unix_rule::downgrade_rule(Profile &prof) {
	if (!prof.net.allow && !prof.alloc_net_table())
		yyerror(_("Memory allocation error."));
	if (deny) {
		prof.net.deny[AF_UNIX] |= 1 << sock_type_n;
		if (!audit)
			prof.net.quiet[AF_UNIX] |= 1 << sock_type_n;
	} else {
		prof.net.allow[AF_UNIX] |= 1 << sock_type_n;
		if (audit)
			prof.net.audit[AF_UNIX] |= 1 << sock_type_n;
	}
}

static uint32_t map_perms(uint32_t mask)
{
	return (mask & 0x7f) |
		((mask & (AA_NET_GETATTR | AA_NET_SETATTR)) << (AA_OTHER_SHIFT - 8)) |
		((mask & (AA_NET_ACCEPT | AA_NET_BIND | AA_NET_LISTEN)) >> 4) | /* 2 + (AA_OTHER_SHIFT - 20) */
		((mask & (AA_NET_SETOPT | AA_NET_GETOPT)) >> 5); /* 5 + (AA_OTHER_SHIFT - 24) */
}

int unix_rule::gen_policy_re(Profile &prof)
{
	std::ostringstream buffer, tmp;
	std::string buf;

	pattern_t ptype;
	int pos;
	int mask = mode;

	/* always generate a downgraded rule. This doesn't change generated
	 * policy size and allows the binary policy to be loaded against
	 * older kernels and be enforced to the best of the old network
	 * rules ability
	 */
	downgrade_rule(prof);
	if (!kernel_supports_unix) {
		if (kernel_supports_network) {
			/* only warn if we are building against a kernel
			 * that requires downgrading */
			warn_once(prof.name, "downgrading extended network unix socket rule to generic network rule\n");
			/* TODO: add ability to abort instead of downgrade */
			return RULE_OK;
		}
		warn_once(prof.name);
		return RULE_NOT_SUPPORTED;
	}


	buffer << "\\x" << std::setfill('0') << std::setw(2) << std::hex << AA_CLASS_NET;
	buffer << writeu16(buffer, AF_UNIX);
	if (sock_type)
		buffer << writeu16(buffer, sock_type_n);
	else
		buffer << "..";
	if (proto)
		buffer << writeu16(buffer, proto_n);
	else
		buffer << "..";

	if (mask & AA_NET_CREATE) {
		buf = buffer.str();
		if (!prof.policy.rules->add_rule(buf.c_str(), deny,
						 map_perms(AA_NET_CREATE),
						 map_perms(audit & AA_NET_CREATE),
						 dfaflags))
			goto fail;
		mask &= ~AA_NET_CREATE;
	}

	/* local addr */
	if (addr) {
		if (strcmp(addr, "none") == 0) {
			buffer << "\\x01";
		} else {
			/* skip leading @ */
			ptype = convert_aaregex_to_pcre(addr + 1, 0, buf, &pos);
			if (ptype == ePatternInvalid)
				goto fail;
			/* kernel starts abstract with \0 */
			buffer << "\\x00";
			buffer << buf;
		}
	} else
		buffer << ".*";

	/* change to out of band separator */
	buffer << "\\x00";

	if (mask & AA_LOCAL_NET_PERMS) {
		/* local label option */
		if (label) {
			ptype = convert_aaregex_to_pcre(label, 0, buf, &pos);
			if (ptype == ePatternInvalid)
				goto fail;
			/* kernel starts abstract with \0 */
			buffer << buf;
		} else
			tmp << anyone_match_pattern;
		buffer << "\\x00";

		/* create already masked off */
		if (mask & AA_LOCAL_NET_PERMS & ~AA_LOCAL_NET_CMD) {
			buf = buffer.str();
			if (!prof.policy.rules->add_rule(buf.c_str(), deny,
							 map_perms(mask & AA_LOCAL_NET_PERMS & ~AA_LOCAL_NET_CMD),
							 map_perms(audit & AA_LOCAL_NET_PERMS & ~AA_LOCAL_NET_CMD),
							 dfaflags))
				goto fail;
		}

		/* cmd selector - drop accept??? */
		if (mask & AA_NET_ACCEPT) {
			tmp.str(buffer.str());
			tmp << "\\x" << std::setfill('0') << std::setw(2) << std::hex << CMD_ACCEPT;
			buf = tmp.str();
			if (!prof.policy.rules->add_rule(buf.c_str(), deny,
							 map_perms(AA_NET_ACCEPT),
							 map_perms(audit & AA_NET_ACCEPT),
							 dfaflags))
				goto fail;
		}
		if (mask & AA_NET_LISTEN) {
			tmp.str(buffer.str());
			tmp << "\\x" << std::setfill('0') << std::setw(2) << std::hex << CMD_LISTEN;
			/* TODO: backlog conditional */
			tmp << "..";
			buf = tmp.str();
			if (!prof.policy.rules->add_rule(buf.c_str(), deny,
							 map_perms(AA_NET_LISTEN),
							 map_perms(audit & AA_NET_LISTEN),
							 dfaflags))
				goto fail;
		}
		if (mask & AA_NET_OPT) {
			tmp.str(buffer.str());
			tmp << "\\x" << std::setfill('0') << std::setw(2) << std::hex << CMD_OPT;
			/* TODO: sockopt conditional */
			tmp << "..";
			buf = tmp.str();
			if (!prof.policy.rules->add_rule(buf.c_str(), deny,
							 map_perms(AA_NET_OPT),
							 map_perms(audit & AA_NET_OPT),
							 dfaflags))
				goto fail;
		}
		mask &= ~AA_LOCAL_NET_PERMS;
	}

	if (mask & AA_PEER_NET_PERMS) {
		/* cmd selector */
		buffer << "\\x" << std::setfill('0') << std::setw(2) << std::hex << CMD_ADDR;

		/* peer addr */
		if (peer_addr) {
			if (strcmp(peer_addr, "none") == 0) {
				buffer << "\\x01";
			} else {
				/* skip leading @ */
				ptype = convert_aaregex_to_pcre(peer_addr + 1, 0, buf, &pos);
				if (ptype == ePatternInvalid)
					goto fail;
				/* kernel starts abstract with \0 */
				buffer << "\\x00";
				buffer << buf;
			}
		}
		/* change to out of band separator */
		buffer << "\\x00";

		if (peer_label) {
			ptype = convert_aaregex_to_pcre(peer_label, 0, buf, &pos);
			if (ptype == ePatternInvalid)
				goto fail;
			buffer << buf;
		} else {
			buffer << anyone_match_pattern;
		}

		buf = buffer.str();
		if (!prof.policy.rules->add_rule(buf.c_str(), deny, map_perms(mode & AA_PEER_NET_PERMS), map_perms(audit), dfaflags))
			goto fail;
	}

	return RULE_OK;

fail:
	return RULE_ERROR;
}
