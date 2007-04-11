/*   $Id: apparmor.h 6203 2006-02-02 22:03:41Z steve $
 *
 *   Copyright (c) 2003, 2004, 2005, 2006, 2007 Novell, Inc.
 *   (All rights reserved)
 *
 *   The libapparmor library is licensed under the terms of the GNU
 *   Lesser General Public License, version 2.1. Please see the file
 *   COPYING.LGPL.
 */

#ifndef APPARMOR_RE_H
#define APPARMOR_RE_H

#ifdef __cplusplus
extern "C" {
#endif

struct aare_ruleset;

typedef struct aare_ruleset aare_ruleset_t;

aare_ruleset_t *aare_new_ruleset(int reverse);
void aare_delete_ruleset(aare_ruleset_t *rules);
int aare_add_rule(aare_ruleset_t *rules, char *rule, uint32_t perms);
void *aare_create_dfa(aare_ruleset_t *rules, int equiv_classes, size_t *size);

#ifdef __cplusplus
}
#endif

#endif /* APPARMOR_RE_H */
