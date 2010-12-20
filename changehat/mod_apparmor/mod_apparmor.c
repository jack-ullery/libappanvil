/*
 *   Copyright (c) 2004, 2005, 2006 NOVELL (All rights reserved)
 *
 *    The mod_apparmor module is licensed under the terms of the GNU
 *    Lesser General Public License, version 2.1. Please see the file
 *    COPYING.LGPL.
 *
 * mod_apparmor - (apache 2.0.x)
 * Author: Steve Beattie <sbeattie@suse.de>
 *
 * This currently only implements change_hat functionality, but could be
 * extended for other stuff we decide to do.
 */

#include "ap_config.h"
#include "httpd.h"
#include "http_config.h"
#include "http_request.h"
#include "http_log.h"
#include "http_protocol.h"
#include "util_filter.h"
#include "apr.h"
#include "apr_strings.h"
#include "apr_lib.h"

#ifndef USE_COMPAT_IMMUNIX_H
#include <sys/apparmor.h>
#else
#include <sys/immunix.h>
#endif
#include <unistd.h>

/* #define DEBUG */
#ifndef __unused
#define __unused __attribute__((unused))
#endif

/* should the following be configurable? */
#define DEFAULT_HAT "HANDLING_UNTRUSTED_INPUT"
#define DEFAULT_URI_HAT "DEFAULT_URI"

module AP_MODULE_DECLARE_DATA apparmor_module;

static unsigned int magic_token = 0;
static int inside_default_hat = 0;

typedef struct {
	const char * hat_name;
	char * path;
} immunix_dir_cfg;

typedef struct {
	const char * hat_name;
	int is_initialized;
} immunix_srv_cfg;

/* immunix_init() gets invoked in the post_config stage of apache.
 * Unfortunately, apache reads its config once when it starts up, then
 * it re-reads it when goes into its restart loop, where it starts it's
 * children. This means we cannot call change_hat here, as the modules
 * memory will be wiped out, and the magic_token will be lost, so apache
 * wouldn't be able to change_hat back out. */
static int 
immunix_init (apr_pool_t *p, apr_pool_t *plog, apr_pool_t *ptemp, server_rec *s)
{
    apr_file_t * file;
    apr_size_t size = sizeof (magic_token);
    int ret;

    ret = apr_file_open (&file, "/dev/urandom", APR_READ, APR_OS_DEFAULT, p);
    if (!ret) {
    	apr_file_read (file, (void *) &magic_token, &size);
	apr_file_close (file);
    } else {
        ap_log_error (APLOG_MARK, APLOG_ERR, 0, NULL, "Failed to open /dev/urandom");
    }
    ap_log_error (APLOG_MARK, APLOG_DEBUG, 0, NULL, "Opened /dev/urandom successfully");

    return OK;
}
    
/* As each child starts up, we'll change_hat into a default hat, mostly
 * to protect ourselves from bugs in parsing network input, but before
 * we change_hat to the uri specific hat. */
static void 
immunix_child_init (apr_pool_t *p, server_rec *s)
{
    int ret;

    ap_log_error (APLOG_MARK, APLOG_DEBUG, 0, NULL, "init: calling change_hat");
    ret = change_hat (DEFAULT_HAT, magic_token);
    if (ret < 0) {
    	change_hat (NULL, magic_token);
        ap_log_error (APLOG_MARK, APLOG_ERR, 0, NULL, "Failed to change_hat to '%s'",
			DEFAULT_HAT);
    } else {
        inside_default_hat = 1;
    }
}    			 

#ifdef DEBUG
static void
debug_dump_uri (apr_uri_t * uri) 
{
    if (uri) 
    	ap_log_error (APLOG_MARK, APLOG_ERR, 0, NULL, "Dumping uri info "
    	          "scheme='%s' host='%s' path='%s' query='%s' fragment='%s'",
    		  uri->scheme, uri->hostname, uri->path, uri->query,
		  uri->fragment);
    else
    	ap_log_error (APLOG_MARK, APLOG_ERR, 0, NULL, "Asked to dump NULL uri");

}
#else
static void
debug_dump_uri (apr_uri_t * __unused uri) { }
#endif
    
/* 
   immunix_enter_hat will attempt to change_hat in the following order:
   (1) to a hatname in a location directive
   (2) to the uri
   (3) to a per-server default 
   (4) to DEFAULT_URI
   (5) back to the parent profile
*/
static int 
immunix_enter_hat (request_rec *r)
{
    int sd_ret = -1;
    immunix_dir_cfg * dcfg = (immunix_dir_cfg *) 
    		ap_get_module_config (r->per_dir_config, &apparmor_module);
    immunix_srv_cfg * scfg = (immunix_srv_cfg *) 
    		ap_get_module_config (r->server->module_config, &apparmor_module);

    debug_dump_uri (&r->parsed_uri);
    ap_log_error (APLOG_MARK, APLOG_DEBUG, 0, NULL, "in immunix_enter_hat (%s) n:0x%lx p:0x%lx main:0x%lx", 
    	dcfg->path, (unsigned long) r->next, (unsigned long) r->prev, 
	(unsigned long) r->main);

    /* We only call change_hat for the main request, not subrequests */
    if (r->main) 
    	return OK;

    if (inside_default_hat) {
        change_hat (NULL, magic_token);
	inside_default_hat = 0;
    }

    if (dcfg != NULL && dcfg->hat_name != NULL) {
        ap_log_error (APLOG_MARK, APLOG_DEBUG, 0, NULL, "calling change_hat [dcfg] %s", dcfg->hat_name);
        sd_ret = change_hat (dcfg->hat_name, magic_token);
	if (sd_ret < 0) {
	    change_hat (NULL, magic_token);
	} else {
	    return OK;
	}
    }

    ap_log_error (APLOG_MARK, APLOG_DEBUG, 0, NULL, "calling change_hat [uri] %s", r->uri);
    sd_ret = change_hat (r->uri, magic_token);
    if (sd_ret < 0) {
    	change_hat (NULL, magic_token);
    } else {
	    return OK;
    }

    if (scfg != NULL && scfg->hat_name != NULL) {
        ap_log_error (APLOG_MARK, APLOG_DEBUG, 0, NULL, "calling change_hat [scfg] %s", scfg->hat_name);
        sd_ret = change_hat (scfg->hat_name, magic_token);
	if (sd_ret < 0) {
	    change_hat (NULL, magic_token);
	} else {
	    return OK;
	}
    }

    ap_log_error (APLOG_MARK, APLOG_DEBUG, 0, NULL, "calling change_hat DEFAULT_URI");
    sd_ret = change_hat (DEFAULT_URI_HAT, magic_token);
    if (sd_ret < 0) change_hat (NULL, magic_token);

    return OK;
}

static int 
immunix_exit_hat (request_rec *r)
{
    int sd_ret;
    immunix_dir_cfg * dcfg = (immunix_dir_cfg *) 
    		ap_get_module_config (r->per_dir_config, &apparmor_module);
    /* immunix_srv_cfg * scfg = (immunix_srv_cfg *)
    		ap_get_module_config (r->server->module_config, &apparmor_module); */
    ap_log_error (APLOG_MARK, APLOG_DEBUG, 0, NULL, "exiting change_hat - dir hat %s path %s", dcfg->hat_name, dcfg->path);
    change_hat (NULL, magic_token);

    sd_ret = change_hat (DEFAULT_HAT, magic_token);
    if (sd_ret < 0) {
    	change_hat (NULL, magic_token);
        ap_log_error (APLOG_MARK, APLOG_ERR, 0, NULL, "Failed to change_hat to '%s'",
			DEFAULT_HAT);
    } else {
        inside_default_hat = 1;
    }

    return OK;
}

static const char *
aa_cmd_ch_path (cmd_parms * cmd, void * mconfig, const char * parm1)
{
    ap_log_error(APLOG_MARK, APLOG_DEBUG, 0, NULL, "config change hat %s",
    			parm1 ? parm1 : "DEFAULT");
    immunix_dir_cfg * dcfg = mconfig;
    if (parm1 != NULL) {
    	dcfg->hat_name = parm1;
    } else {
    	dcfg->hat_name = "DEFAULT";
    }
    return NULL;
}

static int path_warn_once;

static const char *
immunix_cmd_ch_path (cmd_parms * cmd, void * mconfig, const char * parm1)
{
    if (path_warn_once == 0) {
    	ap_log_error(APLOG_MARK, APLOG_NOTICE, 0, NULL, "ImmHatName is "
		     "deprecated, please use AAHatName instead");
	path_warn_once = 1;
    }
    return aa_cmd_ch_path(cmd, mconfig, parm1);
}

static const char *
aa_cmd_ch_srv (cmd_parms * cmd, void * mconfig, const char * parm1)
{
    ap_log_error(APLOG_MARK, APLOG_DEBUG, 0, NULL, "config change hat %s",
    			parm1 ? parm1 : "DEFAULT");
    immunix_srv_cfg * scfg = mconfig;
    if (parm1 != NULL) {
    	scfg->hat_name = parm1;
    } else {
    	scfg->hat_name = "DEFAULT";
    }
    return NULL;
}

static int srv_warn_once;

static const char *
immunix_cmd_ch_srv (cmd_parms * cmd, void * mconfig, const char * parm1)
{
    if (srv_warn_once == 0) {
	ap_log_error(APLOG_MARK, APLOG_NOTICE, 0, NULL, "ImmDefaultHatName is "
		     "deprecated, please use AADefaultHatName instead");
	srv_warn_once = 1;
    }
    return aa_cmd_ch_srv(cmd, mconfig, parm1);
}

static void *
immunix_create_dir_config (apr_pool_t * p, char * path)
{
    immunix_dir_cfg * newcfg = (immunix_dir_cfg *) apr_pcalloc(p, sizeof(* newcfg));

    ap_log_error (APLOG_MARK, APLOG_DEBUG, 0, NULL, "in immunix_create_dir (%s)", path ? path : ":no path:");
    if (newcfg == NULL) {
        ap_log_error (APLOG_MARK, APLOG_ERR, 0, NULL, "immunix_create_dir: couldn't alloc dir config");
    	return NULL;
    }
    newcfg->path = apr_pstrdup (p, path ? path : ":no path:");

    return newcfg;
}

/* XXX: Should figure out an appropriate action to take here, if any

static void *
immunix_merge_dir_config (apr_pool_t * p, void * parent, void * child)
{
    immunix_dir_cfg * newcfg = (immunix_dir_cfg *) apr_pcalloc(p, sizeof(* newcfg));

    ap_log_error (APLOG_MARK, APLOG_DEBUG, 0, NULL, "in immunix_merge_dir ()");
    if (newcfg == NULL)
    	return NULL;

    return newcfg;
}
*/

static void *
immunix_create_srv_config (apr_pool_t * p, server_rec * srv)
{
    immunix_srv_cfg * newcfg = (immunix_srv_cfg *) apr_pcalloc(p, sizeof(* newcfg));

    ap_log_error (APLOG_MARK, APLOG_DEBUG, 0, NULL, "in immunix_create_srv");
    if (newcfg == NULL) {
        ap_log_error (APLOG_MARK, APLOG_ERR, 0, NULL, "immunix_create_srv: couldn't alloc srv config");
    	return NULL;
    }

    return newcfg;
}


static const command_rec immunix_cmds[] = {

    AP_INIT_TAKE1 (
        "ImmHatName",
	immunix_cmd_ch_path,
	NULL,
	ACCESS_CONF,
	""
    ),
    AP_INIT_TAKE1 (
        "ImmDefaultHatName",
	immunix_cmd_ch_srv,
	NULL,
	RSRC_CONF,
	""
    ),
    AP_INIT_TAKE1 (
        "AAHatName",
	aa_cmd_ch_path,
	NULL,
	ACCESS_CONF,
	""
    ),
    AP_INIT_TAKE1 (
        "AADefaultHatName",
	aa_cmd_ch_srv,
	NULL,
	RSRC_CONF,
	""
    ),
    { NULL }
};

static void 
register_hooks (apr_pool_t *p)
{
    ap_hook_post_config (immunix_init, NULL, NULL, APR_HOOK_MIDDLE);
    ap_hook_child_init (immunix_child_init, NULL, NULL, APR_HOOK_MIDDLE);
    ap_hook_access_checker(immunix_enter_hat, NULL, NULL, APR_HOOK_FIRST);
    /* ap_hook_post_read_request(immunix_enter_hat, NULL, NULL, APR_HOOK_FIRST); */
    ap_hook_log_transaction(immunix_exit_hat, NULL, NULL, APR_HOOK_LAST);
}

module AP_MODULE_DECLARE_DATA apparmor_module = {
    STANDARD20_MODULE_STUFF,
    immunix_create_dir_config,	/* dir config creater */
    NULL,			/* dir merger --- default is to override */
    /* immunix_merge_dir_config, */	/* dir merger --- default is to override */
    immunix_create_srv_config,	/* server config */
    NULL,			/* merge server config */
    immunix_cmds,		/* command table */
    register_hooks		/* register hooks */
};
