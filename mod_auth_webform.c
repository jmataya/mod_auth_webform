/*
 * Copyright 2011 Jeffrey Mataya
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#include <httpd.h>
#include <http_config.h>
#include <http_log.h>
#include <http_protocol.h>

//
// Get a value from the Apache configuration.
// Inputs:
//  (*) r - The current request data structure.
//  (*) key - Key identifying the value to find.
// Returns:
//  (*) Either the value as a character string. Returns NULL if not found.
//
static char * get_conf_value(request_rec * r, char * key) {
    char * value = NULL;

    if (r != NULL && r->subprocess_env != NULL && key != NULL) {
        value = apr_table_get(r->subprocess_env, key);
    }

    return value;
}

static int mod_auth_webform_handler(request_rec *r) {
    // Ensure that this handler is being requested.
    if (!r->handler || strcmp(r->handler, "mod_auth_webform")) {
        return DECLINED;
    }
    else if (r->method_number != M_GET) {
        return HTTP_METHOD_NOT_ALLOWED;
    }

    // Ensure that filename and finfo have been set.
    if (r->filename == NULL) {
        ap_log_rerror(
            APLOG_MARK,
            APLOG_ERR,
            0,
            r,
            "mod_auth_webform: Incomplete request_rec!");
        return HTTP_INTERNAL_SERVER_ERROR;
    }


    return OK;
}

static void mod_auth_webform_hooks(apr_pool_t * pool) {
    ap_hook_handler(mod_auth_webform_handler, NULL, NULL, APR_HOOK_MIDDLE);
}

module AP_MODULE_DECLARE_DATA mod_auth_webform_module = {
    STANDARD20_MODULE_STUFF,
    NULL,
    NULL,
    NULL,
    NULL,
    NULL,
    mod_auth_webform_hooks
};
