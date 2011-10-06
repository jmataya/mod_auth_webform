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

// Apache References
#include <httpd.h>
#include <http_config.h>
#include <http_log.h>
#include <http_protocol.h>

// APR References
#include "apr.h"
#include "apr_strings.h"
#include "apr_hash.h"
#include "apr_user.h"
#include "apr_lib.h"
#include "apr_signal.h"
#include "apr_global_mutex.h"
#include "apr_dbm.h"

// Linux References
#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>

// Other references
#include <stdlib.h>

// Constants
#define URL_MAX_LEN 2000    // Based on research that 2,000 is what browsers
                            // will implement at a maximum.

//
// The configuration structure. This structure is heavily influenced by
// Mathieu Carbonneaux's mod_auth_memcookie.
//
typedef struct {
    char *	szAuth_memCookie_memCached_addr;
    apr_time_t 	tAuth_memCookie_MemcacheObjectExpiry;
    int 	nAuth_memCookie_MemcacheObjectExpiryReset;

    int 	nAuth_memCookie_SetSessionHTTPHeader;
    int 	nAuth_memCookie_SetSessionHTTPHeaderEncode;
    int 	nAuth_memCookie_SessionTableSize;

    char *	szAuth_memCookie_CookieName;

    int 	nAuth_memCookie_GroupAuthoritative;
    int 	nAuth_memCookie_Authoritative;
    int 	nAuth_memCookie_MatchIP_Mode;

    int 	nAuth_memCookie_authbasicfix;
} strAuth_memCookie_config_rec;

//
// Extract the cookie from the headers.
// This method was influenced by Mathieu Carbonneaux's mod_auth_memcookie.
//
// Inputs:
//  (*) r - The current request.
//  (*) cookie_name - The name of the cookie.
//
// Returns:
//  (*) The cookie.
//
static char * extract_cookie(request_rec *r, const char *cookie_name) {
    char *last = NULL;
    char *raw_cookie = NULL;
    char *individual_cookie = NULL;
    char *specific_cookie = NULL;
    char tokens[] = "; ";

    // Extract the raw cookie from the headers.
    raw_cookie = apr_palloc(r->pool, 1024 * sizeof(char));
    apr_cpystrn(raw_cookie, (char*)apr_table_get(r->headers_in, "Cookie"), 1024);

    if (raw_cookie == NULL) {
        ap_log_rerror(
            APLOG_MARK,
            APLOG_ERR,
            0,
            r,
            "mod_auth_webform: Cookie not found in the headers.");
        return NULL;
    }

    ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r, raw_cookie);
 
    // Separate the cookies and inspect one by one.
    individual_cookie = apr_strtok(raw_cookie, tokens, &last);
    while (individual_cookie != NULL) {
        ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r, individual_cookie);
        individual_cookie = apr_strtok(NULL, tokens, &last);
    }

    // Search for the cookie name.
    /*//do {
        // Get the first occurrance of the cookie name.
        raw_cookie = strstr(raw_cookie, cookie_name);
        if (raw_cookie == NULL) {
            ap_log_rerror(
                APLOG_MARK,
                APLOG_ERR,
                0,
                r,
                "mod_auth_webform: Cookie name not found.");
            return NULL;
        }

*/
    return "test";
}

//
// Get a value from the Apache configuration.
//
// Inputs:
//  (*) r - The current request data structure.
//  (*) key - Key identifying the value to find.
//
// Returns:
//  (*) Either the value as a character string. Returns NULL if not found.
//
static char * get_conf_value(request_rec *r, char *key) {
    char * value = NULL;
    
    if (r != NULL && r->subprocess_env != NULL && key != NULL) {
        value = (char *)apr_table_get(r->subprocess_env, key);
    }
    
    return value;
}

//
// Copy part of a string.
//
// Inputs:
//  (*) r - The request data structure.
//  (*) source - The original string.
//  (*) start_index - The place in the string where the copy should start.
//  (*) copy_length - The number of characters to copy. This should NOT include
//          the null character.
// Returns:
//  (*) The substring that has been copied.
//
static char * substr_copy(request_rec *r, char *source, int start_index, int copy_length) {

    char *substr = NULL;
    int index = 0;
    
    if (start_index >= 0 && start_index < strlen(source)) {
        substr = apr_palloc(r->pool, (copy_length + 1) * sizeof(char));
        
        while (start_index < strlen(source) && index < copy_length) {
            substr[index++] = source[start_index++];
        }
        
        substr[index] = '\0';
    }
    
    return substr;
}

//
// Replace a substring within a string.
//
// Inputs:
//  (*) r - The request data structure.
//  (*) initial - The initial string.
//  (*) to_remove - The part of the string that should be replaced.
//  (*) to_add - The new string to add.
//
// Returns:
//  (*) The new string.
//
static char * replace_substr(request_rec *r, char *initial, char *to_remove, char *to_add) {

    char *improved;
    char *substr;
    int improved_size;
    int idx_initial = 0;
    int idx_improved = 0;
    int idx_to_add = 0;
    int to_remove_found = 0;
    
    improved_size = strlen(initial) - strlen(to_remove) + strlen(to_add);
    improved = apr_palloc(r->pool, improved_size * sizeof(char));
    
    while (idx_initial < strlen(initial) && idx_improved < improved_size) {
    
        improved[idx_improved] = initial[idx_initial];
        
        // Check for replacement
        if (!to_remove_found) {
            substr = substr_copy(r, initial, idx_initial, strlen(to_remove));
            if (strcmp(substr, to_remove) == 0) {
                to_remove_found = 1;
                
                // Insert the new string.
                for (idx_to_add = 0; idx_to_add < strlen(to_add); idx_to_add++) {
                    improved[idx_improved++] = to_add[idx_to_add];
                }
                                
                // Update the indecies.
                idx_initial += strlen(to_remove) - 1;
                idx_improved -= 1;
            }
        }
        
                
        
        idx_initial++;
        idx_improved++;
    }
    
    return improved;
}

    
//
// Strips the http(s):// from the beginning of the URL.
//
// Inputs:
//  (*) url - The raw URL that is inputted from the user.
//            TODO: Do some testing around XSS here.
// Returns:
//  (*) The new normalized URL.
//
static char * normalize_url(request_rec *r, char *url) {
    char *return_url = NULL;
    char *file_root = NULL;
    char *server_name = NULL;
    
    // Some basic error checking.
    if (url == NULL || strlen(url) > URL_MAX_LEN) {
        return_url = apr_palloc(r->pool, sizeof(char));
        return_url[0] = '\0';
        return return_url;
    }
    else if (url[strlen(url)] != '\0') {
        // Ensure that the string is null terminated.
        url[strlen(url)] = '\0';
    }
    
    // Initialize the return URL.
    return_url = apr_palloc(r->pool, (strlen(url) + 1) * sizeof(char));     
 
    // Attempt to retrieve the document root from httpd.conf.
    file_root = get_conf_value(r, "file_root");
    if (file_root == NULL) {
        ap_log_rerror(
            APLOG_MARK,
            APLOG_ERR,
            0,
            r,
            "mod_auth_webform: Env variable file_root not found in httpd.conf");
        return NULL;
    }   
    
    // Attempt to retrieve the server name from httpd.conf.
    server_name = get_conf_value(r, "server_name");
    if (server_name == NULL) {
        ap_log_rerror(
            APLOG_MARK,
            APLOG_ERR,
            0,
            r,
            "mod_auth_webform: Env variable server_name not found in httpd.conf");
        return NULL;
    }

    // Remove https, then http, then the file_root.
    return_url = replace_substr(r, url, "https://", "");
    return_url = replace_substr(r, url, "http://", "");
    return_url = replace_substr(r, url, file_root, server_name);
    
    return return_url;
}

//
// Craft the login URL. This involves setting the URL that goes to the login page.
// It also adds the redirection query string parameters.
//
// Inputs:
//  (*) r - The current request data source.
//  (*) login_url - The location of the login page.
//  (*) return_url - The URL that the user was trying to get to.
//
// Returns:
//  (*) The final URL.
//
static char * craft_login_url(request_rec *r, char *login_url, char *return_url) {
    char *final_url;
    char *fixed_return_url;
    int size;
    
    // Fix the return URL.
    fixed_return_url = normalize_url(r, return_url);
    if (fixed_return_url == NULL) {
        ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r, "mod_auth_webform: Error fixing URL");
        return NULL;
    }
    
    // Get the size of the new URL.
    size = strlen(login_url) + strlen("?redir=") + strlen(fixed_return_url) + 3;
    
    // Set the new URL.
    final_url = apr_palloc(r->pool, size * sizeof(char));
    strcat(final_url, login_url);
    strcat(final_url, "?redir=");
    strcat(final_url, fixed_return_url);
    return final_url;
}

static int mod_auth_webform_handler(request_rec *r) {
     
    apr_file_t *fd;
    apr_size_t sz;
    apr_status_t rv;
    char *login_filename;
    char *fixed_login_filename;
    struct stat st;
    int size;
    char *final_login_url;

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

    //
    // TODO: Insert logic that checks to see if the user is signed in. If so,
    // then serve the requested page. If not, redirect to the login page.
    //
    extract_cookie(r, "Test");

    // Attempt to retrieve the login page from httpd.conf.
    login_filename = get_conf_value(r, "auth_page");
    if (login_filename == NULL) {
        ap_log_rerror(
            APLOG_MARK,
            APLOG_ERR,
            0,
            r,
            "mod_auth_webform: Env variable auth_page not found in httpd.conf");
        return HTTP_INTERNAL_SERVER_ERROR;
    }

    final_login_url = craft_login_url(r, login_filename, r->filename);
    if (final_login_url == NULL) {
        ap_log_rerror(
            APLOG_MARK,
            APLOG_ERR,
            0,
            r,
            "mod_auth_webform: Error in final_login_url");
        return HTTP_INTERNAL_SERVER_ERROR;
    }

    apr_table_setn(r->headers_out, "Location", final_login_url);
    return HTTP_MOVED_TEMPORARILY;
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
