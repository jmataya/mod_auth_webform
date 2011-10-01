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
// Get a value from the Apache configuration.
// Inputs:
//  (*) r - The current request data structure.
//  (*) key - Key identifying the value to find.
// Returns:
//  (*) Either the value as a character string. Returns NULL if not found.
//
char * get_conf_value(request_rec *r, char *key) {
    char * value = NULL;
    
    if (r != NULL && r->subprocess_env != NULL && key != NULL) {
        value = (char *)apr_table_get(r->subprocess_env, key);
    }
    
    return value;
}

//
// Copy part of a string.
// Inputs:
//  (*) r - The request data structure.
//  (*) source - The original string.
//  (*) start_index - The place in the string where the copy should start.
//  (*) copy_length - The number of characters to copy. This should NOT include
//          the null character.
// Returns:
//  (*) The substring that has been copied.
//
char * substr_copy(request_rec *r, char *source, int start_index, int copy_length) {

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
// Inputs:
//  (*) r - The request data structure.
//  (*) initial - The initial string.
//  (*) to_remove - The part of the string that should be replaced.
//  (*) to_add - The new string to add.
// Returns:
//  (*) The new string.
//
char * replace_substr(request_rec *r, char *initial, char *to_remove, char *to_add) {

    char *improved;
    char *substr;
    int improved_size;
    int idx_initial = 0;
    int idx_improved = 0;
    int idx_to_remove = 0;
    int idx_to_add = 0;
    int idx_placeholder = 0;
    int to_remove_found = 0;
    
    improved_size = strlen(initial) - strlen(to_remove) + strlen(to_add);
    improved = apr_palloc(r->pool, improved_size * sizeof(char));
    
    while (idx_initial < strlen(initial) && idx_improved < improved_size) {
    
        improved[idx_improved] = initial[idx_initial];
        
        // Check for replacement
        if (!to_remove_found) {
            substr = substr_copy(r, initial, idx_initial, strlen(to_remove));
            printf("Sub num. %i: %s\n", idx_initial, substr);
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

static char * my_cat(request_rec *r, char *destination, char *source) {
    int new_size = 0;
    int index_old = 0;
    int index_new = 0;
    char *new_string = NULL;
    char to_copy;
    
    // Allocate the new string.
    new_size = strlen(destination) + strlen(source) + 1;
    new_string = apr_palloc(r->pool, new_size * sizeof(char));
    
    // Copy the old string.
    while (index_old < strlen(destination) && destination[index_old] != '\0') {
        to_copy = destination[index_old];
        new_string[index_new] = to_copy;
        
        index_new++;
        index_old++;
    }
    
    // Copy the new string.
    index_old = 0;
    while (index_old < strlen(source) && source[index_new] != '\0') {
        // Copy.
        new_string[index_new] = source[index_old];
        index_new++;
        index_old++;
    }
    
    //new_string[index_new] = '\0';
    return new_string;
}

static char * craft_login_url(request_rec *r, char *login_url, char *return_url) {
    char *final_url;
    char *fixed_return_url;
    int size;
    
    // Fix the return URL.
    fixed_return_url = normalize_url(r, return_url);
    ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r, fixed_return_url);
    
    // Get the size of the new URL.
    size = strlen(login_url) + strlen(fixed_return_url) + 3;
    
    // Set the new URL.
    final_url = apr_palloc(r->pool, size * sizeof(char));
    //strcat(final_url, login_url);
    final_url = my_cat(r, final_url, login_url);
    final_url = my_cat(r, final_url, "?redir=");
    final_url = my_cat(r, final_url, fixed_return_url);
    
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

    //
    // TODO: Obviously, we don't want to always redirect to Google. Replace this
    // with the value taken from the configuration file.
    //
    final_login_url = craft_login_url(r, login_filename, r->filename);
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
