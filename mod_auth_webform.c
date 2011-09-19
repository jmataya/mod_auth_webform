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

// Linux References
#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>

//
// Get a value from the Apache configuration.
// Inputs:
//  (*) r - The current request data structure.
//  (*) key - Key identifying the value to find.
// Returns:
//  (*) Either the value as a character string. Returns NULL if not found.
//
static char * get_conf_value(request_rec *r, char *key) {
    char *value = NULL;

    if (r != NULL && r->subprocess_env != NULL && key != NULL) {
        value = apr_table_get(r->subprocess_env, key);
    }

    return value;
}

static int mod_auth_webform_handler(request_rec *r) {
    apr_file_t *fd;
    apr_size_t sz;
    apr_status_t rv;
    char *login_filename;
    struct stat st;
    int size;

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
            "mod_auth_webform: Env variable auth_page not found in httpd.conf!");
        return HTTP_INTERNAL_SERVER_ERROR;
    }

    apr_table_setn(r->headers_out, "Location", "http://localhost");
    ap_internal_redirect("http://localhost", r);
/*
    // Redirect to the login page.
    ap_set_content_type(r, "text/html;charset=ascii");

    // Set the file size.
    stat(login_filename, &st);
    ap_set_content_length(r, st.st_size);

    // Set the last modified date.
    if (st.st_mtime) {
        char *date_str = apr_palloc(r->pool, APR_RFC822_DATE_LEN);
        apr_rfc822_date(date_str, st.st_mtime);
        apr_table_setn(r->headers_out, "Last-Modified", date_str);
    }

    // Open the file.
    rv = apr_file_open(
        &fd,
        login_filename,
        APR_READ|APR_SHARELOCK|APR_SENDFILE_ENABLED,
        APR_OS_DEFAULT,
        r->pool);

    if (rv != APR_SUCCESS) {
        ap_log_rerror(
            APLOG_MARK,
            APLOG_ERR,
            0, 
            r,
            "can't open %s",
            login_filename);
        return HTTP_NOT_FOUND;
    }

    // Send the file.
    ap_send_fd(fd, r, 0, st.st_size, &sz);
    apr_file_close(fd);
*/
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
