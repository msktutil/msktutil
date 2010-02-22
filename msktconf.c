/*
 *----------------------------------------------------------------------------
 *
 * msktconf.c
 *
 * (C) 2004-2006 Dan Perry (dperry@pppl.gov)
 *
    This program is free software; you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation; either version 2 of the License, or
    (at your option) any later version.

    This program is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.

    You should have received a copy of the GNU General Public License
    along with this program; if not, write to the Free Software
    Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA  02110-1301  USA
 *
 *-----------------------------------------------------------------------------
 */

#include "msktutil.h"


/* Store the orginal config file and CC name */
static char *org_config = NULL;
static char *org_ccname = NULL;


#ifndef HAVE_SETENV

int setenv(const char *var, const char *val, int overwrite)
{
    char *env;
    int ret;


    env = (char *) malloc(strlen(var) + strlen(val) + 2);
    if (!env) {
        fprintf(stderr, "Error: malloc failed\n");
        return ENOMEM;
    }
    memset(env, 0, strlen(var) + strlen(val) + 2);
    sprintf(env, "%s=%s", var, val);
    ret = putenv(env);

    return ret;
}


#endif
#ifndef HAVE_UNSETENV

int unsetenv(const char *var)
{
    char *env;
    int ret;


    env = (char *) malloc(strlen(var) + 2);
    if (!env) {
        fprintf(stderr, "Error: malloc failed\n");
        return ENOMEM;
    }
    memset(env, 0, strlen(var) + 2);
    sprintf(env, "%s=", var);
    ret = putenv(env);

    return ret;
}

#endif


int create_fake_krb5_conf(msktutil_flags *flags)
{
    char *filename;
    FILE *file;
    int ret;


    filename = (char *) malloc(strlen(TMP_DIR) + 49);
    if (!filename) {
        fprintf(stderr, "Error: malloc failed\n");
        return ENOMEM;
    }
    memset(filename, 0, strlen(TMP_DIR) + 49);
    sprintf(filename, "%s/.mskt-%dkrb5.conf", TMP_DIR, getpid());
    file = fopen(filename, "w");
    if (!file) {
        fprintf(stderr, "Error: failed to open %s\n", filename);
        free(filename);
        return -1;
    }
    fprintf(file, "[libdefaults]\n");
    fprintf(file, " default_realm = %s\n", flags->realm_name);
    fprintf(file, " dns_lookup_kdc = false\n");
    fprintf(file, " udp_preference_limit = 1\n");
    fprintf(file, "[realms]\n");
    fprintf(file, " %s = {\n", flags->realm_name);
    fprintf(file, "  kdc = %s\n", flags->server);
    fprintf(file, "  admin_server = %s\n", flags->server);
    fprintf(file, " }\n");
    fclose(file);

    if (getenv("KRB5_CONFIG")) {
        org_config = strdup(getenv("KRB5_CONFIG"));
    }

    ret = setenv("KRB5_CONFIG", filename, 1);
    VERBOSE("Created a fake krb5.conf file: %s", filename);
    free(filename);
    if (ret) {
        fprintf(stderr, "Error: setenv failed\n");
        return ret;
    }

    krb5_free_context(flags->context);
    flags->context = NULL;
    return get_krb5_context(flags);
}


int remove_fake_krb5_conf()
{
    char *filename;
    int ret;


    ret = unsetenv("KRB5_CONFIG");
    if (org_config) {
        ret |= setenv("KRB5_CONFIG", org_config, 1);
    }

    filename = (char *) malloc(strlen(TMP_DIR) + 49);
    if (!filename) {
        fprintf(stderr, "Error: malloc failed\n");
        return ENOMEM;
    }
    memset(filename, 0, strlen(TMP_DIR) + 49);
    sprintf(filename, "%s/.mskt-%dkrb5.conf", TMP_DIR, getpid());
    ret |= unlink(filename);
    free(filename);

    return ret;
}


int try_machine_keytab(msktutil_flags *flags)
{
    char *filename;
    krb5_keytab keytab;
    krb5_creds creds;
    krb5_principal principal;
    krb5_ccache ccache;
    int ret;


    filename = (char *) malloc(strlen(TMP_DIR) + 52);
    if (!filename) {
        fprintf(stderr, "Error: malloc failed\n");
        return ENOMEM;
    }
    memset(filename, 0, strlen(TMP_DIR) + 52);
    sprintf(filename, "%s/.mskt-%dkrb5_ccache", TMP_DIR, getpid());
    VERBOSE("Using the local credential cache: %s", filename);

    if (getenv("KRB5CCNAME")) {
        org_ccname = strdup(getenv("KRB5CCNAME"));
    }

    ret = setenv("KRB5CCNAME", filename, 1);
    if (ret) {
        fprintf(stderr, "Error: setenv failed\n");
        return ret;
    }

    ret = krb5_kt_resolve(flags->context, flags->keytab_file, &keytab);
    if (ret) {
        VERBOSE("krb5_kt_resolve failed (%s)", error_message(ret));
        VERBOSE("Unable to authenticate using the local keytab");
        free(filename);
        return ret;
    }
    ret = krb5_parse_name(flags->context, flags->userPrincipalName, &principal);
    if (ret) {
        VERBOSE("krb5_parse_name failed (%s)", error_message(ret));
        VERBOSE("Unable to authenticate using the local keytab");
        krb5_kt_close(flags->context, keytab);
        free(filename);
        return ret;
    }
    ret = krb5_get_init_creds_keytab(flags->context, &creds, principal, keytab, 0, NULL, NULL);
    krb5_kt_close(flags->context, keytab);
    if (ret) {
        VERBOSE("krb5_get_init_creds_keytab failed (%s)", error_message(ret));
        VERBOSE("Unable to authenticate using the local keytab");
        free(filename);
        return ret;
    }
    ret = krb5_cc_resolve(flags->context, filename, &ccache);
    free(filename);
    if (ret) {
        VERBOSE("krb5_cc_default failed (%s)", error_message(ret));
        VERBOSE("Unable to authenticate using the local keytab");
        krb5_free_cred_contents(flags->context, &creds);
        return ret;
    }
    ret = krb5_cc_initialize(flags->context, ccache, principal);
    krb5_free_principal(flags->context, principal);
    if (ret) {
        VERBOSE("krb5_cc_initialize failed (%s)", error_message(ret));
        VERBOSE("Unable to authenticate using the local keytab");
        krb5_cc_close(flags->context, ccache);
        krb5_free_cred_contents(flags->context, &creds);
        return ret;
    }
    ret = krb5_cc_store_cred(flags->context, ccache, &creds);
    krb5_cc_close(flags->context, ccache);
    krb5_free_cred_contents(flags->context, &creds);
    if (ret) {
        VERBOSE("krb5_cc_store_cred failed (%s)", error_message(ret));
        VERBOSE("Unable to authenticate using the local keytab");
    }
    return ret;
}


int untry_machine_keytab()
{
    char *filename;
    int ret;


    ret = unsetenv("KRB5CCNAME");
    if (org_ccname) {
        ret |= setenv("KRB5CCNAME", org_ccname, 1);
    }

    filename = (char *) malloc(strlen(TMP_DIR) + 52);
    if (!filename) {
        fprintf(stderr, "Error: malloc failed\n");
        return ENOMEM;
    }
    memset(filename, 0, strlen(TMP_DIR) + 52);
    sprintf(filename, "%s/.mskt-%dkrb5_ccache", TMP_DIR, getpid());
    ret |= unlink(filename);
    free(filename);

    return ret;
}
