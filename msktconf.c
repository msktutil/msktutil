/*
 *----------------------------------------------------------------------------
 *
 * msktconf.c
 *
 * (C) 2004-2006 Dan Perry (dperry@pppl.gov)
 * (C) 2010 James Y Knight (foom@fuhm.net)
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

#include <fstream>


/* Store the orginal config file and CC name */
static char *org_config = NULL;
static char *org_ccname = NULL;


#ifndef HAVE_SETENV

int setenv(const char *var, const char *val, ATTRUNUSED int overwrite)
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


void create_fake_krb5_conf(msktutil_flags *flags)
{
    std::string filename = sform("%s/.mskt-%dkrb5.conf", TMP_DIR, getpid());;
    std::ofstream file(filename.c_str());

    file << "[libdefaults]\n"
         << " default_realm = " << flags->realm_name << "\n"
         << " dns_lookup_kdc = false\n"
         << " udp_preference_limit = 1\n"
         << "[realms]\n"
         << " " << flags->realm_name << " = {\n"
         << "  kdc = " << flags->server << "\n"
         << "  admin_server = " << flags->server << "\n"
         << " }\n";
    file.close();

    if (getenv("KRB5_CONFIG")) {
        org_config = strdup(getenv("KRB5_CONFIG"));
    }

    int ret = setenv("KRB5_CONFIG", filename.c_str(), 1);
    VERBOSE("Created a fake krb5.conf file: %s", filename.c_str());
    if (ret)
        throw Exception("setenv failed");

    g_context.reload();
}


int remove_fake_krb5_conf()
{
    std::string filename;
    int ret;


    ret = unsetenv("KRB5_CONFIG");
    if (org_config) {
        ret |= setenv("KRB5_CONFIG", org_config, 1);
    }

    filename = sform("%s/.mskt-%dkrb5.conf", TMP_DIR, getpid());
    ret = unlink(filename.c_str());

    return ret;
}


int try_machine_keytab(msktutil_flags *flags)
{
    std::string filename;
    krb5_keytab keytab;
    krb5_principal principal;
    krb5_ccache ccache;
    int ret;


    filename = sform("%s/.mskt-%dkrb5_ccache", TMP_DIR, getpid());
    VERBOSE("Using the local credential cache: %s", filename.c_str());

    if (getenv("KRB5CCNAME")) {
        org_ccname = strdup(getenv("KRB5CCNAME"));
    }

    ret = setenv("KRB5CCNAME", filename.c_str(), 1);
    if (ret) {
        fprintf(stderr, "Error: setenv failed\n");
        return ret;
    }

    ret = krb5_kt_resolve(g_context.get(), flags->keytab_file.c_str(), &keytab);
    if (ret) {
        VERBOSE("krb5_kt_resolve failed (%s)", error_message(ret));
        VERBOSE("Unable to authenticate using the local keytab");
        return ret;
    }
    ret = krb5_parse_name(g_context.get(), flags->userPrincipalName.c_str(), &principal);
    if (ret) {
        VERBOSE("krb5_parse_name failed (%s)", error_message(ret));
        VERBOSE("Unable to authenticate using the local keytab");
        krb5_kt_close(g_context.get(), keytab);
        return ret;
    }

    krb5_creds creds;
    ret = krb5_get_init_creds_keytab(g_context.get(), &creds, principal, keytab, 0, NULL, NULL);
    krb5_kt_close(g_context.get(), keytab);
    if (ret) {
        VERBOSE("krb5_get_init_creds_keytab failed (%s)", error_message(ret));
        VERBOSE("Unable to authenticate using the local keytab");
        return ret;
    }
    ret = krb5_cc_resolve(g_context.get(), filename.c_str(), &ccache);

    if (ret) {
        VERBOSE("krb5_cc_default failed (%s)", error_message(ret));
        VERBOSE("Unable to authenticate using the local keytab");
        krb5_free_principal(g_context.get(), principal);
        krb5_free_cred_contents(g_context.get(), &creds);
        return ret;
    }
    ret = krb5_cc_initialize(g_context.get(), ccache, principal);
    krb5_free_principal(g_context.get(), principal);
    if (ret) {
        VERBOSE("krb5_cc_initialize failed (%s)", error_message(ret));
        VERBOSE("Unable to authenticate using the local keytab");
        krb5_cc_close(g_context.get(), ccache);
        krb5_free_cred_contents(g_context.get(), &creds);
        return ret;
    }
    ret = krb5_cc_store_cred(g_context.get(), ccache, &creds);
    krb5_cc_close(g_context.get(), ccache);
    krb5_free_cred_contents(g_context.get(), &creds);
    if (ret) {
        VERBOSE("krb5_cc_store_cred failed (%s)", error_message(ret));
        VERBOSE("Unable to authenticate using the local keytab");
    }
    return ret;
}


int untry_machine_keytab()
{
    std::string filename;
    int ret;


    ret = unsetenv("KRB5CCNAME");
    if (org_ccname) {
        ret |= setenv("KRB5CCNAME", org_ccname, 1);
    }

    filename = sform("%s/.mskt-%dkrb5_ccache", TMP_DIR, getpid());
    ret = unlink(filename.c_str());

    return ret;
}
