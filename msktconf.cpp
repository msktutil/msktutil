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

#define PRIVATE_CCACHE_NAME "MEMORY:msktutil"

void switch_default_ccache(char *ccache_name)
{
    char *filename = ccache_name;
    VERBOSE("Using the local credential cache: %s", filename);

    // Is this setenv really necessary given krb5_cc_set_default_name?
    if (setenv("KRB5CCNAME", filename, 1))
        throw Exception("Error: setenv failed");

    krb5_cc_set_default_name(g_context.get(), filename);
}

bool try_machine_keytab_princ(msktutil_flags *flags, std::string principal_name) {
    try {
        VERBOSE("Trying to authenticate for %s from local keytab...", principal_name.c_str());
        KRB5Keytab keytab(flags->keytab_file);
        KRB5Principal principal(principal_name);
        KRB5Creds creds(principal, keytab);
        KRB5CCache ccache(PRIVATE_CCACHE_NAME);
        ccache.initialize(principal);
        ccache.store(creds);
        switch_default_ccache(PRIVATE_CCACHE_NAME);
        return true;
    } catch (KRB5Exception &e) {
        VERBOSE(e.what());
        VERBOSE("Authentication with keytab failed");
        return false;
    }
}

bool try_machine_password(msktutil_flags *flags) {
    try {
        VERBOSE("Trying to authenticate for %s with password.", flags->samAccountName.c_str());
        KRB5Principal principal(flags->samAccountName);
        KRB5Creds creds(principal, /*password:*/ flags->samAccountName_nodollar);
        KRB5CCache ccache(PRIVATE_CCACHE_NAME);
        ccache.initialize(principal);
        ccache.store(creds);
        switch_default_ccache(PRIVATE_CCACHE_NAME);
        return true;
    } catch (KRB5Exception &e) {
        VERBOSE(e.what());
        VERBOSE("Authentication with password failed");
        return false;
    }
}

bool try_user_creds() {
    try {
        VERBOSE("Checking if default ticket cache has tickets...");
        // The following is for the side effect of throwing an exception or not.
        KRB5CCache ccache(KRB5CCache::defaultName());
        KRB5Principal princ(ccache);

        return true;
    } catch(KRB5Exception &e) {
        VERBOSE(e.what());
        VERBOSE("User ticket cache was not valid.");
        return false;
    }
}


int find_working_creds(msktutil_flags *flags) {
    std::string host_princ = "host/" + flags->hostname;

    if (try_machine_keytab_princ(flags, flags->samAccountName))
        return AUTH_FROM_SAM_KEYTAB;
    else if (try_machine_keytab_princ(flags, host_princ))
        return AUTH_FROM_HOSTNAME_KEYTAB;
    else if (try_machine_password(flags))
        return AUTH_FROM_PASSWORD;
    else if (try_user_creds())
        return AUTH_FROM_USER_CREDS;
    else
        return AUTH_NONE;
}


