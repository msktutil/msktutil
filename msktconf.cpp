/*
 *----------------------------------------------------------------------------
 *
 * msktconf.cpp
 *
 * (C) 2004-2006 Dan Perry (dperry@pppl.gov)
 * (C) 2006 Brian Elliott Finley (finley@anl.gov)
 * (C) 2009-2010 Doug Engert (deengert@anl.gov)
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


/* Filenames to delete on exit (temporary config / ccaches) */
static std::string g_config_filename;
static std::string g_ccache_filename;

std::string get_tempfile_name(const char *name) {
    std::string full_template = sform("%s/%s-XXXXXX", TMP_DIR, name);
    char template_arr[full_template.size() + 1];
    memcpy(template_arr, full_template.c_str(), full_template.size() + 1);

    int fd = mkstemp(template_arr);
    if (fd < 0)
        throw Exception(sform("Error: mkstemp failed: %d", errno));

    // Didn't need an fd, just to have the filename created securely.
    close(fd);
    return std::string(template_arr);
}

void create_fake_krb5_conf(msktutil_flags *flags)
{
    g_config_filename = get_tempfile_name(".msktkrb5.conf");
    std::ofstream file(g_config_filename.c_str());

    file << "[libdefaults]\n"
         << " default_realm = " << flags->realm_name << "\n"
         << " dns_lookup_kdc = false\n"
         << " udp_preference_limit = 1\n";

    if (flags->no_reverse_lookups)
        file << " rdns = false\n";

    file << "[realms]\n"
         << " " << flags->realm_name << " = {\n"
         << "  kdc = " << flags->server << "\n"
         << "  admin_server = " << flags->server << "\n"
         << " }\n";
    file.close();

    int ret = setenv("KRB5_CONFIG", g_config_filename.c_str(), 1);
    VERBOSE("Created a fake krb5.conf file: %s", g_config_filename.c_str());
    if (ret)
        throw Exception("setenv failed");

    g_context.reload();
}


void remove_fake_krb5_conf()
{
    if (!g_config_filename.empty()) {
        unlink(g_config_filename.c_str());
        g_config_filename.clear();
    }
}

void remove_ccache() {
    if (!g_ccache_filename.empty()) {
        unlink(g_ccache_filename.c_str());
        g_ccache_filename.clear();
    }
}
void switch_default_ccache(const char *ccache_name)
{
    VERBOSE("Using the local credential cache: %s", ccache_name);

    // Is this setenv really necessary given krb5_cc_set_default_name?
    // ...answer: YES, because ldap's sasl won't be using our context object,
    // and may in fact be using a different implementation of kerberos entirely!
    if (setenv("KRB5CCNAME", ccache_name, 1))
        throw Exception("Error: setenv failed");

    krb5_cc_set_default_name(g_context.get(), ccache_name);
}

bool try_machine_keytab_princ(msktutil_flags *flags, const std::string &principal_name,
                              const char *ccache_name) {
    try {
        VERBOSE("Trying to authenticate for %s from local keytab...", principal_name.c_str());
        KRB5Keytab keytab(flags->keytab_readname);
        KRB5Principal principal(principal_name);
        KRB5Creds creds(principal, keytab);
        KRB5CCache ccache(ccache_name);
        ccache.initialize(principal);
        ccache.store(creds);
        switch_default_ccache(ccache_name);
        return true;
    } catch (KRB5Exception &e) {
        VERBOSE(e.what());
        VERBOSE("Authentication with keytab failed");
        return false;
    }
}

bool try_machine_password(msktutil_flags *flags, const char *ccache_name) {
    try {
        VERBOSE("Trying to authenticate for %s with password.", flags->samAccountName.c_str());
        KRB5Principal principal(flags->samAccountName);
        KRB5Creds creds(principal, /*password:*/ flags->samAccountName_nodollar);
        KRB5CCache ccache(ccache_name);
        ccache.initialize(principal);
        ccache.store(creds);
        switch_default_ccache(ccache_name);
        return true;
    } catch (KRB5Exception &e) {
        VERBOSE(e.what());
        VERBOSE("Authentication with password failed");
        return false;
    }
}

bool try_machine_supplied_password(msktutil_flags *flags, const char *ccache_name) {
    try {
        VERBOSE("Trying to authenticate for %s with supplied password.", flags->samAccountName.c_str());
        KRB5Principal principal(flags->samAccountName);
        KRB5Creds creds(principal, /*password:*/ flags->old_account_password);
        KRB5CCache ccache(ccache_name);
        ccache.initialize(principal);
        ccache.store(creds);
        switch_default_ccache(ccache_name);
        return true;
    } catch (KRB5Exception &e) {
        VERBOSE(e.what());
        if (e.err() == KRB5KDC_ERR_KEY_EXP) {
            VERBOSE("Password needs to be changed");
            flags->password_expired = true;
            return false;
        } else {
            VERBOSE("Authentication with supplied password failed");
            return false;
        }
    }
}

bool get_creds(msktutil_flags *flags) {
    g_ccache_filename = get_tempfile_name(".mskt_krb5_ccache");
    std::string ccache_name = "FILE:" + g_ccache_filename;
    try {
        KRB5Principal principal(flags->samAccountName);
        KRB5Creds creds(principal, /*password:*/ flags->password);
        KRB5CCache ccache(ccache_name.c_str());
        ccache.initialize(principal);
        ccache.store(creds);
	switch_default_ccache(ccache_name.c_str());
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

    /* We try some different ways, in order:
       1) Use principal from keytab. Try both:
         a) samAccountName
         b) host/full-hostname (for compat with older msktutil which didn't write the first).
       2) Use principal samAccountName with default password (samAccountName_nodollar)
       3) Use supplied credentials (--old-account-password)
          When the supplied password has expired (e.g. because the service account 
          has been newly created) we cannot find any working credentials here 
          and have to return AUTH_FROM_SUPPLIED_EXPIRED_PASSWORD.
          In this case working credentials need to be obtained after changing password
       4) Calling user's existing credentials from their credential cache.
    */

    if (!flags->user_creds_only) {
        std::string host_princ = "host/" + flags->hostname;

        // NOTE: we have to use an actual file for the credential cache, and not a MEMORY: type,
        // because libsasl may be using heimdal, while this program may be compiled against MIT
        // kerberos. So, while it's all in the same process and you'd think an in-mem ccache would
        // be the right thing, the two kerberos implementations cannot share an in-memory ccache, so
        // we have to use a file. Sigh.
        g_ccache_filename = get_tempfile_name(".mskt_krb5_ccache");
        std::string ccache_name = "FILE:" + g_ccache_filename;

        if (try_machine_keytab_princ(flags, flags->samAccountName, ccache_name.c_str()))
            return AUTH_FROM_SAM_KEYTAB;
        if (try_machine_keytab_princ(flags, host_princ, ccache_name.c_str()))
            return AUTH_FROM_HOSTNAME_KEYTAB;
        if (try_machine_password(flags, ccache_name.c_str()))
            return AUTH_FROM_PASSWORD;
        if (strlen(flags->old_account_password.c_str())) {
	    if (try_machine_supplied_password(flags, ccache_name.c_str())) {
                return AUTH_FROM_SUPPLIED_PASSWORD;
            }
            if (flags->password_expired) {
                return AUTH_FROM_SUPPLIED_EXPIRED_PASSWORD;
            }
        }
    }
    if (try_user_creds())
        return AUTH_FROM_USER_CREDS;

    return AUTH_NONE;
}


