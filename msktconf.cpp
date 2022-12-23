/*
 *----------------------------------------------------------------------------
 *
 * msktconf.cpp
 *
 * (C) 2004-2006 Dan Perry (dperry@pppl.gov)
 * (C) 2006 Brian Elliott Finley (finley@anl.gov)
 * (C) 2009-2010 Doug Engert (deengert@anl.gov)
 * (C) 2010 James Y Knight (foom@fuhm.net)
 * (C) 2010-2013 Ken Dreyer <ktdreyer at ktdreyer.com>
 * (C) 2012-2017 Mark Proehl <mark at mproehl.net>
 * (C) 2012-2017 Olaf Flebbe <of at oflebbe.de>
 * (C) 2013-2017 Daniel Kobras <d.kobras at science-computing.de>
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
#include <cctype>


std::string create_default_machine_password(const std::string &sAMAccountName)
{
    std::string machine_password(sAMAccountName);

    /* Default machine password after 'reset account' is created with the
     * following algorithm:
     *
     * 1) Remove trailing $ from sAMAcountName
     * 2) Truncate to first 14 characters
     * 3) Convert all characters to lowercase
     *
     */

    /* Remove trailing '$' */
    if (machine_password[machine_password.size() - 1] == '$') {
        machine_password.resize(machine_password.size() - 1);
    }

    /* Truncate to first 14 characters */
    if (machine_password.size() > MAX_DEF_MACH_PASS_LEN) {
        machine_password.resize(MAX_DEF_MACH_PASS_LEN);
    }

    /* Convert all characters to lowercase */
    for (size_t i = 0; i < machine_password.size(); i++) {
        machine_password[i] = std::tolower(machine_password[i]);
    }

    VERBOSE("Default machine password for %s is %s",
            sAMAccountName.c_str(),
            machine_password.c_str());

    return machine_password;
}


/* Filenames to delete on exit (temporary config / ccaches) */
static std::string g_config_filename;
static std::string g_ccache_filename;

std::string get_tempfile_name(const char *name)
{
    std::string full_template = sform("%s/%s-XXXXXX", TMP_DIR, name);
    char *template_arr = strdup(full_template.c_str());

    int fd = mkstemp(template_arr);
    if (fd < 0) {
        error_exit("mkstemp failed");
    }

    /* Didn't need an fd, just to have the filename created securely. */
    close(fd);
    std::string tempfile_name = std::string(template_arr);
    free(template_arr);

    return tempfile_name;
}


void create_fake_krb5_conf(msktutil_flags *flags)
{
    g_config_filename = get_tempfile_name(".msktkrb5.conf");
    std::ofstream file(g_config_filename.c_str());

    file << "[libdefaults]\n"
         << " default_realm = " << flags->realm_name << "\n"
         << " dns_lookup_kdc = true\n"
         << " udp_preference_limit = 1\n"
         << " default_ccache_name = " << KRB5CCache::defaultName() << "\n";

    if (flags->allow_weak_crypto) {
        file << " allow_weak_crypto = true\n";
    }

    if (flags->enctypes == VALUE_ON) {
        file << " default_tkt_enctypes =";
        if (flags->supportedEncryptionTypes & 0x1) {
            file << " des-cbc-crc";
        }
        if (flags->supportedEncryptionTypes & 0x2) {
            file << " des-cbc-md5";
        }
        if (flags->supportedEncryptionTypes & 0x4) {
            file << " arcfour-hmac-md5";
        }
        if (flags->supportedEncryptionTypes & 0x8) {
            file << " aes128-cts";
        }
        if (flags->supportedEncryptionTypes & 0x10) {
            file << " aes256-cts";
        }
        file << "\n";
    }
    if ((flags->no_reverse_lookups) || (flags->no_canonical_name)) {
        file << " rdns = false\n";
    }

    file << "[realms]\n"
         << " " << flags->realm_name << " = {\n"
         << "  kdc = " << flags->server << "\n"
         << "  admin_server = " << flags->server << "\n"
         << " }\n";
    file.close();

#ifdef HAVE_SETENV
    int ret = setenv("KRB5_CONFIG", g_config_filename.c_str(), 1);
    if (ret) {
        error_exit("setenv failed");
    }
#else
    int ret = putenv(strdup((std::string("KRB5_CONFIG=") +  g_config_filename).c_str()));
    if (ret) {
        error_exit("putenv failed");
    }
#endif

    VERBOSE("Created fake krb5.conf file: %s", g_config_filename.c_str());

    destroy_g_context();
    initialize_g_context();
}


void remove_fake_krb5_conf()
{
    if (!g_config_filename.empty()) {
        unlink(g_config_filename.c_str());
        g_config_filename.clear();
    }
}


void remove_ccache()
{
    if (!g_ccache_filename.empty()) {
        unlink(g_ccache_filename.c_str());
        g_ccache_filename.clear();
    }
}


void switch_default_ccache(const char *ccache_name)
{
    VERBOSE("Using the local credential cache: %s", ccache_name);

    /* Is this setenv really necessary given krb5_cc_set_default_name?
     * ...answer: YES, because LDAP's SASL won't be using our context
     * object, and may in fact be using a different implementation of
     * Kerberos entirely! */
#ifdef HAVE_SETENV
    if (setenv("KRB5CCNAME", ccache_name, 1)) {
        error_exit("setenv failed");
    }
#else
    if (!putenv(strdup((std::string("KRB5CCNAME=")+ ccache_name).c_str()))) {
        error_exit("putenv failed");
    }
#endif
    krb5_cc_set_default_name(g_context, ccache_name);
}


bool try_machine_keytab_princ(msktutil_flags *flags,
                              const std::string &principal_name,
                              const char *ccache_name)
{
    try {
        VERBOSE("Trying to authenticate %s from local keytab",
                principal_name.c_str());
        KRB5Keytab keytab(flags->keytab_readname);
        KRB5Principal principal(principal_name);
        KRB5Creds creds(principal, keytab);
        KRB5CCache ccache(ccache_name);
        ccache.initialize(principal);
        ccache.store(creds);
        switch_default_ccache(ccache_name);
        return true;
    } catch (KRB5Exception &e) {
        VERBOSE("%s", e.what());
        VERBOSE("Authentication with keytab failed");
        return false;
    }
}


bool try_machine_password(msktutil_flags *flags, const char *ccache_name)
{
    try {
        VERBOSE("Trying to authenticate %s with password",
                flags->sAMAccountName.c_str());
        KRB5Principal principal(flags->sAMAccountName);
        KRB5Creds creds(principal,
                        /*password:*/
                        create_default_machine_password(flags->sAMAccountName));
        KRB5CCache ccache(ccache_name);
        ccache.initialize(principal);
        ccache.store(creds);
        switch_default_ccache(ccache_name);
        return true;
    } catch (KRB5Exception &e) {
        VERBOSE("%s", e.what());
        VERBOSE("Authentication with password failed");
        return false;
    }
}


bool try_machine_supplied_password(msktutil_flags *flags,
                                   const char *ccache_name)
{
    try {
        VERBOSE("Trying to authenticate %s with supplied password",
                flags->sAMAccountName.c_str());
        KRB5Principal principal(flags->sAMAccountName);
        KRB5Creds creds(principal, /*password:*/ flags->old_account_password);
        KRB5CCache ccache(ccache_name);
        ccache.initialize(principal);
        ccache.store(creds);
        switch_default_ccache(ccache_name);
        return true;
    } catch (KRB5Exception &e) {
        VERBOSE("%s", e.what());
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


bool get_creds(msktutil_flags *flags)
{
    g_ccache_filename = get_tempfile_name(".mskt_krb5_ccache");
    std::string ccache_name = "FILE:" + g_ccache_filename;
    try {
        KRB5Principal principal(flags->sAMAccountName);
        KRB5Creds creds(principal, /*password:*/ flags->password);
        KRB5CCache ccache(ccache_name.c_str());
        ccache.initialize(principal);
        ccache.store(creds);
        switch_default_ccache(ccache_name.c_str());
        return true;
    } catch (KRB5Exception &e) {
        VERBOSE("%s", e.what());
        VERBOSE("Authentication with password failed");
        return false;
    }
}


bool try_user_creds()
{
    try {
        VERBOSE("Checking if default ticket cache has tickets");
        /* The following is for the side effect of throwing an
         * exception or not. */
        KRB5CCache ccache(KRB5CCache::defaultName());
        KRB5Principal princ(ccache);

        return true;
    } catch(KRB5Exception &e) {
        VERBOSE("%s", e.what());
        VERBOSE("Default ticket cache was not valid");
        return false;
    }
}


int find_working_creds(msktutil_flags *flags)
{
    /* We try some different ways, in order:
     * 1) Use principal from keytab. Try both:
     *    a) sAMAccountName
     *    b) host/full-hostname (for compat with older msktutil which
     *       didn't write the first).
     * 2) Use principal sAMAccountName with default password
     *    (sAMAccountName_nodollar)
     * 3) Use supplied credentials (--old-account-password)
     *    When the supplied password has expired (e.g. because
     *    the service account has been newly created) we cannot find
     *    any working credentials here and have to return
     *    AUTH_FROM_SUPPLIED_EXPIRED_PASSWORD.
     *    In this case working credentials need to be obtained
     *    after changing password
     * 4) Calling user's existing credentials from their credential
     *    cache.
    */
    if (!flags->user_creds_only) {
        std::string host_princ = "host/" + flags->hostname;
        /*
         * NOTE: we have to use an actual file for the credential
         * cache, and not a MEMORY: type, because libsasl may be using
         * Heimdal, while this program may be compiled against MIT
         * Kerberos. So, while it's all in the same process and you'd
         * think an in-mem ccache would be the right thing, the two
         * Kerberos implementations cannot share an in-memory ccache,
         * so we have to use a file. Sigh.
         */
        g_ccache_filename = get_tempfile_name(".mskt_krb5_ccache");
        std::string ccache_name = "FILE:" + g_ccache_filename;

        if (!flags->keytab_auth_princ.empty() &&
            access(flags->keytab_file.c_str(), R_OK) == 0 &&
            try_machine_keytab_princ(flags,
                                     flags->keytab_auth_princ,
                                     ccache_name.c_str())) {
            return AUTH_FROM_EXPLICIT_KEYTAB;
        }
        if (access(flags->keytab_file.c_str(), R_OK) == 0 &&
            try_machine_keytab_princ(flags,
                                     flags->sAMAccountName,
                                     ccache_name.c_str())) {
            return AUTH_FROM_SAM_KEYTAB;
        }
        if (access(flags->keytab_file.c_str(), R_OK) == 0 &&
            try_machine_keytab_princ(flags,
                                     flags->sAMAccountName_uppercase,
                                     ccache_name.c_str())) {
            return AUTH_FROM_SAM_UPPERCASE_KEYTAB;
        }
        if (access(flags->keytab_file.c_str(), R_OK) == 0 &&
            try_machine_keytab_princ(flags,
                                     host_princ,
                                     ccache_name.c_str())) {
            return AUTH_FROM_HOSTNAME_KEYTAB;
        }
        if (try_machine_password(flags, ccache_name.c_str())) {
            return AUTH_FROM_PASSWORD;
        }
        if (strlen(flags->old_account_password.c_str())) {
            if (try_machine_supplied_password(flags, ccache_name.c_str())) {
                return AUTH_FROM_SUPPLIED_PASSWORD;
            }
            if (flags->password_expired) {
                return AUTH_FROM_SUPPLIED_EXPIRED_PASSWORD;
            }
        }
    }
    if (try_user_creds()) {
        return AUTH_FROM_USER_CREDS;
    }

    return AUTH_NONE;
}
