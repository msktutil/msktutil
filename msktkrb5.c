/*
 *----------------------------------------------------------------------------
 *
 * msktkrb5.c
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
#include <cctype>
#include <algorithm>


std::string get_user_principal()
{
    VERBOSE("Obtaining Principal for the executing user");
    KRB5CCache ccache(KRB5CCache::defaultName());
    KRB5Principal principal(ccache);

    return principal.name();
}


void get_default_keytab(msktutil_flags *flags)
{
    char keytab_name[MAX_KEYTAB_NAME_LEN];

    if (flags->keytab_file.empty()) {
        /* Only set the field to a default if it's empty */
        krb5_error_code ret = krb5_kt_default_name(g_context.get(), keytab_name, MAX_KEYTAB_NAME_LEN);
        if (ret)
            throw KRB5Exception("krb5_kt_default_name (get_default_keytab)", ret);

        if (!strncmp(keytab_name, "FILE:", 5)) {
            /* Ignore the opening FILE: part */
            flags->keytab_file = std::string(keytab_name + 5);
        } else if (!strncmp(keytab_name, "WRFILE:", 7)) {
            /* Ignore the opening WRFILE: part */
            flags->keytab_file = std::string(keytab_name + 7);
        } else {
            /* No prefix to the keytab path */
            flags->keytab_file = std::string(keytab_name);
        }
        VERBOSE("Obtaining the default keytab name: %s", flags->keytab_file.c_str());
    }
}

int flush_keytab(msktutil_flags *flags)
{
    VERBOSE("Flushing the keytab");
    std::string keytab_name = sform("WRFILE:%s", flags->keytab_file.c_str());
    KRB5Keytab keytab(keytab_name);

    // Delete all entries for this host
    typedef std::vector<std::pair<std::pair<std::string, krb5_kvno>, krb5_enctype> > to_delete_t;
    to_delete_t to_delete;

    try {
        KRB5Keytab::cursor cursor(keytab);
        while (cursor.next()) {
            std::string principal = cursor.principal().name();
            size_t first_chr = principal.find('/') + 1;
            size_t last_chr = principal.rfind('@');

            std::string host = principal.substr(first_chr, last_chr - first_chr);
            if (host == flags->hostname) {
                to_delete.push_back(std::make_pair(std::make_pair(principal, cursor.kvno()),
                                                   cursor.enctype()));
            }
        }
    } catch (KRB5Exception ex) {
        // Ignore errors reading keytab
    }

    for(to_delete_t::const_iterator it = to_delete.begin(); it != to_delete.end(); ++it) {
        KRB5Principal princ(it->first.first);
        krb5_kvno kvno = it->first.second;
        krb5_enctype enctype = it->second;
        VERBOSE("Deleting %s kvno=%d, enctype=%d", it->first.first.c_str(), kvno, enctype);
        keytab.removeEntry(princ, kvno, enctype);
    }

    return ldap_flush_principals(flags);
}


int update_keytab(msktutil_flags *flags)
{
    std::vector<std::string> principals;
    int ret = 0;


    /* Need to call set_password first, as this will check and create the computer account if needed */
    ret = set_password(flags);
    if (ret) {
        fprintf(stderr, "Error: set_password failed\n");
        return ret;
    }

    VERBOSE("Updating all entires for %s", flags->short_hostname.c_str());
    add_principal(flags->samAccountName, flags);

    principals = ldap_list_principals(flags);
    for (size_t i = 0; i < principals.size(); ++i) {
        ret = add_principal(principals[i], flags);
        if (ret) {
            fprintf(stderr, "Error: add_principal failed\n");
            return ret;
        }
    }

    return ret;
}


int add_principal(const std::string &principal, msktutil_flags *flags)
{
    int ret;
    krb5_kvno kvno;


    VERBOSE("Adding principal to keytab: %s", principal.c_str());
    std::string keytab_name = sform("WRFILE:%s", flags->keytab_file.c_str());
    KRB5Keytab keytab(keytab_name);

    std::string principal_string = sform("%s@%s", principal.c_str(), flags->realm_name.c_str());
    KRB5Principal princ(principal_string);

    /* Need to call set_password first, as that produces a 'stable' kvno */
    ret = set_password(flags);
    if (ret) {
        fprintf(stderr, "Error: set_password failed\n");
        return ret;
    }
    kvno = ldap_get_kvno(flags);

    typedef std::vector<std::pair<std::pair<std::string, krb5_kvno>, krb5_enctype> > to_delete_t;
    to_delete_t to_delete;

    // Delete all entries with old kvnos (keep most recent)
    try {
        KRB5Keytab::cursor cursor(keytab);
        while (cursor.next()) {
            std::string curr_principal = cursor.principal().name();
            if (curr_principal == principal_string &&
                cursor.kvno() != kvno - 1) {
                to_delete.push_back(std::make_pair(std::make_pair(curr_principal, cursor.kvno()),
                                                   cursor.enctype()));
            }
        }
    } catch (KRB5Exception ex) {
        // Ignore errors reading keytab
    }

    for(to_delete_t::const_iterator it = to_delete.begin(); it != to_delete.end(); ++it) {
        KRB5Principal princ(it->first.first);
        krb5_kvno kvno = it->first.second;
        krb5_enctype enctype = it->second;
        VERBOSE("Deleting %s kvno=%d, enctype=%d", it->first.first.c_str(), kvno, enctype);
        keytab.removeEntry(princ, kvno, enctype);
    }

    std::vector<uint32_t> enc_types;
    if (flags->ad_supportedEncryptionTypes & MS_KERB_ENCTYPE_DES_CBC_CRC)
        enc_types.push_back(ENCTYPE_DES_CBC_CRC);
    if (flags->ad_supportedEncryptionTypes & MS_KERB_ENCTYPE_DES_CBC_MD5)
        enc_types.push_back(ENCTYPE_DES_CBC_MD5);
    if (flags->ad_supportedEncryptionTypes & MS_KERB_ENCTYPE_RC4_HMAC_MD5)
        enc_types.push_back(ENCTYPE_ARCFOUR_HMAC);
#ifdef ENCTYPE_AES128_CTS_HMAC_SHA1_96
    if (flags->ad_supportedEncryptionTypes & MS_KERB_ENCTYPE_AES128_CTC_HMAC_SHA1_96)
        enc_types.push_back(ENCTYPE_AES128_CTS_HMAC_SHA1_96);
#endif
#ifdef ENCTYPE_AES256_CTS_HMAC_SHA1_96
    if (flags->ad_supportedEncryptionTypes & MS_KERB_ENCTYPE_AES256_CTS_HMAC_SHA1_96)
        enc_types.push_back(ENCTYPE_AES256_CTS_HMAC_SHA1_96);
#endif

    ret = set_password(flags);
    if (ret) {
        fprintf(stderr, "Error: set_password failed\n");
        return ret;
    }

    std::string salt;

    for(size_t i = 0; i < enc_types.size(); ++i) {
        /*
         * Windows uses realm_name+"host"+samAccountName_nodollar+"."+lower_realm_name
         * for the salt. (note: arcfour-hmac doesn't use salts at all; it's irrelevant what you set it to)
         *
         * Windows 2000 may have used something different, but who cares.
         *
         * FIXME: this is stupid, and unreliable. The salt is supposed to be an implementation
         * detail that can be changed by the server anytime they feel like. Furthermore, if you
         * rename an account, the salt doesn't change until next time you reset a password.
         *
         * We should be able to simply ask the KDC what salt to use for the account (the very first
         * message the client sends when authenticating gets the salt as a response...).  However,
         * at first glance, it looks like the kerberos client APIs don't provide any way to get to
         * this functionality (??)
         */
        std::string lower_accountname = flags->samAccountName_nodollar;
        for(std::string::iterator it = lower_accountname.begin();
            it != lower_accountname.end(); ++it)
            *it = std::tolower(*it);

        salt = sform("%shost%s.%s", flags->realm_name.c_str(), lower_accountname.c_str(), flags->lower_realm_name.c_str());

        VERBOSE("    Using salt of %s", salt.c_str());
        KRB5Keyblock keyblock;

        keyblock.from_string(static_cast<krb5_enctype>(enc_types[i]), flags->password, salt);

        VERBOSE("  Adding entry of enctype 0x%x", enc_types[i]);
        keytab.addEntry(princ, kvno, keyblock);
    }

    return 0;
}
