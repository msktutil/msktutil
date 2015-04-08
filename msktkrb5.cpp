/*
 *----------------------------------------------------------------------------
 *
 * msktkrb5.cpp
 *
 * (C) 2004-2006 Dan Perry (dperry@pppl.gov)
 * (C) 2006 Brian Elliott Finley (finley@anl.gov)
 * (C) 2009-2010 Doug Engert (deengert@anl.gov)
 * (C) 2010 James Y Knight (foom@fuhm.net)
 * (C) 2010-2013 Ken Dreyer <ktdreyer at ktdreyer.com>
 * (C) 2012-2015 Mark Proehl <mark at mproehl.net>
 * (C) 2012-2015 Olaf Flebbe <of at oflebbe.de>
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
        if (ret) {
            throw KRB5Exception("krb5_kt_default_name (get_default_keytab)", ret);
        }
        flags->keytab_readname = std::string(keytab_name);

#ifdef HEIMDAL
        ret = krb5_kt_default_modify_name(g_context.get(), keytab_name, MAX_KEYTAB_NAME_LEN);
        if (ret) {
            throw KRB5Exception("krb5_kt_default_modify_name (get_default_keytab)", ret);
        }
        flags->keytab_writename = std::string(keytab_name);
#else
        if (!strncmp(keytab_name, "FILE:", 5)) {
            /* Ignore opening FILE: part */
            flags->keytab_writename = "WRFILE:" + std::string(keytab_name + 5);
        } else if (!strncmp(keytab_name, "WRFILE:", 7)) {
            /* Ignore the opening WRFILE: part */
            flags->keytab_writename = std::string(keytab_name);
        } else {
            /* No prefix to the keytab path */
            flags->keytab_writename = "WRFILE:" + std::string(keytab_name);
        }
#endif
        VERBOSE("Obtaining the default keytab name: %s", flags->keytab_readname.c_str());
    } else {
        flags->keytab_writename = "WRFILE:" + flags->keytab_file;
        flags->keytab_readname = "FILE:" + flags->keytab_file;
    }
}


int flush_keytab(msktutil_flags *flags)
{
    VERBOSE("Flushing the keytab");
    KRB5Keytab keytab(flags->keytab_writename);

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


void cleanup_keytab(msktutil_flags *flags)
{
    VERBOSE("Cleaning the keytab");
    KRB5Keytab keytab(flags->keytab_writename);

    // Determine timestamp of newest entries:
    time_t newest_timestamp;
    // Delete all entries for this host
    typedef std::vector<std::pair<std::pair<std::string, krb5_kvno>, krb5_enctype> > to_delete_t;
    to_delete_t to_delete;
    time_t ttNow = time(NULL);
    try {
        newest_timestamp = 0;
        {
            KRB5Keytab::cursor cursor(keytab);
            while (cursor.next()) {
                if (newest_timestamp < cursor.timestamp()) {
                    newest_timestamp = cursor.timestamp();
                }
            }
        }
        KRB5Keytab::cursor cursor(keytab);
        while (cursor.next()) {
            if ((cursor.enctype() == flags->cleanup_enctypes) ||
                ((ttNow - cursor.timestamp() >= flags->cleanup_days * 60 * 60 * 24) &&
                 (flags->cleanup_days != -1) &&
                 (abs(newest_timestamp - cursor.timestamp()) >= 2))) {
                std::string principal = cursor.principal().name();
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
}


void update_keytab(msktutil_flags *flags)
{
    VERBOSE("Updating all entires for %s", flags->samAccountName.c_str());
    //    krb5_kvno kvno = ldap_get_kvno(flags);
    add_principal_keytab(flags->samAccountName, flags);
    if (!flags->use_service_account) {
        add_principal_keytab(flags->samAccountName_uppercase, flags);
    }
    //add upn
    if (!flags->userPrincipalName.empty()) {
        add_principal_keytab(flags->userPrincipalName, flags);
    }
    //add host/sAMAccountNAme
    if (!flags->use_service_account) {
        add_principal_keytab("host/" + flags->samAccountName_nodollar, flags);
    }
    for (size_t i = 0; i < flags->ad_principals.size(); ++i) {
        add_principal_keytab(flags->ad_principals[i], flags);
    }
}


void add_principal_keytab(const std::string &principal, msktutil_flags *flags)
{
    VERBOSE("Adding principal to keytab: %s", principal.c_str());
    KRB5Keytab keytab(flags->keytab_writename);

    std::string principal_string = "";

    if (principal.find("@") != std::string::npos) {
        principal_string = sform("%s", principal.c_str());
    } else {
        principal_string = sform("%s@%s", principal.c_str(), flags->realm_name.c_str());
    }
    KRB5Principal princ(principal_string);

    typedef std::vector<std::pair<std::pair<std::string, krb5_kvno>, krb5_enctype> > to_delete_t;
    to_delete_t to_delete;

    // Delete entries with obsolete kvnos.

    // Keep all old keys with smaller kvnos which could've been used in the last week (a
    // conservative guess for reasonable maximum ticket lifetimes).  That is: if kvno 3 has
    // timestamp Jan 1, 2010, kvno 4 has timestamp Jan 20, 2010, and it is currently Jan 20, 2010,
    // then keep both kvno 3 and 4, while writing out a new kvno 5. This is needed so that users who
    // already have a valid service ticket in their credential cache can continue using it to
    // connect to the server.
    try {
        krb5_kvno earliest_kvno_to_keep = 0;
        {
            krb5_timestamp min_keep_timestamp = time(NULL) - (7*24*60*60);

            KRB5Keytab::cursor cursor(keytab);
            while (cursor.next()) {
                std::string curr_principal = cursor.principal().name();
                if (curr_principal == principal_string) {
                    if (cursor.kvno() < flags->kvno) {
                        if (cursor.timestamp() < min_keep_timestamp) {
                            earliest_kvno_to_keep = std::max(earliest_kvno_to_keep, cursor.kvno());
                        }
                    }
                }
            }
        }
        VERBOSE("Removing entries with kvno < %d", earliest_kvno_to_keep);
        {
            KRB5Keytab::cursor cursor(keytab);
            while (cursor.next()) {
                std::string curr_principal = cursor.principal().name();
                if (curr_principal == principal_string &&
                    (cursor.kvno() >= flags->kvno || cursor.kvno() < earliest_kvno_to_keep)) {
                    to_delete.push_back(std::make_pair(std::make_pair(curr_principal, cursor.kvno()),
                                                       cursor.enctype()));
                }
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
    if (flags->ad_supportedEncryptionTypes & MS_KERB_ENCTYPE_DES_CBC_CRC) {
        enc_types.push_back(ENCTYPE_DES_CBC_CRC);
    }
    if (flags->ad_supportedEncryptionTypes & MS_KERB_ENCTYPE_DES_CBC_MD5) {
        enc_types.push_back(ENCTYPE_DES_CBC_MD5);
    }
    if (flags->ad_supportedEncryptionTypes & MS_KERB_ENCTYPE_RC4_HMAC_MD5) {
        enc_types.push_back(ENCTYPE_ARCFOUR_HMAC);
    }
#if HAVE_DECL_ENCTYPE_AES128_CTS_HMAC_SHA1_96
    if (flags->ad_supportedEncryptionTypes & MS_KERB_ENCTYPE_AES128_CTC_HMAC_SHA1_96) {
        enc_types.push_back(ENCTYPE_AES128_CTS_HMAC_SHA1_96);
    }
#endif
#if HAVE_DECL_ENCTYPE_AES256_CTS_HMAC_SHA1_96
    if (flags->ad_supportedEncryptionTypes & MS_KERB_ENCTYPE_AES256_CTS_HMAC_SHA1_96) {
        enc_types.push_back(ENCTYPE_AES256_CTS_HMAC_SHA1_96);
    }
#endif

    std::string salt;

    for(size_t i = 0; i < enc_types.size(); ++i) {
        /*
         * Windows uses realm_name+"host"+samAccountName_nodollar+"."+lower_realm_name
         * for the salt. (note: only for DES/AES; arcfour-hmac-md5 doesn't use salts at all)
         *
         *     Note (Mark Pr"ohl, 2012-12-11): salt for service accounts is created in a different
         *     way:
         *     - if userPrincpalName is not set: realm_name+samAccountName
         *     - if userPrincpalName is set: realm_name + first component from userPrincpalName
         *
         * Windows 2000 may have used something different, but who cares.
         *
         * FIXME: this is stupid, and not future proof. The salt is supposed to be an implementation
         * detail that the server can set to whatever it feels like (so long as it doesn't change it
         * except when the password changes). A future version of windows may change the salting
         * algorithm to something else, or may even start using random salts.
         *
         * In the normal authentication path, the client asks the KDC what salt to use when
         * encrypting the password for the account, and then uses that. And for the creation of a
         * keytab in MIT kerberos (in the suual case), you use the kadmin protocol to download the
         * already salted key block.
         *
         * But, here, we need to take a password and encrypt it the same way the server is going to,
         * in order to store it in the keytab. All we need is to ask the server what salt it wants
         * to use...But, as far as I can tell, there exists no API in libkrb5 that can retrieve the
         * salt that should be used with a given principal, even though it's clearly available in
         * the network protocol.
         *
         *     Note (Mark Pr"ohl, 2012-12-11): even if the salting string could be fetched from the
         *     network protocol, that would only be possible after the password has been set in AD.
         *     But the keytab entry should be created before that.
         *
         * What we're doing here is very much like MIT kerberos' ktutil addent -password, which also
         * assumes the server uses a particular salt. And that is also broken. Given this email
         * thread: <http://mailman.mit.edu/pipermail/krbdev/2009-July/007835.html>, I hope libkrb5
         * will provide the proper API before MS switches to start using randomized salts in some
         * future AD release.
         */
        std::string lower_accountname = flags->samAccountName_nodollar;
        for(std::string::iterator it = lower_accountname.begin();
            it != lower_accountname.end(); ++it)
            *it = std::tolower(*it);

        if (flags->use_service_account) {

            if (flags->userPrincipalName.empty()) {
                salt = sform("%s%s", flags->realm_name.c_str(), lower_accountname.c_str());
            } else {
                std::string upnsalt = flags->userPrincipalName;
                upnsalt.erase(std::remove(upnsalt.begin(), upnsalt.end(), '/'),upnsalt.end());
                salt = sform("%s%s", flags->realm_name.c_str(), upnsalt.c_str());
            }
        } else {
            salt = sform("%shost%s.%s", flags->realm_name.c_str(), lower_accountname.c_str(),
                                        flags->lower_realm_name.c_str());
        }

        VERBOSE("    Using salt of %s", salt.c_str());
        KRB5Keyblock keyblock;

        keyblock.from_string(static_cast<krb5_enctype>(enc_types[i]), flags->password, salt);

        VERBOSE("  Adding entry of enctype 0x%x", enc_types[i]);
        keytab.addEntry(princ, flags->kvno, keyblock);
    }
}
