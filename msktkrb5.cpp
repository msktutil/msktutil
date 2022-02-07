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
#include <cctype>
#include <algorithm>

void get_default_keytab(msktutil_flags *flags)
{
    char keytab_name[MAX_KEYTAB_NAME_LEN];

    if (flags->keytab_file.empty()) {
        /* Only set the field to a default if it's empty */

        krb5_error_code ret = krb5_kt_default_name(g_context,
                                                   keytab_name,
                                                   MAX_KEYTAB_NAME_LEN);
        if (ret) {
            throw KRB5Exception("krb5_kt_default_name (get_default_keytab)",
                                ret);
        }
        flags->keytab_readname = std::string(keytab_name);

#ifdef HEIMDAL
        ret = krb5_kt_default_modify_name(g_context,
                                          keytab_name,
                                          MAX_KEYTAB_NAME_LEN);
        if (ret) {
            throw KRB5Exception("krb5_kt_default_modify_name "
                                "(get_default_keytab)",
                                ret);
        }
        flags->keytab_writename = std::string(keytab_name);
        if (!strncmp(keytab_name, "FILE:", 5)) {
            /* Ignore opening FILE: part */
            flags->keytab_file = std::string(keytab_name + 5);
        } else {
            /* untyped or unsupported--just try to use it as
             * a filename for now */
            flags->keytab_file = std::string(keytab_name);
        }
#else
        if (!strncmp(keytab_name, "FILE:", 5)) {
            /* Ignore opening FILE: part */
            flags->keytab_writename = "WRFILE:" + std::string(keytab_name + 5);
        } else if (!strncmp(keytab_name, "WRFILE:", 7)) {
            /* Already includes the opening WRFILE: part */
            flags->keytab_writename = std::string(keytab_name);
        } else {
            /* No prefix to the keytab path */
            flags->keytab_writename = "WRFILE:" + std::string(keytab_name);
        }

        /* Ignore opening WRFILE: part */
        flags->keytab_file = flags->keytab_writename.substr(7);
#endif
        VERBOSE("Obtaining the default keytab name: %s",
                flags->keytab_readname.c_str());
    } else {
        flags->keytab_writename = "WRFILE:" + flags->keytab_file;
        flags->keytab_readname = "FILE:" + flags->keytab_file;
    }
}

/* Salt creation -- see windows-salt.txt */
std::string get_salt(msktutil_flags *flags)
{
    std::string salt;
    if (flags->use_service_account) {
        if (flags->userPrincipalName.empty()) {
            salt = sform("%s%s",
                         flags->realm_name.c_str(),
                         flags->sAMAccountName.c_str());
        } else {
            std::string upnsalt = flags->userPrincipalName;
            upnsalt.erase(std::remove(upnsalt.begin(),
                                      upnsalt.end(),
                                      '/'),
                          upnsalt.end());
            salt = sform("%s%s",
                         flags->realm_name.c_str(),
                         upnsalt.c_str());
        }
    } else {

        std::string lower_accountname = flags->sAMAccountName_nodollar;
        for(std::string::iterator it = lower_accountname.begin();
            it != lower_accountname.end(); ++it) {
            *it = std::tolower(*it);
        }
        salt = sform("%shost%s.%s",
                     flags->realm_name.c_str(),
                     lower_accountname.c_str(),
                     flags->lower_realm_name.c_str());
    }
    VERBOSE("Using salt: %s", salt.c_str());
    return(salt);
}


int flush_keytab(msktutil_flags *flags)
{
    VERBOSE("Flushing the keytab");
    KRB5Keytab keytab(flags->keytab_writename);

    std::vector<KRB5KeytabEntry> keytab_entries;

    /* Extract a vector of keytab entries */
    for (KRB5Keytab::cursor cursor(keytab); cursor.next(); ) {
        keytab_entries.push_back(cursor);
    }

    for (std::vector<KRB5KeytabEntry>::iterator it = keytab_entries.begin(); it != keytab_entries.end(); it++) {
        KRB5Principal principal(it->principal());
        std::string principal_name(principal.name());
        size_t first_chr = principal_name.find('/') + 1;
        size_t last_chr = principal_name.rfind('@');

        std::string host = principal_name.substr(first_chr,
                                                 last_chr - first_chr);

        if (host != flags->hostname) {
            continue;
        }

        VERBOSE("Deleting %s (kvno=%d, enctype=%d) from keytab", principal_name.c_str(), it->kvno(), it->enctype());
        keytab.removeEntry(principal, it->kvno(), it->enctype());
    }

    return ldap_flush_principals(flags);
}


void cleanup_keytab(msktutil_flags *flags)
{
    VERBOSE("Cleaning the keytab");
    KRB5Keytab keytab(flags->keytab_writename);

    std::vector<KRB5KeytabEntry> keytab_entries;

    /* Extract a vector of keytab entries */
    for (KRB5Keytab::cursor cursor(keytab); cursor.next(); ) {
        keytab_entries.push_back(cursor);
    }

    /* cleanup all entries that match --remove-enctype */
    for (std::vector<KRB5KeytabEntry>::iterator it = keytab_entries.begin(); it != keytab_entries.end(); it++) {
        if (it->enctype() != flags->cleanup_enctype) {
            continue;
        }
        KRB5Principal principal(it->principal());
        VERBOSE("Deleting %s with kvno=%d, enctype=%d from keytab", principal.name().c_str(), it->kvno(), it->enctype());
        keytab.removeEntry(principal, it->kvno(), it->enctype());
    }

    /* stop further processing unless --remove-old was given */
    if (flags->cleanup_days == -1) {
        return;
    }

    /* Sort vector by timestamp in descending order */
    std::sort(keytab_entries.rbegin(), keytab_entries.rend());

    std::vector<KRB5KeytabEntry>::iterator it = keytab_entries.begin();

    /* Empty list? Nothing to do */
    if (it == keytab_entries.end())
        return;

    /* kvno of the first (== most recent) entry */
    /* FIXME this will work nicely for multiple principals derived from the
     * same account/password, but what about multiple independent principals
     * within the same keytab? We could run the cleanup separately for each
     * principal, but then there's no way to get rid of truely obsolete
     * principals. */
    krb5_kvno keep_kvno = it->kvno();
    time_t min_keep_timestamp = time(0) - flags->cleanup_days * 60 * 60 * 24;

    for (; it != keytab_entries.end(); it++) {
        if (it->timestamp() > min_keep_timestamp || it->kvno() == keep_kvno) {
            continue;
        }
        KRB5Principal principal(it->principal());
        VERBOSE("Deleting %s (kvno=%d, enctype=%d) from keytab", principal.name().c_str(), it->kvno(), it->enctype());
        keytab.removeEntry(principal, it->kvno(), it->enctype());
    }
}


void remove_keytab_entries(msktutil_flags *flags,
                                   std::vector<std::string> remove_principals)
{
    KRB5Keytab keytab(flags->keytab_writename);

    VERBOSE("Trying to remove entries for %s from keytab", flags->sAMAccountName.c_str());

    std::vector<KRB5KeytabEntry> keytab_entries;

    /* Extract a vector of keytab entries */
    for (KRB5Keytab::cursor cursor(keytab); cursor.next(); ) {
        keytab_entries.push_back(cursor);
    }

    for (std::vector<KRB5KeytabEntry>::iterator it = keytab_entries.begin(); it != keytab_entries.end(); it++) {
        KRB5Principal principal(it->principal());
        std::string principal_name(principal.name());
        for (size_t i = 0; i < remove_principals.size(); ++i) {
            std::string remove_principal = remove_principals[i] + "@" + flags->realm_name;
            if (principal_name.compare(remove_principal) == 0) {
                VERBOSE("Deleting %s (kvno=%d, enctype=%d) from keytab", principal.name().c_str(), it->kvno(), it->enctype());
                keytab.removeEntry(principal, it->kvno(), it->enctype());
            }
        }
    }
}


void add_keytab_entries(msktutil_flags *flags)
{
    KRB5Keytab keytab(flags->keytab_writename);

    VERBOSE("Trying to add missing entries for %s to keytab", flags->sAMAccountName.c_str());

    std::vector<KRB5KeytabEntry> keytab_entries;
    std::vector<KRB5KeytabEntry> sam_entries;

    std::string template_principal = flags->sAMAccountName + "@" + flags->realm_name;

    /* Extract a vector of keytab entries */
    for (KRB5Keytab::cursor cursor(keytab); cursor.next(); ) {
        keytab_entries.push_back(cursor);
        if (cursor.principal().name().compare(template_principal) == 0) {
            sam_entries.push_back(cursor);
        }
    }

    for (size_t i = 0; i < flags->ad_principals.size(); ++i) {
        /* We look at all keytab entries that match the account name
         * and fetch their kvno, enctype and key. If an entry for the
         * principal that needs to be added already exists, we do
         * nothing.  If not, we are adding it by using the fetched keys
         * from the account name entry. Doing it this way we are able
         * to add service principals without changing the account
         * password.
         */
        VERBOSE("Checking if %s needs to be added to keytab", flags->ad_principals[i].c_str());

        std::string add_principal = flags->ad_principals[i] + "@" + flags->realm_name;

        for (std::vector<KRB5KeytabEntry>::iterator sam = sam_entries.begin(); sam != sam_entries.end(); sam++) {
            std::vector<KRB5KeytabEntry>::iterator it = keytab_entries.begin();
            for (; it != keytab_entries.end(); it++) {
                if (sam->kvno() != it->kvno() || sam->enctype() != it->enctype()) {
                    continue;
                }
                if (add_principal.compare(KRB5Principal(it->principal()).name()) == 0) {
                    break;
                }
            }

            if (it != keytab_entries.end()) {
                /* Matching entry already present for this KVNO and enctype */
                continue;
            }

            VERBOSE("Adding %s (kvno=%d, enctype=%d) to keytab", add_principal.c_str(), sam->kvno(), sam->enctype());

            KRB5Principal princ(add_principal);
            krb5_keyblock keyblock(sam->keyblock());
            keytab.addEntry(princ, sam->kvno(), keyblock);
        }
    }
}


void update_keytab(msktutil_flags *flags)
{
    VERBOSE("Updating all entries for %s", flags->sAMAccountName.c_str());
    add_principal_keytab(flags->sAMAccountName, flags);
    if (!flags->use_service_account) {
        add_principal_keytab(flags->sAMAccountName_uppercase, flags);
    }
    /* add upn */
    if (!flags->userPrincipalName.empty()) {
        add_principal_keytab(flags->userPrincipalName, flags);
    }
    for (size_t i = 0; i < flags->ad_principals.size(); ++i) {
        if ((flags->userPrincipalName.empty()) ||
            flags->userPrincipalName.compare(flags->ad_principals[i]) != 0) {
            add_principal_keytab(flags->ad_principals[i], flags);
        } else {
            VERBOSE("Entries for SPN %s have already been added. Skipping ...",
                    flags->ad_principals[i].c_str()
                );
        }
    }
}


static void prune_keytab(KRB5Keytab& keytab, KRB5Principal &principal, krb5_timestamp min_keep_timestamp)
{
    std::vector<KRB5KeytabEntry> keytab_entries;

    /* Extract a vector of keytab entries for this principal */
    for (KRB5Keytab::cursor cursor(keytab); cursor.next(); ) {
        if (cursor.principal().name() != principal.name())
            continue;

        keytab_entries.push_back(cursor);
    }

    /* Sort vector by timestamp in descending order */
    std::sort(keytab_entries.rbegin(), keytab_entries.rend());

    /* Now find the first entry older than min_keep_timestamp */
    std::vector<KRB5KeytabEntry>::iterator it = keytab_entries.begin();

    for (; it != keytab_entries.end(); it++) {
        if (it->timestamp() < min_keep_timestamp)
            break;
    }

    if (it == keytab_entries.end())
        return;

    /* Keys for this kvno may still be valid, but any older entries for
     * different keys (different kvno) have definitely been stale for more
     * than min_keep_timestamp, and can therefore be pruned. */
    krb5_kvno keep_kvno = it->kvno();

    for (; it != keytab_entries.end(); it++) {
        if (it->kvno() == keep_kvno)
            continue;

        KRB5Principal principal(it->principal());
        VERBOSE("Deleting %s (kvno=%d, enctype=%d) from keytab",
                principal.name().c_str(), it->kvno(), it->enctype());
        keytab.removeEntry(principal, it->kvno(), it->enctype());
    }
}

void add_principal_keytab(const std::string &principal, msktutil_flags *flags)
{
    std::string principal_string = "";

    if (principal.find("@") != std::string::npos) {
        principal_string = sform("%s", principal.c_str());
    } else {
        principal_string = sform("%s@%s",
                                 principal.c_str(),
                                 flags->realm_name.c_str());
    }
    VERBOSE("Adding principal to keytab: %s", principal_string.c_str());
    VERBOSE("Using supportedEncryptionTypes: %d", flags->ad_supportedEncryptionTypes);

    /* FIXME: Why do we use a fixed magic number instead of reusing
     * flags->cleanup_days for update as well? */
    krb5_timestamp min_keep_timestamp = time(NULL) - (7*24*60*60);
    KRB5Principal princ(principal_string);

    KRB5Keytab keytab(flags->keytab_writename);
    prune_keytab(keytab, princ, min_keep_timestamp);

    std::vector<int32_t> enc_types;
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
    if (flags->ad_supportedEncryptionTypes &
        MS_KERB_ENCTYPE_AES128_CTC_HMAC_SHA1_96) {
        enc_types.push_back(ENCTYPE_AES128_CTS_HMAC_SHA1_96);
    }
#endif
#if HAVE_DECL_ENCTYPE_AES256_CTS_HMAC_SHA1_96
    if (flags->ad_supportedEncryptionTypes &
        MS_KERB_ENCTYPE_AES256_CTS_HMAC_SHA1_96) {
        enc_types.push_back(ENCTYPE_AES256_CTS_HMAC_SHA1_96);
    }
#endif

    std::string salt = get_salt(flags);
    std::string password = flags->dont_change_password ?
        flags->old_account_password : flags->password;

    if (password.empty()) {
        VERBOSE("No password available, skipping creation "
                "of password-based keytab entries");
    } else {
        for(size_t i = 0; i < enc_types.size(); ++i) {
            VERBOSE("  Adding entry of enctype 0x%x", enc_types[i]);
            keytab.addEntry(princ, flags->kvno,
                            static_cast<krb5_enctype>(enc_types[i]),
                            password, salt);
        }
    }
}
