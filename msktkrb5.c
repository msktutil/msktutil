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
#include <iostream>

#ifdef HEIMDAL
krb5_error_code krb5_free_unparsed_name(krb5_context context, void *buffer)
{
    if (buffer) {
        free(buffer);
    }
    return 0;
}


krb5_error_code krb5_free_keytab_entry_contents(krb5_context context, krb5_keytab_entry *entry)
{
    if (entry) {
        krb5_free_principal(context, entry->principal);
        if (entry->keyblock.keyvalue.data) {
            memset(entry->keyblock.keyvalue.data, 0, entry->keyblock.keyvalue.length);
            free(entry->keyblock.keyvalue.data);
        }
        return 0;
    }
    return -1;
}
#endif


std::string get_user_principal()
{
    int ret;
    krb5_ccache ccache;


    VERBOSE("Obtaining Principal for the executing user");
    ret = krb5_cc_default(g_context.get(), &ccache);
    if (ret) {
        VERBOSE("krb5_cc_default failed (%s)", error_message(ret));
        return NULL;
    }

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
    principals = ldap_list_principals(flags);
    for (int i = 0; i < principals.size(); ++i) {
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


    ret = ldap_add_principal(principal, flags);
    if (ret) {
        fprintf(stderr, "Error: ldap_add_principal failed\n");
        return ret;
    }

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

    std::vector<krb5_enctype> enc_types;
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

#ifndef HEIMDAL     /* MIT */
    std::string salt;

    for(size_t i = 0; i < enc_types.size(); ++i) {
        /*
         * Windows uses realm_name+"host"+samAccountName_nodollar+"."+lower_realm_name
         * for DES and AES i.e. all except RC4.
         */
        bool self_allocated = false;
        if (kvno != KVNO_WIN_2000 && enc_types[i] != ENCTYPE_ARCFOUR_HMAC) {
            self_allocated = true;
            std::string lower_accountname = flags->samAccountName_nodollar;
            for(std::string::iterator it = lower_accountname.begin();
                it != lower_accountname.end(); ++it)
                *it = std::tolower(*it);

            salt = sform("%shost%s.%s", flags->realm_name.c_str(), lower_accountname.c_str(), flags->lower_realm_name.c_str());
        } else {
            krb5_data krb5salt;
            ret = krb5_principal2salt(g_context.get(), princ.get(), &krb5salt);
            if (ret)
                throw KRB5Exception("krb5_principal2salt", ret);
            salt = std::string(krb5salt.data, krb5salt.length);
            krb5_free_data_contents(g_context.get(), &krb5salt);
        }

        VERBOSE("    Using salt of %s", salt.c_str());
        KRB5Keyblock keyblock;

        keyblock.from_string(enc_types[i], flags->password, salt);

        VERBOSE("  Adding entry of enctype 0x%x", enc_types[i]);
        keytab.addEntry(princ, kvno, keyblock);
    }

    return 0;
#else /* HEIMDAL */
    krb5_salt salt;
#error reimplement HEIMDAL support

    salt.saltvalue.data = NULL;
    salt.saltvalue.length = 0;
    for (i = 0; enc_types[i]; i++) {
        /*
         * Windows uses the realm_name+host+samAccountNumber_nodollar+.lower_realm_name
         * For DES and AES i.e. all accept RC4.
         */
        if (kvno != KVNO_WIN_2000 && enc_types[i] != ENCTYPE_ARCFOUR_HMAC) {
            salt.salttype = KRB5_PW_SALT;
            salt.saltvalue.data = malloc((strlen(flags->realm_name) * 2) + strlen(flags->samAccountName_nodollar) + 6);
            if (!salt.saltvalue.data) {
                fprintf(stderr, "Error: malloc failed\n");
                ret = ENOMEM;
                goto error;
            }

            memset(salt.saltvalue.data, 0, (strlen(flags->realm_name) * 2) + strlen(flags->samAccountName_nodollar) + 6);
            sprintf(salt.saltvalue.data, "%shost%s.%s", flags->realm_name, flags->samAccountName_nodollar, flags->lower_realm_name);
            salt.saltvalue.length = strlen(salt.saltvalue.data);
        } else {
            ret = krb5_get_pw_salt(g_context.get(), princ, &salt);
            if (ret) {
                fprintf(stderr, "Error: krb5_get_pw_salt failed (%s)\n", error_message(ret));
                goto error;
            }
        }

        VERBOSE("    Using salt of %s", (char *) salt.saltvalue.data);
        pass.data = flags->password.c_str();
        pass.length = PASSWORD_LEN;
        ret = krb5_string_to_key_data_salt(g_context.get(), enc_types[i], pass, salt, &key);
        if (ret) {
            fprintf(stderr, "Error: krb5_string_to_key_data_salt failed (%s)\n", error_message(ret));
            krb5_free_data_contents(g_context.get(), &salt.saltvalue);
            goto error;
        }
        entry.principal = princ;
        entry.vno = kvno;
        entry.keyblock = key;
        ret = krb5_kt_add_entry(g_context.get(), keytab, &entry);
        VERBOSE("  Adding entry of enctype 0x%x", enc_types[i]);
        krb5_free_data_contents(g_context.get(), &salt.saltvalue);
        krb5_free_keyblock_contents(g_context.get(), &key);
        if (ret) {
            fprintf(stderr, "Error: krb5_kt_add_entry failed (%s)\n", error_message(ret));
            goto error;
        }
        if (salt.saltvalue.data) {
            free(salt.saltvalue.data);
            salt.saltvalue.data = NULL;
        }
    }
error:
    if (salt.saltvalue.data)
        free(salt.saltvalue.data);
    free(enc_types);
    memset(&key, 0, sizeof(krb5_keyblock));
    krb5_free_principal(g_context.get(), princ);
    krb5_kt_close(g_context.get(), keytab);

    return ret;

#endif
}
