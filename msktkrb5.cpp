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

/* The full set of krb5_enctype values msDs-supportedEncryptionTypes can
 * express, paired with their AD bitmask bit. This is the only place
 * that maps between the two numbering schemes; krb5_string_to_enctype()/
 * krb5_enctype_to_name() (krb5wrap.h) handle the string<->krb5_enctype
 * side, so this table only needs to go one level further, to the AD
 * bit. Every AES entry (SHA1-96 and SHA2 alike) is only ever included
 * on a build whose krb5.h actually declares the corresponding
 * ENCTYPE_... macro (HAVE_DECL_ENCTYPE_... from configure.ac). */
static const struct {
    krb5_enctype enctype;
    unsigned int ad_bit;
} ms_kerb_enctype_table[] = {
    { ENCTYPE_DES_CBC_CRC,  MS_KERB_ENCTYPE_DES_CBC_CRC },
    { ENCTYPE_DES_CBC_MD5,  MS_KERB_ENCTYPE_DES_CBC_MD5 },
    { ENCTYPE_ARCFOUR_HMAC, MS_KERB_ENCTYPE_RC4_HMAC_MD5 },
#if HAVE_DECL_ENCTYPE_AES128_CTS_HMAC_SHA1_96
    { ENCTYPE_AES128_CTS_HMAC_SHA1_96, MS_KERB_ENCTYPE_AES128_CTC_HMAC_SHA1_96 },
#endif
#if HAVE_DECL_ENCTYPE_AES256_CTS_HMAC_SHA1_96
    { ENCTYPE_AES256_CTS_HMAC_SHA1_96, MS_KERB_ENCTYPE_AES256_CTS_HMAC_SHA1_96 },
#endif
#if HAVE_DECL_ENCTYPE_AES128_CTS_HMAC_SHA256_128
    { ENCTYPE_AES128_CTS_HMAC_SHA256_128, MS_KERB_ENCTYPE_AES128_CTS_HMAC_SHA256_128 },
#endif
#if HAVE_DECL_ENCTYPE_AES256_CTS_HMAC_SHA384_192
    { ENCTYPE_AES256_CTS_HMAC_SHA384_192, MS_KERB_ENCTYPE_AES256_CTS_HMAC_SHA384_192 },
#endif
};

static const size_t ms_kerb_enctype_table_len =
    sizeof(ms_kerb_enctype_table) / sizeof(ms_kerb_enctype_table[0]);

/* AD bit for <enctype>, or 0 if <enctype> has no msDs-supportedEncryptionTypes
 * representation at all (e.g. it's not one of the types AD/the KDC can
 * express there, such as des3 or camellia). */
unsigned int ad_bit_for_enctype(krb5_enctype enctype)
{
    for (size_t i = 0; i < ms_kerb_enctype_table_len; i++) {
        if (ms_kerb_enctype_table[i].enctype == enctype) {
            return ms_kerb_enctype_table[i].ad_bit;
        }
    }
    return 0;
}

/* Every krb5_enctype with an msDs-supportedEncryptionTypes bit, for
 * iterating in the other direction (AD bit -> enctype), e.g. to list
 * or translate an entire AD bitmask. */
std::vector<krb5_enctype> ms_kerb_enctypes()
{
    std::vector<krb5_enctype> result;
    for (size_t i = 0; i < ms_kerb_enctype_table_len; i++) {
        result.push_back(ms_kerb_enctype_table[i].enctype);
    }
    return result;
}

/* Returns the subset of bits in ms_enctypes (an msDs-supportedEncryptionTypes
 * style AD bitmask) for which the linked Kerberos library cannot actually
 * derive a key. Returns 0 if every requested enctype is usable. */
unsigned int unsupported_ms_kerb_enctypes(unsigned int ms_enctypes)
{
    unsigned int unsupported = 0;

    for (size_t i = 0; i < ms_kerb_enctype_table_len; i++) {
        unsigned int ad_bit = ms_kerb_enctype_table[i].ad_bit;
        if ((ms_enctypes & ad_bit) &&
            !enctype_supported(ms_kerb_enctype_table[i].enctype)) {
            unsupported |= ad_bit;
        }
    }

    return unsupported;
}

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

            /* Only the part before the realm/suffix is used for
             * salting, whether the UPN is classic (user@REALM) or
             * enterprise (user@othersuffix) */
            size_t pos = upnsalt.find('@');
            if (pos != std::string::npos)
                upnsalt.erase(pos);

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


/* Returns every principal (sAMAccountName, its uppercase variant for
 * machine accounts, userPrincipalName, and every servicePrincipalName)
 * currently assigned to this account, i.e. every principal whose
 * keytab entries belong to it. Mirrors the enumeration update_keytab()
 * uses to add entries, so it stays in sync with what "this account's
 * principals" actually means for both machine and service accounts. */
std::vector<std::string> get_account_principals(msktutil_flags *flags)
{
    std::vector<std::string> principals;

    principals.push_back(flags->sAMAccountName);
    if (!flags->use_service_account) {
        principals.push_back(flags->sAMAccountName_uppercase);
    }
    if (!flags->userPrincipalName.empty()) {
        principals.push_back(flags->userPrincipalName);
    }
    for (size_t i = 0; i < flags->ad_principals.size(); ++i) {
        principals.push_back(flags->ad_principals[i]);
    }

    return principals;
}


/* Returns the baseline principal set "flush" resets the account back
 * down to: sAMAccountName (+ uppercase for a machine account), plus,
 * for a machine account only, the default host SPN for both the
 * short and fully-qualified hostname (a service account has no
 * default SPN at all) -- host/<hostname> in particular is what lets
 * other clients reach this machine over Kerberos at all, so it must
 * survive a flush, not just the account's own ability to authenticate
 * as itself. The current userPrincipalName, if any, is also kept:
 * msktutil has no record of whether a UPN already existed on the
 * account before it was ever touched, so it can't safely be treated
 * as "not part of the baseline" and removed. */
std::vector<std::string> get_default_account_principals(msktutil_flags *flags)
{
    std::vector<std::string> principals;

    principals.push_back(flags->sAMAccountName);
    if (!flags->use_service_account) {
        principals.push_back(flags->sAMAccountName_uppercase);

        std::vector<std::string> host_spns;
        host_spns.push_back("host");
        qualify_principal_vec(host_spns, flags);
        for (size_t i = 0; i < host_spns.size(); ++i) {
            principals.push_back(host_spns[i]);
        }
    }
    if (!flags->userPrincipalName.empty()) {
        principals.push_back(flags->userPrincipalName);
    }

    return principals;
}


/* Returns every distinct, qualified principal name physically present
 * in the local keytab, deduplicated across kvnos/enctypes. */
std::vector<std::string> get_keytab_principals(msktutil_flags *flags)
{
    KRB5Keytab keytab(flags->keytab_writename);
    std::vector<std::string> principals;

    for (KRB5Keytab::cursor cursor(keytab); cursor.next(); ) {
        std::string name = cursor.principal().name();
        if (std::find(principals.begin(), principals.end(), name) ==
                principals.end()) {
            principals.push_back(name);
        }
    }

    return principals;
}


/* Determines the realm-qualified form of a bare principal <name_arg>
 * and whether it needs enterprise-principal parsing -- shared by every
 * caller that builds a KRB5Principal from a bare SPN/UPN, so this
 * classification only lives in one place. Service principals always
 * contain a '/' and are never qualified with a realm/suffix of their
 * own; they must be parsed in classic mode so '/' keeps separating the
 * service and instance components. Only a bare userPrincipalName can
 * be an enterprise principal (a UPN whose suffix differs from the
 * local realm), identified by containing an '@' that doesn't match
 * is_in_realm(). */
static std::string qualify_principal_name(
    const std::string &name_arg, msktutil_flags *flags, bool *eupn_out)
{
    std::string name = normalize_host_spn(name_arg);
    bool is_spn = (name.find('/') != std::string::npos);
    bool in_realm = is_in_realm(name, flags);
    *eupn_out = !is_spn && !in_realm && (name.find('@') != std::string::npos);

    return in_realm ? name : name + "@" + flags->realm_name;
}


/* Builds the comparable (and, for an enterprise principal, correctly
 * escaped) qualified form of each name in <names> -- shared so that
 * every caller matching bare principal names against actual
 * keytab/krb5 principal names stays in sync with that logic. */
static std::vector<std::string> qualify_principal_names(
    const std::vector<std::string> &names, msktutil_flags *flags)
{
    std::vector<std::string> qualified_names;

    for (size_t i = 0; i < names.size(); ++i) {
        bool eupn;
        std::string qualified = qualify_principal_name(names[i], flags, &eupn);
        qualified_names.push_back(KRB5Principal(qualified, eupn).name());
    }

    return qualified_names;
}


/* Returns every entry in <principals> that doesn't also appear in
 * <baseline>, case-sensitively (matching how the keytab/AD itself
 * store these names). */
static std::vector<std::string> subtract_principals(
    const std::vector<std::string> &principals,
    const std::vector<std::string> &baseline)
{
    std::vector<std::string> result;

    for (size_t i = 0; i < principals.size(); ++i) {
        bool in_baseline = false;
        for (size_t j = 0; j < baseline.size(); ++j) {
            if (principals[i] == baseline[j]) {
                in_baseline = true;
                break;
            }
        }
        if (!in_baseline) {
            result.push_back(principals[i]);
        }
    }

    return result;
}


int flush_keytab(msktutil_flags *flags)
{
    VERBOSE("Flushing the keytab");

    std::vector<std::string> to_remove = subtract_principals(
        get_account_principals(flags),
        get_default_account_principals(flags));

    remove_keytab_entries(flags, to_remove);

    return ldap_flush_principals(flags, get_default_account_principals(flags));
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
     * principal, but then there's no way to get rid of truly obsolete
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


/* Removes every keytab entry whose (already qualified) principal name
 * appears in <remove_principal_names>, independent of kvno/enctype. */
static void remove_keytab_entries_qualified(
    msktutil_flags *flags, const std::vector<std::string> &remove_principal_names)
{
    KRB5Keytab keytab(flags->keytab_writename);

    std::vector<KRB5KeytabEntry> keytab_entries;

    /* Extract a vector of keytab entries */
    for (KRB5Keytab::cursor cursor(keytab); cursor.next(); ) {
        keytab_entries.push_back(cursor);
    }

    for (std::vector<KRB5KeytabEntry>::iterator it = keytab_entries.begin(); it != keytab_entries.end(); it++) {
        KRB5Principal principal(it->principal());
        std::string principal_name(principal.name());
        for (size_t i = 0; i < remove_principal_names.size(); ++i) {
            if (principal_name.compare(remove_principal_names[i]) == 0) {
                VERBOSE("Deleting %s (kvno=%d, enctype=%d) from keytab", principal.name().c_str(), it->kvno(), it->enctype());
                keytab.removeEntry(principal, it->kvno(), it->enctype());
            }
        }
    }
}


void remove_keytab_entries(msktutil_flags *flags,
                                   std::vector<std::string> remove_principals)
{
    VERBOSE("Trying to remove entries for %s from keytab", flags->sAMAccountName.c_str());

    /* Build the comparable (and, for an enterprise principal,
     * correctly escaped) form of each name to remove once, so the
     * comparison below is exact regardless of whether a principal is
     * a bare SPN, a classic UPN, or an enterprise UPN. */
    std::vector<std::string> remove_principal_names =
        qualify_principal_names(remove_principals, flags);

    remove_keytab_entries_qualified(flags, remove_principal_names);
}


/* Removes every keytab entry whose principal isn't currently known to
 * this account in AD (sAMAccountName, its uppercase variant,
 * userPrincipalName, or any current servicePrincipalName) -- e.g. an
 * SPN removed from AD out-of-band (ADUC, another tool) rather than via
 * --remove-service, which would otherwise sit in the keytab forever:
 * never revisited by add_principal_keytab()/prune_keytab() since it no
 * longer appears in flags->ad_principals, regardless of how much time
 * passes or how many password rotations happen. Comparison is by
 * qualified principal name only, independent of kvno, so this also
 * catches entries left over from a since-deleted-and-recreated account
 * that happened not to collide on kvno with the current one. */
void remove_unknown_keytab_entries(msktutil_flags *flags)
{
    VERBOSE("Trying to remove unknown entries for %s from keytab",
            flags->sAMAccountName.c_str());

    std::vector<std::string> known_qualified =
        qualify_principal_names(get_account_principals(flags), flags);
    std::vector<std::string> in_keytab = get_keytab_principals(flags);
    std::vector<std::string> unknown =
        subtract_principals(in_keytab, known_qualified);

    remove_keytab_entries_qualified(flags, unknown);
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
                /* Matching entry already present for this kvno and enctype */
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

void add_principal_keytab(const std::string &principal_arg, msktutil_flags *flags)
{
    bool eupn;
    std::string principal_string =
        qualify_principal_name(principal_arg, flags, &eupn);

    VERBOSE("Adding principal to keytab: %s", principal_string.c_str());
    VERBOSE("Using supportedEncryptionTypes: %d", flags->ad_supportedEncryptionTypes);

    /* FIXME: Why do we use a fixed magic number instead of reusing
     * flags->cleanup_days for update as well? */
    krb5_timestamp min_keep_timestamp = time(NULL) - (7*24*60*60);
    KRB5Principal princ(principal_string, eupn);

    KRB5Keytab keytab(flags->keytab_writename);
    prune_keytab(keytab, princ, min_keep_timestamp);

    std::vector<int32_t> enc_types;
    std::vector<krb5_enctype> all_ms_kerb_enctypes = ms_kerb_enctypes();
    for (size_t i = 0; i < all_ms_kerb_enctypes.size(); i++) {
        if (flags->ad_supportedEncryptionTypes &
            ad_bit_for_enctype(all_ms_kerb_enctypes[i])) {
            enc_types.push_back(all_ms_kerb_enctypes[i]);
        }
    }

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
