/*
 *----------------------------------------------------------------------------
 *
 * krb5wrap.cpp
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

#ifdef HEIMDAL
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

KRB5Context::KRB5Context() {
    VERBOSE("Creating Kerberos Context");
    krb5_error_code ret = krb5_init_context(&m_context);
    if (ret)
        throw KRB5Exception("krb5_init_context", ret);
}

KRB5Context::~KRB5Context() {
    VERBOSE("Destroying Kerberos Context");
    krb5_free_context(m_context);
}

void KRB5Context::reload() {
    VERBOSE("Reloading Kerberos Context");
    krb5_free_context(m_context);
    krb5_error_code ret = krb5_init_context(&m_context);
    if (ret)
        throw KRB5Exception("krb5_init_context", ret);
}

void KRB5Keyblock::from_string(krb5_enctype enctype, const std::string &password, const std::string &salt) {
#ifdef HEIMDAL
    krb5_data pass_data;
    krb5_salt salt_data;

    salt_data.salttype = KRB5_PW_SALT;
    salt_data.saltvalue.data = const_cast<char *>(salt.c_str());
    salt_data.saltvalue.length = salt.length();

    pass_data.data = const_cast<char *>(password.c_str());
    pass_data.length = password.length();

    krb5_error_code ret = krb5_string_to_key_data_salt(g_context.get(), enctype,
                                                       pass_data, salt_data, &m_keyblock);
    if (ret)
        throw KRB5Exception("krb5_string_to_key_data_salt", ret);
#else
    krb5_data salt_data, pass_data;
    salt_data.data = const_cast<char *>(salt.c_str());
    salt_data.length = salt.length();

    pass_data.data = const_cast<char *>(password.c_str());
    pass_data.length = password.length();

    krb5_error_code ret = krb5_c_string_to_key(g_context.get(), enctype,
                                               &pass_data, &salt_data, &m_keyblock);
    if (ret)
        throw KRB5Exception("krb5_c_string_to_key", ret);
#endif
}

void KRB5CCache::initialize(KRB5Principal &principal) {
    krb5_error_code ret = krb5_cc_initialize(g_context.get(), m_ccache, principal.get());
    if (ret)
        throw KRB5Exception("krb5_cc_initialize", ret);
}

void KRB5CCache::store(KRB5Creds &creds) {
    krb5_error_code ret = krb5_cc_store_cred(g_context.get(), m_ccache, creds.get());
    if (ret)
        throw KRB5Exception("krb5_cc_store_cred", ret);
}

KRB5Creds::KRB5Creds(KRB5Principal &principal, KRB5Keytab &keytab, const char *tkt_service) : m_creds() {
    krb5_error_code ret =
        krb5_get_init_creds_keytab(g_context.get(), &m_creds, principal.get(), keytab.get(), 0, const_cast<char*>(tkt_service), NULL);
    if (ret)
        throw KRB5Exception("krb5_get_init_creds_keytab", ret);
}

KRB5Creds::KRB5Creds(KRB5Principal &principal, const std::string &password, const char *tkt_service) : m_creds() {
    krb5_error_code ret =
        krb5_get_init_creds_password(g_context.get(), &m_creds, principal.get(),
                                     const_cast<char*>(password.c_str()), NULL, NULL,
                                     0, const_cast<char*>(tkt_service), NULL);
    if (ret)
        throw KRB5Exception("krb5_get_init_creds_keytab", ret);
}


std::string KRB5Principal::name() {
    char *principal_string;
    krb5_error_code ret = krb5_unparse_name(g_context.get(), m_princ, &principal_string);
    if (ret)
        throw KRB5Exception("krb5_unparse_name", ret);

    std::string result(principal_string);

#ifdef HEIMDAL
    krb5_xfree(principal_string);
#else
    krb5_free_unparsed_name(g_context.get(), principal_string);
#endif

    return result;
}

void KRB5Keytab::addEntry(KRB5Principal &princ, krb5_kvno kvno, KRB5Keyblock &keyblock) {
    krb5_keytab_entry entry;

    entry.principal = princ.get();
    entry.vno = kvno;
#ifdef HEIMDAL
    entry.keyblock = keyblock.get();
#else
    entry.key = keyblock.get();
#endif
    krb5_error_code ret = krb5_kt_add_entry(g_context.get(), m_keytab, &entry);
    if (ret)
        throw KRB5Exception("krb5_kt_add_entry", ret);
}

void KRB5Keytab::removeEntry(KRB5Principal &princ, krb5_kvno kvno, krb5_enctype enctype) {
    krb5_keytab_entry entry;

    entry.principal = princ.get();
    entry.vno = kvno;
#ifdef HEIMDAL
    entry.keyblock.keytype = enctype;
#else
    entry.key.enctype = enctype;
#endif

    krb5_error_code ret = krb5_kt_remove_entry(g_context.get(), m_keytab, &entry);
    if (ret)
        throw KRB5Exception("krb5_kt_remove_entry", ret);
}

KRB5Keytab::cursor::cursor(KRB5Keytab &keytab) : m_keytab(keytab), m_cursor(), m_entry(), m_princ() {
    krb5_error_code ret = krb5_kt_start_seq_get(g_context.get(), m_keytab.m_keytab, &m_cursor);
    if (ret)
        throw KRB5Exception("krb5_kt_start_seq_get", ret);
}

KRB5Keytab::cursor::~cursor() {
    krb5_free_keytab_entry_contents(g_context.get(), &m_entry);
    memset(&m_entry, 0, sizeof(m_entry));
    // Tell m_princ to not free its contents!
    m_princ.reset_no_free(NULL);
    krb5_error_code ret = krb5_kt_end_seq_get(g_context.get(), m_keytab.m_keytab, &m_cursor);
    if (ret)
        // FIXME: shouldn't throw from destructor...
        throw KRB5Exception("krb5_kt_end_seq_get", ret);
}

bool KRB5Keytab::cursor::next() {
    krb5_free_keytab_entry_contents(g_context.get(), &m_entry);
    memset(&m_entry, 0, sizeof(m_entry));
    krb5_error_code ret = krb5_kt_next_entry(g_context.get(), m_keytab.m_keytab, &m_entry, &m_cursor);
    m_princ.reset_no_free(m_entry.principal);
    return ret == 0;
}

// GLOBAL:
KRB5Context g_context;
