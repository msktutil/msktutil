/*
 *----------------------------------------------------------------------------
 *
 * krb5wrap.cpp
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

void krb5_error_exit( const char *func, int err_code) {
   v_error_exit("error_exit: krb func %s failed: (%s)", func, error_message(err_code));
}

void krb5_warn( const char *func, int err_code) {
   fprintf( stderr, "Warning: krb func %s failed: (%s)", func, error_message(err_code));
}

#ifdef HEIMDAL
krb5_error_code krb5_free_keytab_entry_contents(krb5_context context,
                                                krb5_keytab_entry *entry)
{
    if (entry) {
        krb5_free_principal(context, entry->principal);
        if (entry->keyblock.keyvalue.data) {
            memset(entry->keyblock.keyvalue.data,
                   0,
                   entry->keyblock.keyvalue.length);
            free(entry->keyblock.keyvalue.data);
        }
        return 0;
    }
    return -1;
}
#endif

void
initialize_g_context() {
    VERBOSE("Creating Kerberos Context");
    krb5_error_code ret = krb5_init_context(&g_context);
    if (ret) {
        krb5_error_exit("krb5_init_context", ret);
    }
}

void
destroy_g_context() {
    VERBOSE("Destroying Kerberos Context");
    krb5_free_context(g_context);
    g_context = 0;
}


void KRB5Keyblock::from_string(krb5_enctype enctype,
                               const std::string &password,
                               const std::string &salt)
{
#ifdef HEIMDAL
    krb5_data pass_data;
    krb5_salt salt_data;

    salt_data.salttype = KRB5_PW_SALT;
    salt_data.saltvalue.data = const_cast<char *>(salt.c_str());
    salt_data.saltvalue.length = salt.length();

    pass_data.data = const_cast<char *>(password.c_str());
    pass_data.length = password.length();

    krb5_error_code ret = krb5_string_to_key_data_salt(g_context,
                                                       enctype,
                                                       pass_data,
                                                       salt_data,
                                                       &m_keyblock);
    if (ret) {
        throw KRB5Exception("krb5_string_to_key_data_salt", ret);
    }
#else
    krb5_data salt_data, pass_data;
    salt_data.data = const_cast<char *>(salt.c_str());
    salt_data.length = salt.length();

    pass_data.data = const_cast<char *>(password.c_str());
    pass_data.length = password.length();

    krb5_error_code ret = krb5_c_string_to_key(g_context,
                                               enctype,
                                               &pass_data,
                                               &salt_data,
                                               &m_keyblock);
    if (ret) {
        throw KRB5Exception("krb5_c_string_to_key", ret);
    }
#endif
}


void KRB5Keyblock::from_keyblock(krb5_keyblock keyblock)
{

    krb5_error_code ret = krb5_copy_keyblock_contents(g_context, &keyblock, &m_keyblock);

    if (ret) {
        throw KRB5Exception("krb5_copy_keyblock_contents", ret);
    }
}


void KRB5CCache::initialize(KRB5Principal &principal)
{
    krb5_error_code ret = krb5_cc_initialize(g_context,
                                             m_ccache,
                                             principal.get());
    if (ret) {
        throw KRB5Exception("krb5_cc_initialize", ret);
    }
}


void KRB5CCache::store(KRB5Creds &creds)
{
    krb5_error_code ret = krb5_cc_store_cred(g_context,
                                             m_ccache,
                                             creds.get());
    if (ret) {
        throw KRB5Exception("krb5_cc_store_cred", ret);
    }
}


KRB5Creds::KRB5Creds(KRB5Principal &principal,
                     KRB5Keytab &keytab,
                     const char *tkt_service) : m_creds()
{
    krb5_error_code ret =
        krb5_get_init_creds_keytab(g_context,
                                   &m_creds,
                                   principal.get(),
                                   keytab.get(),
                                   0,
                                   const_cast<char*>(tkt_service), NULL);
    if (ret) {
        throw KRB5Exception("krb5_get_init_creds_keytab", ret);
    }
}


KRB5Creds::KRB5Creds(KRB5Principal &principal,
                     const std::string &password,
                     const char *tkt_service) : m_creds()
{
    krb5_error_code ret =
        krb5_get_init_creds_password(g_context,
                                     &m_creds,
                                     principal.get(),
                                     const_cast<char*>(password.c_str()),
                                     NULL,
                                     NULL,
                                     0,
                                     const_cast<char*>(tkt_service),
                                     NULL);
    if (ret) {
        throw KRB5Exception("krb5_get_init_creds_keytab", ret);
    }
}


std::string KRB5Principal::name()
{
    char *principal_string;
    krb5_error_code ret = krb5_unparse_name(g_context,
                                            m_princ,
                                            &principal_string);
    if (ret) {
        throw KRB5Exception("krb5_unparse_name", ret);
    }

    std::string result(principal_string);

#ifdef HEIMDAL
    krb5_xfree(principal_string);
#else
    krb5_free_unparsed_name(g_context, principal_string);
#endif

    return result;
}


void KRB5Keytab::addEntry(const KRB5Principal &princ,
                          krb5_kvno kvno,
                          KRB5Keyblock &keyblock)
{
    krb5_keytab_entry entry;

    entry.principal = princ.get();
    entry.vno = kvno;
#ifdef HEIMDAL
    entry.keyblock = keyblock.get();
#else
    entry.key = keyblock.get();
#endif
    krb5_error_code ret = krb5_kt_add_entry(g_context,
                                            m_keytab,
                                            &entry);
    if (ret) {
        if (errno != 0) {
            fprintf(stderr,"Error: Keytab write error: %s!\n", strerror(errno));
        }
        throw KRB5Exception("krb5_kt_add_entry failed", ret);
    }
}


void KRB5Keytab::removeEntry(const KRB5Principal &princ,
                             krb5_kvno kvno,
                             krb5_enctype enctype)
{
    krb5_keytab_entry entry;

    entry.principal = princ.get();
    entry.vno = kvno;
#ifdef HEIMDAL
    entry.keyblock.keytype = enctype;
#else
    entry.key.enctype = enctype;
#endif

    krb5_error_code ret = krb5_kt_remove_entry(g_context,
                                               m_keytab,
                                               &entry);
    if (ret) {
        if (errno != 0) {
            fprintf(stderr,"Error: Keytab write error: %s!\n", strerror(errno));
        }
        throw KRB5Exception("krb5_kt_remove_entry", ret);
    }
}


KRB5Keytab::cursor::cursor(KRB5Keytab &keytab) : m_keytab(keytab),
                                                 m_cursor(),
                                                 m_entry(),
                                                 m_princ(),
                                                 m_ok(true)
{
    memset(&m_entry, 0, sizeof(m_entry));

    krb5_error_code ret = krb5_kt_start_seq_get(g_context,
                                                m_keytab.m_keytab,
                                                &m_cursor);
    if (ret) {
        m_ok = false;
    }
}


KRB5Keytab::cursor::~cursor()
{
    if (!m_ok) {
        m_princ.reset_no_free(NULL);
        return;
    }
    krb5_free_keytab_entry_contents(g_context, &m_entry);
    memset(&m_entry, 0, sizeof(m_entry));
    /* Tell m_princ to not free its contents! */
    m_princ.reset_no_free(NULL);
    krb5_error_code ret = krb5_kt_end_seq_get(g_context,
                                              m_keytab.m_keytab,
                                              &m_cursor);
    if (ret) {
        krb5_warn("krb5_kt_end_seq_get", ret);
    }
}

void KRB5Keytab::cursor::reset()
{
    if (!m_ok) {
        return;
    }
    krb5_error_code ret = krb5_kt_start_seq_get(g_context,
                                                m_keytab.m_keytab,
                                                &m_cursor);
    if (ret) {
        m_ok = false;
    }
}

bool KRB5Keytab::cursor::next()
{
    if (!m_ok) {
        return false;
    }
    krb5_free_keytab_entry_contents(g_context, &m_entry);
    memset(&m_entry, 0, sizeof(m_entry));
    krb5_error_code ret = krb5_kt_next_entry(g_context,
                                             m_keytab.m_keytab,
                                             &m_entry,
                                             &m_cursor);
    m_princ.reset_no_free(m_entry.principal);
    return ret == 0;
}

krb5_context g_context = NULL;
