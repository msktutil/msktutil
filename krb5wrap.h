/*
 *----------------------------------------------------------------------------
 *
 * msktutil.h
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
class KRB5Context {
    krb5_context m_context;

private:
    bool operator=(const KRB5Context other); // not defined
public:
    KRB5Context();
    ~KRB5Context();

    void reload();

    krb5_context &get() { return m_context; }
};

extern KRB5Context g_context;


class KRB5Keyblock {
    krb5_keyblock m_keyblock;

private:
    bool operator=(const KRB5Keyblock other); // not defined
public:
    KRB5Keyblock() : m_keyblock() {}

    void from_string(krb5_enctype enctype, std::string &password, std::string &salt);

    ~KRB5Keyblock() {
        krb5_free_keyblock_contents(g_context.get(), &m_keyblock);
    }

    krb5_keyblock &get() {
        return m_keyblock;
    }
};

class KRB5Principal;

class KRB5Keytab {
    krb5_keytab m_keytab;

private:
    bool operator=(const KRB5Keytab other); // not defined
public:
    KRB5Keytab(std::string &keytab_name) : m_keytab() {
        krb5_error_code ret = krb5_kt_resolve(g_context.get(), keytab_name.c_str(), &m_keytab);
        if (ret)
            throw KRB5Exception("krb5_kt_resolve", ret);
    }

    ~KRB5Keytab() {
        krb5_error_code ret = krb5_kt_close(g_context.get(), m_keytab);
        if (ret)
            // FIXME: shouldn't throw from destructor...
            throw KRB5Exception("krb5_kt_close", ret);
    }

    void addEntry(KRB5Principal &princ, krb5_kvno kvno, KRB5Keyblock &keyblock);
    void removeEntry(KRB5Principal &princ, krb5_kvno kvno, krb5_enctype enctype);

    // Defined below...
    class cursor;
};


class KRB5Principal {
    friend class KRB5Keytab::cursor;

    krb5_principal m_princ;

    KRB5Principal() : m_princ() {}

    void reset_no_free(krb5_principal princ) {
        m_princ = princ;
    }

private:
    bool operator=(const KRB5Principal other); // not defined
public:
    KRB5Principal(krb5_principal princ_raw) : m_princ(princ_raw) {}

    KRB5Principal(krb5_ccache ccache) {
        krb5_error_code ret = krb5_cc_get_principal(g_context.get(), ccache, &m_princ);
        if (ret)
            throw KRB5Exception("krb5_cc_get_principal", ret);
    }

    KRB5Principal(std::string principal_name) {
        krb5_error_code ret = krb5_parse_name(g_context.get(), principal_name.c_str(), &m_princ);
        if (ret)
            throw KRB5Exception("krb5_parse_name", ret);
    }
    ~KRB5Principal() {
        if (m_princ)
            krb5_free_principal(g_context.get(), m_princ);
    }

    krb5_principal get() { return m_princ; }
    std::string name();
};

class KRB5Keytab::cursor {
    KRB5Keytab &m_keytab;
    krb5_kt_cursor m_cursor;
    krb5_keytab_entry m_entry;

    // Duplicates part of entry, but oh well.
    KRB5Principal m_princ;

private:
    bool operator=(const KRB5Keytab::cursor other); // not defined
public:
    cursor(KRB5Keytab &keytab);
    ~cursor();
    bool next();

    KRB5Principal &principal() { return m_princ; }
    krb5_kvno kvno() { return m_entry.vno; }
    krb5_enctype enctype() { return m_entry.key.enctype; }
};

