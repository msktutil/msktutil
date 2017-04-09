/*
 *----------------------------------------------------------------------------
 *
 * krb5wrap.h
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
class noncopyable {
protected:
    noncopyable() {}
    ~noncopyable() {}
private:  /* emphasize the following members are private */
    noncopyable(const noncopyable&);
    const noncopyable& operator=(const noncopyable&);
};

class KRB5Context : noncopyable {
    krb5_context m_context;

public:
    KRB5Context();
    ~KRB5Context();

    void reload();

    krb5_context &get() { return m_context; }
};

extern KRB5Context g_context;


class KRB5Keyblock : noncopyable{
    krb5_keyblock m_keyblock;

public:
    KRB5Keyblock() : m_keyblock() {}

    void from_string(krb5_enctype enctype, const std::string &password, const std::string &salt);

    ~KRB5Keyblock() {
        krb5_free_keyblock_contents(g_context.get(), &m_keyblock);
    }

    krb5_keyblock &get() {
        return m_keyblock;
    }
};

class KRB5Principal;

class KRB5Keytab : noncopyable{
    krb5_keytab m_keytab;

public:
    KRB5Keytab(const std::string &keytab_name) : m_keytab() {
        krb5_error_code ret = krb5_kt_resolve(g_context.get(), keytab_name.c_str(), &m_keytab);
        if (ret)
            throw KRB5Exception("krb5_kt_resolve", ret);
    }

    ~KRB5Keytab() {
        krb5_error_code ret = krb5_kt_close(g_context.get(), m_keytab);
        if (ret)
            /* FIXME: shouldn't throw from destructor... */
            throw KRB5Exception("krb5_kt_close", ret);
    }

    void addEntry(KRB5Principal &princ, krb5_kvno kvno, KRB5Keyblock &keyblock);
    void removeEntry(KRB5Principal &princ, krb5_kvno kvno, krb5_enctype enctype);

    krb5_keytab get() { return m_keytab; }

    /* Defined below... */
    class cursor;
};

class KRB5Creds : noncopyable {
    krb5_creds m_creds;

public:

    KRB5Creds() : m_creds() {}
    KRB5Creds(KRB5Principal &principal, KRB5Keytab &keytab, const char *tkt_service=NULL);
    KRB5Creds(KRB5Principal &principal, const std::string &password, const char *tkt_service=NULL);
    ~KRB5Creds() {
        krb5_free_cred_contents(g_context.get(), &m_creds);
        memset(&m_creds, 0, sizeof(m_creds));
    }

    krb5_creds *get() { return &m_creds; }

    void move_from(KRB5Creds &other) {
        m_creds = other.m_creds;
        memset(&other.m_creds, 0, sizeof(m_creds));
    }
};

class KRB5CCache : noncopyable {
    krb5_ccache m_ccache;

public:
    static const char *defaultName() {
        return krb5_cc_default_name(g_context.get());
    }

    KRB5CCache(const char *cc_name) : m_ccache() {
        krb5_error_code ret = krb5_cc_resolve(g_context.get(), cc_name, &m_ccache);
        if (ret)
            throw KRB5Exception("krb5_cc_resolve", ret);
    }

    ~KRB5CCache() {
        krb5_cc_close(g_context.get(), m_ccache);
    }

    krb5_ccache get() { return m_ccache; }

    void initialize(KRB5Principal &principal);
    void store(KRB5Creds &creds);
};



class KRB5Principal : noncopyable {
    friend class KRB5Keytab::cursor;

    krb5_principal m_princ;

    KRB5Principal() : m_princ() {}

    void reset_no_free(krb5_principal princ) {
        m_princ = princ;
    }

public:
    KRB5Principal(krb5_principal princ_raw) : m_princ(princ_raw) {}

    KRB5Principal(KRB5CCache &ccache) : m_princ() {
        krb5_error_code ret = krb5_cc_get_principal(g_context.get(), ccache.get(), &m_princ);
        if (ret)
            throw KRB5Exception("krb5_cc_get_principal", ret);
    }

    KRB5Principal(std::string principal_name) : m_princ() {
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

class KRB5Keytab::cursor : noncopyable {
    KRB5Keytab &m_keytab;
    krb5_kt_cursor m_cursor;
    krb5_keytab_entry m_entry;

    /* Duplicates part of entry, but oh well. */
    KRB5Principal m_princ;

public:
    cursor(KRB5Keytab &keytab);
    ~cursor();
    bool next();

    KRB5Principal &principal() { return m_princ; }
    krb5_kvno kvno() { return m_entry.vno; }
    krb5_enctype enctype() {
#ifdef HEIMDAL
        return static_cast<krb5_enctype>(m_entry.keyblock.keytype);
#else
        return m_entry.key.enctype;
#endif
    }

    krb5_timestamp timestamp() {
        return m_entry.timestamp;
    }
};
