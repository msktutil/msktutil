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

extern krb5_context g_context;

void krb5_error_exit( const char *func, int err_code);
void krb5_warn( const char *func, int err_code);

void
initialize_g_context();

void
destroy_g_context();

class KRB5Principal;

class KRB5Keytab {
    krb5_keytab m_keytab;

    // make it non copyable
    KRB5Keytab(const KRB5Keytab&);
    const  KRB5Keytab& operator=(const KRB5Keytab&);

public:
    KRB5Keytab(const std::string &keytab_name) : m_keytab() {
        krb5_error_code ret = krb5_kt_resolve(g_context, keytab_name.c_str(), &m_keytab);
        if (ret) {
            throw KRB5Exception("krb5_kt_resolve", ret);
        }
    }

    ~KRB5Keytab() {
        krb5_error_code ret = krb5_kt_close(g_context, m_keytab);
        if (ret) {
            krb5_warn("krb5_kt_close", ret);
        }
    }

    void addEntry(const KRB5Principal &princ, krb5_kvno kvno, krb5_keyblock &keyblock);
    void addEntry(const KRB5Principal &princ, krb5_kvno kvno, krb5_enctype enctype,
                  const std::string &password, const std::string &salt);

    void removeEntry(const KRB5Principal &princ, krb5_kvno kvno, krb5_enctype enctype);

    krb5_keytab get() { return m_keytab; }

    /* Defined below... */
    class cursor;
};

class KRB5Creds {
    krb5_creds m_creds;

    // make it non copyable
    KRB5Creds(const KRB5Creds&);
    const  KRB5Creds& operator=(const KRB5Creds&);

public:
    KRB5Creds() : m_creds() {}
    KRB5Creds(KRB5Principal &principal, KRB5Keytab &keytab, const char *tkt_service=NULL);
    KRB5Creds(KRB5Principal &principal, const std::string &password, const char *tkt_service=NULL);
    ~KRB5Creds() {
        krb5_free_cred_contents(g_context, &m_creds);
        memset(&m_creds, 0, sizeof(m_creds));
    }

    krb5_creds *get() { return &m_creds; }

    void move_from(KRB5Creds &other) {
        m_creds = other.m_creds;
        memset(&other.m_creds, 0, sizeof(m_creds));
    }
};

class KRB5CCache {
    krb5_ccache m_ccache;

    // make it non copyable
    KRB5CCache(const KRB5CCache&);
    const  KRB5CCache& operator=(const KRB5CCache&);

public:
    static const char *defaultName() {
        return krb5_cc_default_name(g_context);
    }

    KRB5CCache(const char *cc_name) : m_ccache() {
        krb5_error_code ret = krb5_cc_resolve(g_context, cc_name, &m_ccache);
        if (ret)
            throw KRB5Exception("krb5_cc_resolve", ret);
    }

    ~KRB5CCache() {
        krb5_cc_close(g_context, m_ccache);
    }

    krb5_ccache get() { return m_ccache; }

    void initialize(KRB5Principal &principal);
    void store(KRB5Creds &creds);
};


class KRB5Principal {
    friend class KRB5Keytab::cursor;

    krb5_principal m_princ;

    KRB5Principal() : m_princ() {}

    void reset_no_free(krb5_principal princ) {
        m_princ = princ;
    }

    // make it non copyable
    KRB5Principal(const KRB5Principal&);
    const KRB5Principal& operator=(const KRB5Principal&);

public:
    KRB5Principal(krb5_principal princ_raw) : m_princ(princ_raw) {}

    KRB5Principal(KRB5CCache &ccache) : m_princ() {
        krb5_error_code ret = krb5_cc_get_principal(g_context, ccache.get(), &m_princ);
        if (ret)
            throw KRB5Exception("krb5_cc_get_principal", ret);
    }

    KRB5Principal(std::string principal_name) : m_princ() {
        krb5_error_code ret = krb5_parse_name(g_context, principal_name.c_str(), &m_princ);
        if (ret)
            throw KRB5Exception("krb5_parse_name", ret);
    }
    ~KRB5Principal() {
        if (m_princ)
            krb5_free_principal(g_context, m_princ);
    }

    krb5_principal get() const { return m_princ; }
    std::string name();
};

class KRB5Keytab::cursor {
    KRB5Keytab &m_keytab;
    krb5_kt_cursor m_cursor;
    krb5_keytab_entry m_entry;

    /* Duplicates part of entry, but oh well. */
    KRB5Principal m_princ;

    // make it non copyable
    cursor(const cursor&);
    const cursor& operator=(const cursor&);
    bool m_ok;
public:
    cursor(KRB5Keytab &keytab);
    ~cursor();
    bool next();
    void reset();

    KRB5Principal &principal() { return m_princ; }
    krb5_kvno kvno() const { return m_entry.vno; }
    krb5_enctype enctype() const {
#ifdef HEIMDAL
        return static_cast<krb5_enctype>(m_entry.keyblock.keytype);
#else
        return m_entry.key.enctype;
#endif
    }

    krb5_timestamp timestamp() const { return m_entry.timestamp; }

    krb5_keyblock key() const {
#ifdef HEIMDAL
       return m_entry.keyblock;
#else
       return m_entry.key;
#endif
    }
};

class KRB5KeytabEntry {
private:
    std::string m_principal;
    krb5_timestamp m_timestamp;
    krb5_kvno m_kvno;
    krb5_enctype m_enctype;
    krb5_keyblock m_keyblock;

public:
    KRB5KeytabEntry(krb5_principal principal,
                    krb5_timestamp timestamp,
                    krb5_kvno kvno,
                    krb5_enctype enctype,
                    krb5_keyblock keyblock) : m_principal(KRB5Principal(principal).name()),
                                              m_timestamp(timestamp),
                                              m_kvno(kvno),
                                              m_enctype(enctype),
                                              m_keyblock(keyblock) {
        krb5_error_code ret = krb5_copy_keyblock_contents(g_context, &keyblock, &m_keyblock);
        if (ret) {
            throw KRB5Exception("krb5_copy_keyblock_contents", ret);
        }
    };

    KRB5KeytabEntry(KRB5Keytab::cursor& cursor) : m_principal(cursor.principal().name()),
                                                        m_timestamp(cursor.timestamp()),
                                                        m_kvno(cursor.kvno()),
                                                        m_enctype(cursor.enctype()),
                                                        m_keyblock(cursor.key()) {
        krb5_keyblock tmp = cursor.key();
        krb5_error_code ret = krb5_copy_keyblock_contents(g_context, &tmp, &m_keyblock);
        if (ret) {
            throw KRB5Exception("krb5_copy_keyblock_contents", ret);
        }
    };

    const  KRB5KeytabEntry& operator=(const KRB5KeytabEntry& keytab_entry) {
        m_principal = keytab_entry.m_principal;
        m_timestamp = keytab_entry.m_timestamp;
        m_kvno = keytab_entry.m_kvno;
        m_enctype = keytab_entry.m_enctype;
        m_keyblock = keytab_entry.m_keyblock;

        krb5_error_code ret = krb5_copy_keyblock_contents(g_context,
                                                          &keytab_entry.m_keyblock,
                                                          &m_keyblock);
        if (ret) {
            throw KRB5Exception("krb5_copy_keyblock_contents", ret);
        }

	return *this;
    };

    KRB5KeytabEntry(const KRB5KeytabEntry &keytab_entry) {
        (void) operator=(keytab_entry);
    };


    ~KRB5KeytabEntry() { krb5_free_keyblock_contents(g_context, &m_keyblock); };

    std::string principal() { return m_principal; };
    krb5_timestamp timestamp() { return m_timestamp; };
    krb5_kvno kvno() { return m_kvno; };
    krb5_enctype enctype() { return m_enctype; };
    krb5_keyblock keyblock() { return m_keyblock; };

    bool operator < (const KRB5KeytabEntry& other) const {
        return m_timestamp < other.m_timestamp;
    };
};
