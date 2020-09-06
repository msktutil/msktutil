/*
 *----------------------------------------------------------------------------
 *
 * ldapconnection.cpp
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

#include <sstream>
#include "msktutil.h"
#include "config.h"
#ifdef HAVE_SASL_H
#include <sasl.h>
#else
#include <sasl/sasl.h>
#endif

#define VERBOSEldap(text...) if (g_verbose > 1) { fprintf(stderr, " ###### %s: ", __FUNCTION__); fprintf(stderr, ## text); fprintf(stderr, "\n"); }

static int sasl_interact(ATTRUNUSED LDAP *ld, ATTRUNUSED unsigned flags,
        ATTRUNUSED void *defaults, void *in)
{
    char *dflt = NULL;
    sasl_interact_t *interact = (sasl_interact_t *) in;
    while (interact->id != SASL_CB_LIST_END) {
        dflt = (char *) interact->defresult;
        interact->result = (dflt && *dflt) ? dflt : (void *) "";
        interact->len = (dflt && *dflt) ? strlen(dflt) : 0;
        interact++;
    }
    return LDAP_SUCCESS;
}

LDAPConnection::LDAPConnection(const std::string &server,
        const std::string &sasl_mechanisms,
        bool no_reverse_lookups) :
        m_ldap()
{
    int ret = 0;
#ifdef HAVE_LDAP_INITIALIZE
    std::string ldap_url = "ldap://" + server;
    VERBOSEldap("calling ldap_initialize");
    ret = ldap_initialize(&m_ldap, ldap_url.c_str());
#else
    VERBOSEldap("calling ldap_init");
    m_ldap = ldap_init(server.c_str(), LDAP_PORT);
    if (m_ldap) {
        ret = LDAP_SUCCESS;
    }  else {
        ret = LDAP_OTHER;
    }
#endif
    if (ret) {
        throw LDAPException("ldap_initialize", ret);
    }

#ifdef LDAP_OPT_DEBUG_LEVEL
    int debug = 0xffffff;
    if (g_verbose > 1) {
        ldap_set_option(NULL, LDAP_OPT_DEBUG_LEVEL, &debug);
    }
#endif

    int version = LDAP_VERSION3;

    VERBOSE("Connecting to LDAP server: %s", server.c_str());

    set_option(LDAP_OPT_PROTOCOL_VERSION, &version);
    set_option(LDAP_OPT_REFERRALS, LDAP_OPT_OFF);
    sasl_ssf_t sasl_gssapi_minssf = 56;
    set_option(LDAP_OPT_X_SASL_SSF_MIN, &sasl_gssapi_minssf);

#ifdef LDAP_OPT_X_SASL_NOCANON
    if (no_reverse_lookups) {
        try {
            set_option(LDAP_OPT_X_SASL_NOCANON, LDAP_OPT_ON);
        } catch (LDAPException &e) {
            VERBOSE("Could not disable reverse lookups in LDAP");
        }
    }
#else
    VERBOSE("Your LDAP version does not support the option to disable "
            "reverse lookups");
#endif

    VERBOSEldap("calling ldap_sasl_interactive_bind_s with mechs = %s", sasl_mechanisms.c_str());

    ret = ldap_sasl_interactive_bind_s(m_ldap, NULL, sasl_mechanisms.c_str(), NULL, NULL,
#ifdef LDAP_SASL_QUIET
            g_verbose ? 0 : LDAP_SASL_QUIET,
#else
            0,
#endif
            sasl_interact, NULL);

    if (ret) {
        print_diagnostics("ldap_sasl_interactive_bind_s failed", ret);
        m_ldap = NULL;
    }
}

void LDAPConnection::print_diagnostics(const char *msg, int err)
{
    fprintf(stderr, "Error: %s (%s)\n", msg, ldap_err2string(err));

#if HAVE_DECL_LDAP_OPT_DIAGNOSTIC_MESSAGE
    char *opt_message = NULL;
    ldap_get_option(m_ldap, LDAP_OPT_DIAGNOSTIC_MESSAGE, &opt_message);
    if (opt_message) {
        fprintf(stderr, "\tadditional info: %s\n", opt_message);
    }
    ldap_memfree(opt_message);
#endif
}

void LDAPConnection::set_option(int option, const void *invalue)
{
    int ret = ldap_set_option(m_ldap, option, invalue);
    if (ret) {
        std::stringstream ss;
        ss << "ldap_set_option (option=" << option << ") ";
        throw LDAPException(ss.str(), ret);
    }
}

void LDAPConnection::get_option(int option, void *outvalue)
{
    int ret = ldap_get_option(m_ldap, option, outvalue);
    if (ret) {
        std::stringstream ss;
        ss << "ldap_get_option (option=" << option << ") ";
        throw LDAPException(ss.str(), ret);
    }
}

LDAPConnection::~LDAPConnection() {
    ldap_unbind_ext(m_ldap, NULL, NULL);
}

class MessageVals
{
    berval** m_vals;
public:
    MessageVals(berval **vals) :
            m_vals(vals) {
    }
    ~MessageVals() {
        if (m_vals)
            ldap_value_free_len(m_vals);
    }
    BerValue *&
    operator *() {
        return *m_vals;
    }
    BerValue *&
    operator [](size_t off) {
        return m_vals[off];
    }
    operator bool() {
        return m_vals;
    }
};

LDAPMessage *
LDAPConnection::search(const std::string &base_dn, int scope,
        const std::string &filter, const std::string& attr)
{
    const char *attrs[] = { attr.c_str(), NULL };
    return search(base_dn, scope, filter, attrs);
}

LDAPMessage *
LDAPConnection::search(const std::string &base_dn, int scope,
        const std::string &filter, const std::vector<std::string>& attr)
{

    std::vector<char *> v_chptr;
    for (unsigned int i = 0; i < attr.size(); i++) {
        char *p = const_cast<char *>(attr[i].c_str());
        v_chptr.push_back(p);
    }
    v_chptr.push_back(NULL);
    char **vattr = &v_chptr[0];
    return search(base_dn, scope, filter, const_cast<const char**>(vattr));
}

LDAPMessage *
LDAPConnection::search(const std::string &base_dn, int scope,
        const std::string &filter, const char *attrs[])
{
    LDAPMessage * mesg;

    VERBOSEldap("calling ldap_search_ext_s");
    VERBOSEldap("ldap_search_ext_s base context: %s", base_dn.c_str());
    VERBOSEldap("ldap_search_ext_s filter: %s", filter.c_str());
    int ret = ldap_search_ext_s(m_ldap, base_dn.c_str(), scope, filter.c_str(),
            const_cast<char **>(attrs), 0, NULL, NULL, NULL, -1, &mesg);

    if (ret) {
        print_diagnostics("ldap_search_ext_s failed", ret);
        throw LDAPException("ldap_search_ext_s", ret);
    }
    return mesg;
}

LDAPMessage *LDAPConnection::first_entry(LDAPMessage *mesg)
{
    return mesg = ldap_first_entry(m_ldap, mesg);
}

std::string LDAPConnection::get_one_val(LDAPMessage *mesg,
        const std::string& name)
{
    MessageVals vals = ldap_get_values_len(m_ldap, mesg, name.c_str());
    if (vals) {
        if (vals[0]) {
            berval *val = vals[0];
            return std::string(val->bv_val, val->bv_len);
        }
    }
    return "";
}

std::vector<std::string> LDAPConnection::get_all_vals(LDAPMessage *mesg,
        const std::string& name)
{
    MessageVals vals = ldap_get_values_len(m_ldap, mesg, name.c_str());
    std::vector < std::string > ret;
    if (vals) {
        size_t i = 0;
        while (berval *val = vals[i]) {
            ret.push_back(std::string(val->bv_val, val->bv_len));
            i++;
        }
    }
    return ret;
}

int LDAPConnection::count_entries(LDAPMessage *mesg)
{
    return ldap_count_entries(m_ldap, mesg);
}

int LDAPConnection::modify_ext(const std::string &dn, const std::string& type,
        char *vals[], int op, bool check)
{
    LDAPMod *mod_attrs[2];
    LDAPMod attr;

    int ret;

    mod_attrs[0] = &attr;
    attr.mod_op = op;
    attr.mod_type = const_cast<char *>(type.c_str());
    attr.mod_values = vals;
    mod_attrs[1] = NULL;

    VERBOSEldap("calling ldap_modify_ext_s");
    ret = ldap_modify_ext_s(m_ldap, dn.c_str(), mod_attrs, NULL, NULL);
    if (check && ret != LDAP_SUCCESS) {
        VERBOSE("ldap_modify_ext_s failed (%s)", ldap_err2string(ret));
    }
    return ret;
}

int LDAPConnection::remove_attr(const std::string &dn, const std::string& type,
        const std::string& val)
{
    char *vals_name[] = { NULL, NULL };
    vals_name[0] = const_cast<char *>(val.c_str());
    return modify_ext(dn, type, vals_name, LDAP_MOD_DELETE, true);
}

int LDAPConnection::add_attr(const std::string &dn, const std::string& type,
        const std::string& val)
{
    char *vals_name[] = { NULL, NULL };
    vals_name[0] = const_cast<char *>(val.c_str());
    return modify_ext(dn, type, vals_name, LDAP_MOD_ADD, true);
}

int LDAPConnection::simple_set_attr(const std::string &dn,
        const std::string &type, const std::string &val)
{
    char *vals_name[] = { NULL, NULL };
    vals_name[0] = const_cast<char *>(val.c_str());
    return modify_ext(dn, type, vals_name, LDAP_MOD_REPLACE, true);
}

int LDAPConnection::flush_attr_no_check(const std::string &dn,
        const std::string &type)
{
    char *vals[] = { NULL };
    return modify_ext(dn, type, vals, LDAP_MOD_REPLACE, false);
}

int LDAPConnection::add(const std::string &dn, const LDAP_mod& mod)
{
    std::vector<LDAPMod*> tmp = mod.get();
    tmp.push_back(NULL);

    int ret = ldap_add_ext_s(m_ldap, dn.c_str(),
                             const_cast<LDAPMod **>(&tmp[0]),
                             NULL,
                             NULL);
    if (ret) {
        print_diagnostics("ldap_add_ext_s failed", ret);
        throw LDAPException("ldap_add_ext_s", ret);
    }
    return ret;
}

void LDAP_mod::add(const std::string& type, const std::string& val,
        bool ucs)
{
    LDAPMod *lm = new LDAPMod;
    lm->mod_type = strdup(type.c_str());
    if (ucs == false) {
        char **mv = new char *[2];
        mv[0] = strdup(val.c_str());
        mv[1] = NULL;
        lm->mod_values = mv;
        lm->mod_op = LDAP_MOD_ADD;
    } else {
        lm->mod_op = LDAP_MOD_ADD | LDAP_MOD_BVALUES;
        lm->mod_bvalues = new BerValue *[2];
        lm->mod_bvalues[0] = new BerValue;
        lm->mod_bvalues[0]->bv_val = new char[(val.length()) * 2];

        memset(lm->mod_bvalues[0]->bv_val, 0, val.length() * 2);
        for (unsigned int i = 0; i < val.length(); i++) {
            lm->mod_bvalues[0]->bv_val[i * 2] = val[i];
        }
        lm->mod_bvalues[0]->bv_len = (val.length()) * 2;
        lm->mod_bvalues[1] = NULL;
    }
    attrs.push_back(lm);
}

void LDAP_mod::add(const std::string& type,
        const std::vector<std::string>& val)
{
    LDAPMod *lm = new LDAPMod;
    lm->mod_op = LDAP_MOD_ADD;
    lm->mod_type = strdup(type.c_str());
    char **mv = new char *[val.size() + 1];
    for (unsigned int i = 0; i < val.size(); i++) {
        mv[i] = strdup(val[i].c_str());
    }
    mv[val.size()] = NULL;
    lm->mod_values = mv;

    attrs.push_back(lm);
}

LDAP_mod::~LDAP_mod()
{
    for (std::vector<LDAPMod*>::iterator ptr = attrs.begin();
            ptr != attrs.end(); ptr++) {
        if (*ptr) {
            LDAPMod *lm = *ptr;
            free(lm->mod_type);

            if (lm->mod_op & LDAP_MOD_BVALUES) {
                BerValue **p = lm->mod_bvalues;
                while (*p != NULL) {
                    delete[] (*p)->bv_val;
                    p++;
                }
                delete[] lm->mod_bvalues;
            } else {
                char **p = lm->mod_values;
                while (*p != NULL) {
                    free(*p++);
                }
                delete[] lm->mod_values;
            }
        }
    }
    attrs.clear();
}

std::vector<LDAPMod *>
LDAP_mod::get() const
{
    return attrs;
}
