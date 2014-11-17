/*
 *----------------------------------------------------------------------------
 *
 * msktldap.cpp
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
#include <algorithm>
#include <sstream>
#include <iostream>

static void ldap_print_diagnostics(LDAP *ldap, char *msg, int err)
{
    fprintf(stderr, "Error: %s (%s)\n", msg, ldap_err2string(err));

#if HAVE_DECL_LDAP_OPT_DIAGNOSTIC_MESSAGE
    ldap_get_option(ldap, LDAP_OPT_DIAGNOSTIC_MESSAGE, (void*)&msg);
    if (msg)
        fprintf(stderr, "\tadditional info: %s\n", msg );
#else
    /* Silence compiler warning about unused parameter */
    (void) ldap;
#endif
}

LDAPConnection::LDAPConnection(const std::string &server) : m_ldap() {
    int ret = 0;
#ifndef SOLARIS_LDAP_KERBEROS
    std::string ldap_url = "ldap://" + server;
    VERBOSEldap("calling ldap_initialize");
    ret = ldap_initialize(&m_ldap, ldap_url.c_str());
#else
    VERBOSEldap("calling ldap_init");
    m_ldap = ldap_init(flags->server.c_str(), LDAP_PORT);
    if (m_ldap) ret = LDAP_SUCCESS;
    else ret = LDAP_OTHER;
#endif
    if (ret)
        throw LDAPException("ldap_initialize", ret);
}

void LDAPConnection::set_option(int option, const void *invalue) {
    int ret = ldap_set_option(m_ldap, option, invalue);
    if (ret) {
        std::stringstream ss;
        ss << "ldap_set_option (option=" << option << ") ";
        throw LDAPException(ss.str(), ret);
    }
}

void LDAPConnection::get_option(int option, void *outvalue) {
    int ret = ldap_get_option(m_ldap, option, outvalue);
    if (ret) {
        std::stringstream ss;
        ss << "ldap_get_option (option=" << option << ") ";
        throw LDAPException(ss.str(), ret);
    }
}

void LDAPConnection::start_tls(LDAPControl **serverctrls, LDAPControl **clientctrls) {
    int ret = ldap_start_tls_s(m_ldap, serverctrls, clientctrls);
    if (ret)
        throw LDAPException("ldap_start_tls_s", ret);
}

LDAPConnection::~LDAPConnection() {
    ldap_unbind_ext(m_ldap, NULL, NULL);
}


class MessageVals {
    berval** m_vals;
public:
    MessageVals(berval **vals) : m_vals(vals) {}
    ~MessageVals() {
        if (m_vals)
            ldap_value_free_len(m_vals);
    }
    BerValue *&operator *() { return *m_vals; }
    BerValue *&operator [](size_t off) { return m_vals[off]; }
    operator bool() { return m_vals; }
};



void LDAPConnection::search(LDAPMessage **mesg_p,
                            const std::string &base_dn, int scope, const std::string &filter, char *attrs[],
                            int attrsonly, LDAPControl **serverctrls, LDAPControl **clientctrls,
                            struct timeval *timeout, int sizelimit) {
    VERBOSEldap("calling ldap_search_ext_s");
    VERBOSEldap("ldap_search_ext_s base context: %s", base_dn.c_str());
    VERBOSEldap("ldap_search_ext_s filter: %s", filter.c_str());
    int ret = ldap_search_ext_s(m_ldap, base_dn.c_str(), scope, filter.c_str(), attrs, attrsonly, serverctrls, clientctrls, timeout, sizelimit, mesg_p);
    if (ret) {
        ldap_print_diagnostics(m_ldap, "ldap_search_ext_s failed", ret);
        throw LDAPException("ldap_search_ext_s", ret);
    }
}

std::string LDAPConnection::get_one_val(LDAPMessage *mesg, char *name) {
    MessageVals vals = ldap_get_values_len(m_ldap, mesg, name);
    if (vals) {
        if (vals[0]) {
            berval *val = vals[0];
            return std::string(val->bv_val, val->bv_len);
        }
    }
    return "";
}

std::vector<std::string> LDAPConnection::get_all_vals(LDAPMessage *mesg, char *name) {
    MessageVals vals = ldap_get_values_len(m_ldap, mesg, name);
    std::vector<std::string> ret;
    if (vals) {
        size_t i = 0;
        while(berval *val = vals[i]) {
            ret.push_back(std::string(val->bv_val, val->bv_len));
            i++;
        }
    }
    return ret;

}

void get_default_ou(msktutil_flags *flags)
{
    if (flags->ldap_ou.empty()) {
        /* Only do this on an empty value */
        std::string dn;
        LDAPMessage *mesg;
        char *attrs[] = {"distinguishedName", NULL};

        if (flags->use_service_account) {
            std::string wkguid = sform("<WKGUID=a9d1ca15768811d1aded00c04fd8d5cd,%s>", flags->base_dn.c_str());
            flags->ldap->search(&mesg, wkguid, LDAP_SCOPE_BASE, "objectClass=*", attrs);
        } else {
            std::string wkguid = sform("<WKGUID=aa312825768811d1aded00c04fd8d5cd,%s>", flags->base_dn.c_str());
            flags->ldap->search(&mesg, wkguid, LDAP_SCOPE_BASE, "objectClass=*", attrs);
        }

        if (ldap_count_entries(flags->ldap->m_ldap, mesg) == 1) {
            mesg = ldap_first_entry(flags->ldap->m_ldap, mesg);
            dn = flags->ldap->get_one_val(mesg, "distinguishedName");
        }
        ldap_msgfree(mesg);
        if (dn.empty()) {
            fprintf(stderr, "Warning: could not get default computer OU from AD.\n");
            flags->ldap_ou = "CN=Computers," + flags->base_dn;
        } else {
            flags->ldap_ou = dn;
        }
        VERBOSE("Determining default OU: %s", flags->ldap_ou.c_str());
    } else {
        flags->ldap_ou = flags->ldap_ou + "," + flags->base_dn;
    }
}


static int sasl_interact(ATTRUNUSED LDAP *ld, ATTRUNUSED unsigned flags, ATTRUNUSED void *defaults, void *in)
{
    char *dflt = NULL;
    sasl_interact_t *interact = (sasl_interact_t *)in;
    while (interact->id != SASL_CB_LIST_END) {
        dflt = (char *) interact->defresult;
        interact->result = (dflt && *dflt) ? dflt : (void *)"";
        interact->len = (dflt && *dflt) ? strlen(dflt) : 0;
        interact++;
    }
    return LDAP_SUCCESS;
}


void ldap_get_base_dn(msktutil_flags *flags)
{
    if (flags->base_dn.empty()) {
        std::string out;

        bool first = true;
        std::string &base = flags->realm_name;
        size_t last_pos = 0;
        do {
            size_t pos = base.find('.', last_pos);
            if (first) {
                out.append("dc=");
                first = false;
            } else
                out.append(",dc=");
            out.append(base.substr(last_pos, pos - last_pos));
            last_pos = pos + 1;
        } while (last_pos != 0);

        flags->base_dn = out;
        VERBOSE("Determining default LDAP base: %s", flags->base_dn.c_str());
    }
}

std::auto_ptr<LDAPConnection> ldap_connect(const std::string &server,
                                           bool no_reverse_lookups,
                                           int try_tls)
{
#ifndef SOLARIS_LDAP_KERBEROS
    int debug = 0xffffff;
    if(g_verbose > 1)
        ldap_set_option(NULL, LDAP_OPT_DEBUG_LEVEL, &debug);
#endif

    std::auto_ptr<LDAPConnection> ldap;
    int version = LDAP_VERSION3;
    int ret;
    bool is_tls = false;

    VERBOSE("Connecting to LDAP server: %s try_tls=%s", server.c_str(),
            (try_tls == ATTEMPT_SASL_NO_TLS)?"NO":"YES");

    ldap.reset(new LDAPConnection(server));
    ldap->set_option(LDAP_OPT_PROTOCOL_VERSION, &version);

    ldap->set_option(LDAP_OPT_REFERRALS, LDAP_OPT_OFF);

#ifdef LDAP_OPT_X_SASL_NOCANON
    if (no_reverse_lookups) {
            try {
                ldap->set_option(LDAP_OPT_X_SASL_NOCANON, LDAP_OPT_ON);
            } catch (LDAPException &e) {
                VERBOSE("Could not disable reverse lookups in LDAP");
            }
    }
#else
    VERBOSE("Your LDAP version does not support the option to disable reverse lookups");
#endif

#ifdef LDAP_OPT_X_TLS
    switch (try_tls) {
        case ATTEMPT_SASL_PARAMS_TLS: {
            sasl_ssf_t tryssf = 1;
            try {
                ldap->set_option(LDAP_OPT_X_SASL_SSF_MAX, &tryssf);
            } catch (LDAPException &e) {
                // Don't worry if it fails.
            }
            // fall through
        }
        case ATTEMPT_SASL_NO_PARAMS_TLS: {
            try {
                ldap->start_tls();
            } catch (LDAPException &e) {
                // If it fails, then...
                return ldap_connect(server, no_reverse_lookups, ATTEMPT_SASL_NO_TLS);
            }
            is_tls = true;
            break;
        }
        case ATTEMPT_SASL_NO_TLS: {
            sasl_ssf_t tryssf=56; // Will cause gssapi to use at least des encryption
            ldap->set_option(LDAP_OPT_X_SASL_SSF_MIN, &tryssf);
            break;
        }
    }
#endif
    VERBOSEldap("calling ldap_sasl_interactive_bind_s");

    ret = ldap_sasl_interactive_bind_s(ldap->m_ldap, NULL, "GSSAPI", NULL, NULL,
#ifndef SOLARIS_LDAP_KERBEROS
                                       g_verbose?0:LDAP_SASL_QUIET,
#else
                                       0,
#endif
                                       sasl_interact, NULL);

    if (ret) {
        ldap_print_diagnostics(ldap->m_ldap, "ldap_sasl_interactive_bind_s failed", ret);
        if (is_tls)
            return ldap_connect(server, no_reverse_lookups, ATTEMPT_SASL_NO_TLS);
        return std::auto_ptr<LDAPConnection>(NULL);
    }

    if (g_verbose) {
        try {
            sasl_ssf_t ssf = -1; /* indicates we dont know what it is */
            ldap->get_option(LDAP_OPT_X_SASL_SSF,&ssf);
            VERBOSE("LDAP_OPT_X_SASL_SSF=%d\n",ssf);
        } catch (LDAPException &e) {
            std::cerr << e.what() << std::endl;
        }
    }
    return ldap;
}

void ldap_cleanup(msktutil_flags *flags)
{
    VERBOSE("Disconnecting from LDAP server");
    flags->ldap.reset();
}

void ldap_get_account_attrs(msktutil_flags *flags, char **attrs, LDAPMessage **mesg_p) {
    std::string filter;
    filter = sform("(&(|(objectCategory=Computer)(objectCategory=User))(sAMAccountName=%s))", flags->samAccountName.c_str());
    flags->ldap->search(mesg_p, flags->base_dn, LDAP_SCOPE_SUBTREE, filter, attrs);
}

int ldap_flush_principals(msktutil_flags *flags)
{
    std::string dn;
    LDAPMessage *mesg;
    char *attrs[] = {"distinguishedName", NULL};
    LDAPMod *mod_attrs[2];
    LDAPMod attrServicePrincipalName;
    char *vals_serviceprincipalname[] = {NULL};
    int ret;


    VERBOSE("Flushing principals from LDAP entry");
    ldap_get_account_attrs(flags, attrs, &mesg);

    if (ldap_count_entries(flags->ldap->m_ldap, mesg) == 1) {
        mesg = ldap_first_entry(flags->ldap->m_ldap, mesg);
        dn = flags->ldap->get_one_val(mesg, "distinguishedName");
    }
    ldap_msgfree(mesg);
    if (dn.empty()) {
        fprintf(stderr, "Error: an account for %s was not found\n", flags->samAccountName.c_str());
        return -1;
    }

    mod_attrs[0] = &attrServicePrincipalName;
    attrServicePrincipalName.mod_op = LDAP_MOD_REPLACE;
    attrServicePrincipalName.mod_type = "servicePrincipalName";
    attrServicePrincipalName.mod_values = vals_serviceprincipalname;
    mod_attrs[1] = NULL;
    VERBOSEldap("calling ldap_modify_ext_s");
    ret = ldap_modify_ext_s(flags->ldap->m_ldap, dn.c_str(), mod_attrs, NULL, NULL);

    /* Ignore if the attribute doesn't exist, that just means that it's already empty */
    if (ret != LDAP_SUCCESS && ret != LDAP_NO_SUCH_ATTRIBUTE) {
        ldap_print_diagnostics(flags->ldap->m_ldap, "ldap_modify_ext_s failed", ret);
        return -1;
    }

    return 0;
}




krb5_kvno ldap_get_kvno(msktutil_flags *flags)
{
    krb5_kvno kvno = KVNO_FAILURE;
    LDAPMessage *mesg;
    char *attrs[] = {"msDS-KeyVersionNumber", NULL};

    ldap_get_account_attrs(flags, attrs, &mesg);
    if (ldap_count_entries(flags->ldap->m_ldap, mesg) == 1) {
        mesg = ldap_first_entry(flags->ldap->m_ldap, mesg);
        std::string kvno_str = flags->ldap->get_one_val(mesg, "msDS-KeyVersionNumber");
        if(!kvno_str.empty())
            kvno = (krb5_kvno) atoi(kvno_str.c_str());
        else {
            /* This must be a Windows 2000 domain, which does support have KVNO's. */
            kvno = KVNO_WIN_2000;
            VERBOSE("Unable to find KVNO attribute on domain controller %s - This must be running windows 2000", flags->server.c_str());
        }
    }
    ldap_msgfree(mesg);

    VERBOSE("KVNO is %d", kvno);
    return kvno;
}


std::string ldap_get_pwdLastSet(msktutil_flags *flags)
{
    std::string pwdLastSet;
    LDAPMessage *mesg;
    char *attrs[] = {"pwdLastSet", NULL};

    ldap_get_account_attrs(flags, attrs, &mesg);

    if (ldap_count_entries(flags->ldap->m_ldap, mesg) == 1) {
        mesg = ldap_first_entry(flags->ldap->m_ldap, mesg);
        pwdLastSet = flags->ldap->get_one_val(mesg, "pwdLastSet");
        VERBOSE("pwdLastSet is %s", pwdLastSet.c_str());
    }
    ldap_msgfree(mesg);
    return pwdLastSet;
}

int ldap_simple_set_attr(LDAPConnection *ldap, const std::string &dn, 
                         const std::string &attrName, const std::string &val, msktutil_flags *flags)
{
    LDAPMod *mod_attrs[2] = {NULL, NULL};
    LDAPMod attr;
    char *vals[] = {NULL, NULL};
    int ret;

    mod_attrs[0] = &attr;
    attr.mod_op = LDAP_MOD_REPLACE;
    attr.mod_type = const_cast<char *>(attrName.c_str());
    attr.mod_values = vals;
    vals[0] = const_cast<char*>(val.c_str());

    VERBOSE("Calling ldap_modify_ext_s to set %s to %s", attrName.c_str(), val.c_str());
    ret = ldap_modify_ext_s(ldap->m_ldap, dn.c_str(), mod_attrs, NULL, NULL);

    if (ret != LDAP_SUCCESS) {
        VERBOSE("ldap_modify_ext_s failed (%s)", ldap_err2string(ret));

        fprintf(stderr, "WARNING: ldap modification of %s\n", dn.c_str());
        fprintf(stderr, "         failed while trying to change %s to %s.\n", attrName.c_str(), val.c_str());
        fprintf(stderr, "         Error was: %s\n", ldap_err2string(ret));
        fprintf(stderr, "         --> Do you have enough privileges?\n");
        fprintf(stderr, "         --> You might try re-\"kinit\"ing.\n");
        if (!flags->user_creds_only) { 
            fprintf(stderr, "         --> Maybe you should try again with --user-creds-only?\n");
        }

        if (attrName.compare(0, 17, "userPrincipalName") == 0) {
            fprintf(stderr, "ERROR:   Can't continue with wrong UPN\n");
            exit(1);
        } else {
            fprintf(stderr, "         Continuing anyway ...\n");
        }
    }

    return ret;
}
int ldap_set_supportedEncryptionTypes(const std::string &dn, msktutil_flags *flags)
{
    int ret;

    if (flags->ad_supportedEncryptionTypes != flags->supportedEncryptionTypes) {
        std::string supportedEncryptionTypes = sform("%d", flags->supportedEncryptionTypes);

        VERBOSE("DEE dn=%s old=%d new=%d\n",
                dn.c_str(), flags->ad_supportedEncryptionTypes, flags->supportedEncryptionTypes);

        ret = ldap_simple_set_attr(flags->ldap.get(), dn, "msDs-supportedEncryptionTypes",
                                   supportedEncryptionTypes, flags);

        if (ret == LDAP_SUCCESS) {
            flags->ad_enctypes = VALUE_ON;
            flags->ad_supportedEncryptionTypes = flags->supportedEncryptionTypes;
        }
    } else {
        VERBOSE("No need to change msDs-supportedEncryptionTypes they are %d\n",flags->ad_supportedEncryptionTypes);
        ret = LDAP_SUCCESS;
    }

    return ret;
}

int ldap_set_userAccountControl_flag(const std::string &dn, int mask, msktutil_val value, msktutil_flags *flags)
{
    LDAPMod *mod_attrs[2];
    LDAPMod attrUserAccountControl;
    char *vals_useraccountcontrol[] = { NULL, NULL};
    int ret;
    unsigned new_userAcctFlags;
    unsigned old_userAcctFlags;

    /* Skip this value if its not to change */
    if (value == VALUE_IGNORE) { return 0; }
    new_userAcctFlags = old_userAcctFlags = flags->ad_userAccountControl;

    mod_attrs[0] = &attrUserAccountControl;
    attrUserAccountControl.mod_op = LDAP_MOD_REPLACE;
    attrUserAccountControl.mod_type = "userAccountControl";
    attrUserAccountControl.mod_values = vals_useraccountcontrol;

    switch (value) {
        case VALUE_ON:
            VERBOSE("Setting userAccountControl bit at 0x%x to 0x%x", mask, value);
            new_userAcctFlags = old_userAcctFlags | mask;
            break;
        case VALUE_OFF:
            VERBOSE("Setting userAccountControl bit at 0x%x to 0x%x", mask, value);
            new_userAcctFlags = old_userAcctFlags & (~mask);
            break;
        case VALUE_IGNORE:
            /* Unreachable */
            break;
    }
    std::string new_userAcctFlags_string = sform("%d", new_userAcctFlags);
    vals_useraccountcontrol[0] = const_cast<char*>(new_userAcctFlags_string.c_str());

    mod_attrs[1] = NULL;

    if (new_userAcctFlags != old_userAcctFlags) {
        VERBOSEldap("calling ldap_modify_ext_s");
        ret = ldap_modify_ext_s(flags->ldap->m_ldap, dn.c_str(), mod_attrs, NULL, NULL);
        if (ret != LDAP_SUCCESS) {
            VERBOSE("ldap_modify_ext_s failed (%s)", ldap_err2string(ret));
        } else {
            flags->ad_userAccountControl = new_userAcctFlags;
        }
    } else {
        VERBOSE(" userAccountControl not changed 0x%x\n", new_userAcctFlags);
        ret = LDAP_SUCCESS;
    }

    return ret;
}



int ldap_add_principal(const std::string &principal, msktutil_flags *flags)
{
    const std::string &dn(flags->ad_computerDn);
    LDAPMessage *mesg;
    char *attrs[] = {"distinguishedName", NULL};
    LDAPMod *mod_attrs[2];
    LDAPMod attrServicePrincipalName;
    char *vals_serviceprincipalname[] = { NULL, NULL};
    int ret;

    VERBOSE("Checking that adding principal %s to %s won't cause a conflict", principal.c_str(), flags->samAccountName.c_str());
    std::string filter = sform("(servicePrincipalName=%s)", principal.c_str());
    flags->ldap->search(&mesg, flags->base_dn, LDAP_SCOPE_SUBTREE, filter, attrs);
    switch (ldap_count_entries(flags->ldap->m_ldap, mesg)) {
        case 0:
            VERBOSE("Adding principal %s to LDAP entry", principal.c_str());
            mod_attrs[0] = &attrServicePrincipalName;
            attrServicePrincipalName.mod_op = LDAP_MOD_ADD;
            attrServicePrincipalName.mod_type = "servicePrincipalName";
            attrServicePrincipalName.mod_values = vals_serviceprincipalname;
            vals_serviceprincipalname[0] = const_cast<char*>(principal.c_str());

            mod_attrs[1] = NULL;

            VERBOSEldap("calling ldap_modify_ext_s");
            ret = ldap_modify_ext_s   (flags->ldap->m_ldap, dn.c_str(), mod_attrs, NULL, NULL);
            if (ret != LDAP_SUCCESS) {
                VERBOSE("ldap_modify_ext_s failed (%s)", ldap_err2string(ret));

                fprintf(stderr, "WARNING: ldap modification of %s\n", dn.c_str());
                fprintf(stderr, "         failed while trying to add servicePrincipalName %s.\n", principal.c_str());
                fprintf(stderr, "         Error was: %s\n", ldap_err2string(ret));
                fprintf(stderr, "         --> Do you have enough privileges?\n");
                fprintf(stderr, "         --> You might try re-\"kinit\"ing.\n");
                if (!flags->user_creds_only) { 
                    fprintf(stderr, "         --> Maybe you should try again with --user-creds-only?\n");
                }

            } else {
                flags->ad_principals.push_back(principal);
            }
            return ret;
        case 1: {
            /* Check if we are the owner of the this principal or not */
            mesg = ldap_first_entry(flags->ldap->m_ldap, mesg);
            std::string found_dn = flags->ldap->get_one_val(mesg, "distinguishedName");
            if (found_dn.empty()) {
                fprintf(stderr, "Error: Inconsistent LDAP entry: No DN value present\n");
                ret = -1;
            } else if (dn != found_dn) {
                fprintf(stderr, "Error: Another computer account (%s) has the principal %s\n",
                        found_dn.c_str(), principal.c_str());
                ret = -1;
            } else
                ret = 0;
            ldap_msgfree(mesg);
            return ret;
        }
        default:
            ret = ldap_count_entries(flags->ldap->m_ldap, mesg);
            fprintf(stderr, "Error: Multiple (%d) LDAP entries were found containing the principal %s\n",
                    ret, principal.c_str());
            ldap_msgfree(mesg);
            return ret;
    }
}

template<typename T>
void vec_remove(std::vector<T> vec, const T &val) {
    vec.erase(std::remove(vec.begin(), vec.end(), val), vec.end());
}

int ldap_remove_principal(const std::string &principal, msktutil_flags *flags)
{
    const std::string &dn(flags->ad_computerDn);
    LDAPMod *mod_attrs[2];
    LDAPMod attrServicePrincipalName;
    char *vals_serviceprincipalname[] = { NULL, NULL};
    int ret;

    VERBOSE("Removing principal %s from LDAP entry", principal.c_str());

    mod_attrs[0] = &attrServicePrincipalName;
    attrServicePrincipalName.mod_op = LDAP_MOD_DELETE;
    attrServicePrincipalName.mod_type = "servicePrincipalName";
    attrServicePrincipalName.mod_values = vals_serviceprincipalname;
    vals_serviceprincipalname[0] = const_cast<char*>(principal.c_str());

    mod_attrs[1] = NULL;

    VERBOSEldap("calling ldap_modify_ext_s");
    ret = ldap_modify_ext_s(flags->ldap->m_ldap, dn.c_str(), mod_attrs, NULL, NULL);
    if (ret != LDAP_SUCCESS) {
        VERBOSE("ldap_modify_ext_s failed (%s)", ldap_err2string(ret));
    } else {
        vec_remove(flags->ad_principals, principal);
    }
    return ret;
}

void ldap_check_account_strings(msktutil_flags *flags)
{
    const std::string &dn = flags->ad_computerDn;

    VERBOSE("Inspecting (and updating) computer account attributes");

    // NOTE: failures to set all the attributes in this function are ignored, for better or worse..

    // don't set dnsHostname on service accounts
    if (!flags->use_service_account) {
        if (!flags->hostname.empty() && flags->hostname != flags->ad_dnsHostName) {
            ldap_simple_set_attr(flags->ldap.get(), dn, "dNSHostName", flags->hostname, flags);
        }
    }

    if (flags->set_description) {
        ldap_simple_set_attr(flags->ldap.get(), dn, "description", flags->description, flags);
    }


    if (flags->set_userPrincipalName) {
        std::string userPrincipalName_string = "";
        if (flags->userPrincipalName.find("@") != std::string::npos) {
            userPrincipalName_string = sform("%s", flags->userPrincipalName.c_str());
        } else {
            userPrincipalName_string = sform("%s@%s", flags->userPrincipalName.c_str(), flags->realm_name.c_str());
        }
        ldap_simple_set_attr(flags->ldap.get(), dn, "userPrincipalName", userPrincipalName_string, flags);
    }
    ldap_set_supportedEncryptionTypes(dn, flags);

    msktutil_val des_only;
    if (flags->supportedEncryptionTypes == (MS_KERB_ENCTYPE_DES_CBC_CRC|MS_KERB_ENCTYPE_DES_CBC_MD5))
        des_only = VALUE_ON;
    else
        des_only = VALUE_OFF;

    ldap_set_userAccountControl_flag(dn, UF_USE_DES_KEY_ONLY, des_only, flags);
    // If msDS-supportedEncryptionTypes isn't set, ad_enctypes will be VALUE_OFF. In that case,
    // reset ad_supportedEncryptionTypes according to the DES flag, in case we changed it.
    if (flags->ad_enctypes == VALUE_OFF) {
        flags->ad_supportedEncryptionTypes =
            MS_KERB_ENCTYPE_DES_CBC_CRC|MS_KERB_ENCTYPE_DES_CBC_MD5;
        if (! (flags->ad_userAccountControl & UF_USE_DES_KEY_ONLY)) {
            flags->ad_supportedEncryptionTypes |= MS_KERB_ENCTYPE_RC4_HMAC_MD5;
        }
    }

    ldap_set_userAccountControl_flag(dn, UF_NO_AUTH_DATA_REQUIRED, flags->no_pac, flags);
    ldap_set_userAccountControl_flag(dn, UF_TRUSTED_FOR_DELEGATION, flags->delegate, flags);
    ldap_set_userAccountControl_flag(dn, UF_DONT_EXPIRE_PASSWORD, flags->dont_expire_password, flags);
}


void ldap_check_account(msktutil_flags *flags)
{
    LDAPMessage *mesg;
    char *machine_attrs[] = {"distinguishedName", "dNSHostName", "msDs-supportedEncryptionTypes",
                      "userAccountControl", "servicePrincipalName", "userPrincipalName", NULL};
    char *user_attrs[] = {"distinguishedName", "msDs-supportedEncryptionTypes",
                      "userAccountControl", "servicePrincipalName", "userPrincipalName", "unicodePwd", NULL};
    int userAcctFlags;
    std::string dn;
    LDAPMod *mod_attrs[6];
    LDAPMod attrObjectClass;
    LDAPMod attrCN;
    LDAPMod attrUserAccountControl;
    LDAPMod attrSamAccountName;
    LDAPMod attrunicodePwd;
    char *vals_machine_objectClass[] = {"top", "person", "organizationalPerson", "user", "computer", NULL};
    char *vals_user_objectClass[] = {"top", "person", "organizationalPerson", "user", NULL};
    char *vals_cn[] = {NULL, NULL};
    char *vals_useraccountcontrol[] = {NULL, NULL};
    char *vals_samaccountname[] = {NULL, NULL};
    BerValue *bvals_unicodepwd[] = {NULL, NULL};
    int attr_count = 0;

    if (flags->use_service_account) {
        VERBOSE("Checking that a service account for %s exists", flags->samAccountName.c_str());
        ldap_get_account_attrs(flags, user_attrs, &mesg);
    } else {
        VERBOSE("Checking that a computer account for %s exists", flags->samAccountName.c_str());
        ldap_get_account_attrs(flags, machine_attrs, &mesg);
    }

    if (ldap_count_entries(flags->ldap->m_ldap, mesg) > 0) {
        /* Account already exists */
        if (flags->use_service_account) {
            VERBOSE("Checking service account - found");
        } else {
            VERBOSE("Checking computer account - found");
        }
        mesg = ldap_first_entry(flags->ldap->m_ldap, mesg);
        flags->ad_computerDn = flags->ldap->get_one_val(mesg, "distinguishedName");

        std::string uac = flags->ldap->get_one_val(mesg, "userAccountControl");
        if(!uac.empty()) {
            flags->ad_userAccountControl = atoi(uac.c_str());
            VERBOSE("Found userAccountControl = 0x%x\n",flags->ad_userAccountControl);
        }

        /* save the current msDs-supportedEncryptionTypes */
        std::string supportedEncryptionTypes = flags->ldap->get_one_val(mesg, "msDs-supportedEncryptionTypes");
        if (!supportedEncryptionTypes.empty()) {
            flags->ad_supportedEncryptionTypes = atoi(supportedEncryptionTypes.c_str());
            flags->ad_enctypes = VALUE_ON; /* actual value found in AD */
            VERBOSE("Found supportedEncryptionTypes = %d\n",
                    flags->ad_supportedEncryptionTypes);
        } else {
            /* Not in current LDAP entry set defaults */
            flags->ad_supportedEncryptionTypes =
                MS_KERB_ENCTYPE_DES_CBC_CRC|MS_KERB_ENCTYPE_DES_CBC_MD5;
            if (! (flags->ad_userAccountControl & UF_USE_DES_KEY_ONLY)) {
                flags->ad_supportedEncryptionTypes |= MS_KERB_ENCTYPE_RC4_HMAC_MD5;
            }
            flags->ad_enctypes = VALUE_OFF; /* this is the assumed default */
            VERBOSE("Found default supportedEncryptionTypes = %d\n",
                    flags->ad_supportedEncryptionTypes);
        }

        if (!flags->use_service_account) {
            // Save current dNSHostName
            flags->ad_dnsHostName = flags->ldap->get_one_val(mesg, "dNSHostName");
            VERBOSE("Found dNSHostName = %s\n", flags->ad_dnsHostName.c_str());
        }

        // Save current servicePrincipalName and userPrincipalName attrs
        if (ldap_count_entries(flags->ldap->m_ldap, mesg) == 1) {
            mesg = ldap_first_entry(flags->ldap->m_ldap, mesg);
            std::vector<std::string> vals = flags->ldap->get_all_vals(mesg, "servicePrincipalName");
            for (size_t i = 0; i < vals.size(); ++i) {
                // translate HOST/ to host/
                if (vals[i].compare(0, 5, "HOST/") == 0) {
                    vals[i].replace(0, 5, "host/");
                }
                flags->ad_principals.push_back(vals[i]);
                VERBOSE("  Found Principal: %s", vals[i].c_str());
            }

            if (flags->set_userPrincipalName) {
                VERBOSE("  userPrincipal specified on command line");
            } else {
                std::string upn = flags->ldap->get_one_val(mesg, "userPrincipalName");
                if(!upn.empty()) {
                    size_t pos = upn.find('@');
                    if (pos != std::string::npos)
                        upn.erase(pos);
                    VERBOSE("  Found User Principal: %s", upn.c_str());
                    //update userPrincipalName for salt generation
                    flags->userPrincipalName = upn.c_str();
                }
            }
        }

        ldap_msgfree(mesg);
    } else {
        ldap_msgfree(mesg);

        /* No computer account found, so let's add one in the OU specified */
        if (flags->use_service_account) {
            VERBOSE("Service account not found, create the account\n");
            fprintf(stdout, "No service account for %s found, creating a new one.\n", flags->samAccountName.c_str());
        } else {
            VERBOSE("Computer account not found, create the account\n");
            fprintf(stdout, "No computer account for %s found, creating a new one.\n", flags->samAccountName_nodollar.c_str());
        }
        flags->ad_computerDn = sform("cn=%s,%s", flags->samAccountName_nodollar.c_str(), flags->ldap_ou.c_str());
        mod_attrs[attr_count++] = &attrObjectClass;
        attrObjectClass.mod_op = LDAP_MOD_ADD;
        attrObjectClass.mod_type = "objectClass";
        if (flags->use_service_account) {
            attrObjectClass.mod_values = vals_user_objectClass;
        } else {
            attrObjectClass.mod_values = vals_machine_objectClass;
        }

        mod_attrs[attr_count++] = &attrCN;
        attrCN.mod_op = LDAP_MOD_ADD;
        attrCN.mod_type = "cn";
        attrCN.mod_values = vals_cn;
        vals_cn[0] = const_cast<char*>(flags->samAccountName_nodollar.c_str());

        mod_attrs[attr_count++] = &attrUserAccountControl;
        attrUserAccountControl.mod_op = LDAP_MOD_ADD;
        attrUserAccountControl.mod_type = "userAccountControl";
        attrUserAccountControl.mod_values = vals_useraccountcontrol;
        if (flags->use_service_account) {
            userAcctFlags = UF_NORMAL_ACCOUNT;
        } else {
            userAcctFlags = UF_WORKSTATION_TRUST_ACCOUNT;
        }
        std::string userAcctFlags_string = sform("%d", userAcctFlags);
        vals_useraccountcontrol[0] = const_cast<char*>(userAcctFlags_string.c_str());

        mod_attrs[attr_count++] = &attrSamAccountName;
        attrSamAccountName.mod_op = LDAP_MOD_ADD;
        attrSamAccountName.mod_type = "sAMAccountName";
        attrSamAccountName.mod_values = vals_samaccountname;
        vals_samaccountname[0] = const_cast<char*>(flags->samAccountName.c_str());
        mod_attrs[attr_count++] = &attrunicodePwd;
        attrunicodePwd.mod_op = LDAP_MOD_ADD | LDAP_MOD_BVALUES;
        attrunicodePwd.mod_type = "unicodePwd";
        attrunicodePwd.mod_bvalues = bvals_unicodepwd;
        std::string passwd = "\"" + flags->password  + "\"";
        bvals_unicodepwd[0] = new BerValue;
        bvals_unicodepwd[0]->bv_val = new char[ (passwd.length())  * 2 ];
        memset(bvals_unicodepwd[0]->bv_val , 0, passwd.length()   * 2);
        for (unsigned int i = 0; i < passwd.length(); i++) {
            bvals_unicodepwd[0]->bv_val[i*2] = passwd[i];
        }
        bvals_unicodepwd[0]->bv_len = (passwd.length()) *2;

        mod_attrs[attr_count++] = NULL;

        // Defaults, will attempt to reset later
        flags->ad_supportedEncryptionTypes = MS_KERB_ENCTYPE_DES_CBC_CRC | MS_KERB_ENCTYPE_DES_CBC_MD5 |
            MS_KERB_ENCTYPE_RC4_HMAC_MD5;
        flags->ad_enctypes = VALUE_OFF;

        int ret = ldap_add_ext_s(flags->ldap->m_ldap, flags->ad_computerDn.c_str(), mod_attrs, NULL, NULL);
        if (ret) {
            ldap_print_diagnostics(flags->ldap->m_ldap, "ldap_add_ext_s failed", ret);
            throw LDAPException("ldap_add_ext_s", ret);
        }
        delete bvals_unicodepwd[0]->bv_val;
        delete bvals_unicodepwd[0];

        flags->ad_userAccountControl = userAcctFlags;
    }

    ldap_check_account_strings(flags);
}
