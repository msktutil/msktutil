/*
 *----------------------------------------------------------------------------
 *
 * msktldap.c
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

LDAPConnection::LDAPConnection(std::string server) : m_ldap() {
#ifndef SOLARIS_LDAP_KERBEROS
    std::string ldap_url = "ldap://" + server;
    VERBOSEldap("calling ldap_initialize");
    int ret = ldap_initialize(&m_ldap, ldap_url.c_str());
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
        std::string s = "ldap_set_option (option=";
        s += option;
        s += ") ";
        throw LDAPException(s, ret);
    }
}

void LDAPConnection::get_option(int option, void *outvalue) {
    int ret = ldap_get_option(m_ldap, option, outvalue);
    if (ret) {
        std::string s = "ldap_set_option (option=";
        s += option;
        s += ") ";
        throw LDAPException(s, ret);
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

void get_default_ou(msktutil_flags *flags)
{
    if (flags->ldap_ou.empty()) {
        /* Only do this on an empty value */
        std::string dn;
        LDAPMessage *mesg;
        char *attrs[] = {"distinguishedName", NULL};
        std::string wkguid = sform("<WKGUID=aa312825768811d1aded00c04fd8d5cd,%s>", flags->base_dn.c_str());
        flags->ldap->search(&mesg, wkguid, LDAP_SCOPE_BASE, "objectClass=*", attrs);

        if (ldap_count_entries(flags->ldap->m_ldap, mesg) == 1) {
            mesg = ldap_first_entry(flags->ldap->m_ldap, mesg);
            dn = flags->ldap->get_one_val(mesg, "distinguishedName");
        }
        ldap_msgfree(mesg);
        if (dn.empty()) {
            fprintf(stderr, "Warning: could not get default computer OU from AD.\n");
            flags->ldap_ou = "CN=Computers" + flags->base_dn;
        } else
            flags->ldap_ou = dn;
        VERBOSE("Determining default OU: %s", flags->ldap_ou.c_str());
    }
}


static int sasl_interact(ATTRUNUSED LDAP *ld, ATTRUNUSED unsigned flags, ATTRUNUSED void *defaults, void *in)
{
    char *dflt = NULL;
    sasl_interact_t *interact = (sasl_interact_t *)in;
    while (interact->id != SASL_CB_LIST_END) {
        dflt = (char *) interact->defresult;
        interact->result = (dflt && *dflt) ? dflt : "";
        interact->len = (dflt && *dflt) ? strlen(dflt) : 0;
        interact++;
    }
    return LDAP_SUCCESS;
}


int ldap_get_base_dn(msktutil_flags *flags)
{
    if (flags->realm_name.empty()) {
        return -1;
    }

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
    return 0;
}

std::auto_ptr<LDAPConnection> ldap_connect(std::string server, int try_tls)
{
#ifndef SOLARIS_LDAP_KERBEROS
    int debug = 0xffffff;
    if( g_verbose > 1)
        ldap_set_option( NULL, LDAP_OPT_DEBUG_LEVEL, &debug);
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
                return ldap_connect(server, ATTEMPT_SASL_NO_TLS);
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
                    g_verbose?0:LDAP_SASL_QUIET |
#endif
                    LDAP_SASL_INTERACTIVE, sasl_interact, NULL);

    if (ret) {
        fprintf(stderr, "Error: ldap_sasl_interactive_bind_s failed 4 (%s)\n", ldap_err2string(ret));
        if (is_tls)
            return ldap_connect(server, ATTEMPT_SASL_NO_TLS);
        return std::auto_ptr<LDAPConnection>(NULL);
    }

    sasl_ssf_t ssf = -1; /* indicates we dont know what it is */
    ldap->get_option(LDAP_OPT_X_SASL_SSF,&ssf);
    VERBOSE("LDAP_OPT_X_SASL_SSF=%d\n",ssf)

    return ldap;
}

void ldap_cleanup(msktutil_flags *flags)
{
    VERBOSE("Disconnecting from LDAP server");
    flags->ldap.reset();
}


void LDAPConnection::search(LDAPMessage **mesg_p,
                            const std::string &base_dn, int scope, const std::string &filter, char *attrs[],
                            int attrsonly, LDAPControl **serverctrls, LDAPControl **clientctrls,
                            struct timeval *timeout, int sizelimit) {
    VERBOSEldap("calling ldap_search_ext_s");
    int ret = ldap_search_ext_s(m_ldap, base_dn.c_str(), scope, filter.c_str(), attrs, attrsonly, serverctrls, clientctrls, timeout, sizelimit, mesg_p);
    if (ret)
        throw LDAPException("ldap_search_ext_s", ret);
}

void ldap_get_computer_attrs(msktutil_flags *flags, char **attrs, LDAPMessage **mesg_p) {
    std::string filter;
    filter = sform("(&(objectClass=computer)(sAMAccountName=%s))", flags->samAccountName.c_str());
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
    ldap_get_computer_attrs(flags, attrs, &mesg);

    if (ldap_count_entries(flags->ldap->m_ldap, mesg) == 1) {
        mesg = ldap_first_entry(flags->ldap->m_ldap, mesg);
        dn = flags->ldap->get_one_val(mesg, "distinguishedName");
    }
    ldap_msgfree(mesg);
    if (dn.empty()) {
        fprintf(stderr, "Error: an account for %s was not found\n", flags->hostname.c_str());
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
        fprintf(stderr, "Error: ldap_modify_ext_s failed (%s)\n", ldap_err2string(ret));
        return -1;
    }

    return 0;
}


std::vector<std::string> ldap_list_principals(msktutil_flags *flags)
{
    LDAPMessage *mesg;
    char *attrs[] = {"servicePrincipalName", "userPrincipalName", NULL};
    std::vector<std::string> principals;

    VERBOSE("Listing principals for LDAP entry");
    ldap_get_computer_attrs(flags, attrs, &mesg);

    if (ldap_count_entries(flags->ldap->m_ldap, mesg) == 1) {
        mesg = ldap_first_entry(flags->ldap->m_ldap, mesg);
        std::vector<std::string> vals = flags->ldap->get_all_vals(mesg, "servicePrincipalName");
        for (size_t i = 0; i < vals.size(); ++i) {
            principals.push_back(vals[i]);
            VERBOSE("  Found Principal: %s", vals[i].c_str());
        }

        std::string upn = flags->ldap->get_one_val(mesg, "userPrincipalName");
        if(!upn.empty()) {
            size_t pos = upn.find('@');
            if (pos != std::string::npos)
                upn.erase(pos);
            principals.push_back(upn);
            VERBOSE("  Found Principal: %s", upn.c_str());
        }
    }
    ldap_msgfree(mesg);

    return principals;
}


krb5_kvno ldap_get_kvno(msktutil_flags *flags)
{
    krb5_kvno kvno = KVNO_FAILURE;
    LDAPMessage *mesg;
    char *attrs[] = {"msDS-KeyVersionNumber", NULL};

    ldap_get_computer_attrs(flags, attrs, &mesg);
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

    ldap_get_computer_attrs(flags, attrs, &mesg);

    if (ldap_count_entries(flags->ldap->m_ldap, mesg) == 1) {
        mesg = ldap_first_entry(flags->ldap->m_ldap, mesg);
        pwdLastSet = flags->ldap->get_one_val(mesg, "pwdLastSet");
        VERBOSE("pwdLastSet is %s", pwdLastSet.c_str());
    }
    ldap_msgfree(mesg);
    return pwdLastSet;
}

int ldap_set_supportedEncryptionTypes(std::string dn, msktutil_flags *flags)
{
    LDAPMod *mod_attrs[2];
    LDAPMod attrsupportedEncryptionTypes;
    char *vals_supportedEncryptionTypes[] = { NULL, NULL};
    int ret;

    if (flags->ad_supportedEncryptionTypes != flags->supportedEncryptionTypes) {
        mod_attrs[0] = &attrsupportedEncryptionTypes;
        if (flags->ad_enctypes == VALUE_ON)
            attrsupportedEncryptionTypes.mod_op = LDAP_MOD_REPLACE;
        else
            attrsupportedEncryptionTypes.mod_op = LDAP_MOD_ADD;

        attrsupportedEncryptionTypes.mod_type = "msDs-supportedEncryptionTypes";
        attrsupportedEncryptionTypes.mod_values = vals_supportedEncryptionTypes;
        std::string supportedEncryptionTypes = sform("%d", flags->supportedEncryptionTypes);
        vals_supportedEncryptionTypes[0] = const_cast<char*>(supportedEncryptionTypes.c_str());

        mod_attrs[1] = NULL;

        VERBOSE("DEE dn=%s mod_op=%s old=%d new=%d\n",
                dn.c_str(), (attrsupportedEncryptionTypes.mod_op==LDAP_MOD_REPLACE)?"replace":"add",
                flags->ad_supportedEncryptionTypes, flags->supportedEncryptionTypes);

        VERBOSEldap("calling ldap_modify_ext_s");
        ret = ldap_modify_ext_s(flags->ldap->m_ldap, dn.c_str(), mod_attrs, NULL, NULL);

        if (ret != LDAP_SUCCESS) {
            VERBOSE("ldap_modify_ext_s failed (%s)", ldap_err2string(ret));
        } else {
            flags->ad_enctypes = VALUE_ON;
            flags->ad_supportedEncryptionTypes = flags->supportedEncryptionTypes;
        }

    } else {
        VERBOSE("No need to change msDs-supportedEncryptionTypes they are %d\n",flags->ad_supportedEncryptionTypes);
        ret = LDAP_SUCCESS;
    }

    return ret;
}

int ldap_set_userAccountControl_flag(std::string dn, int mask, msktutil_val value, msktutil_flags *flags)
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
            new_userAcctFlags = old_userAcctFlags ^ mask;
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
    std::string dn;
    LDAPMessage *mesg;
    char *attrs[] = {"distinguishedName", NULL};
    LDAPMod *mod_attrs[2];
    LDAPMod attrServicePrincipalName;
    char *vals_serviceprincipalname[] = { NULL, NULL};
    int ret;


    ldap_get_computer_attrs(flags, attrs, &mesg);
    if (ldap_count_entries(flags->ldap->m_ldap, mesg) == 1) {
        mesg = ldap_first_entry(flags->ldap->m_ldap, mesg);
        dn = flags->ldap->get_one_val(mesg, "distinguishedName");
    }
    ldap_msgfree(mesg);
    if (dn.empty()) {
        fprintf(stderr, "Error: an account for %s was not found\n", flags->hostname.c_str());
        return -1;
    }

    VERBOSE("Checking that adding principal %s to %s won't cause a conflict", principal.c_str(), flags->short_hostname.c_str());
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
            ret = ldap_modify_ext_s(flags->ldap->m_ldap, dn.c_str(), mod_attrs, NULL, NULL);
            if (ret != LDAP_SUCCESS) {
                VERBOSE("ldap_modify_ext_s failed (%s)", ldap_err2string(ret));
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
std::string get_user_dn(msktutil_flags *flags)
{
    std::string dn;
    std::string user;
    char *attrs[] = {"distinguishedName", NULL};
    LDAPMessage *mesg;

    try {
        user = get_user_principal();
    } catch (KRB5Exception &e) {
        VERBOSE("No user principal available.");
        return "";
    }
    std::string filter = sform("(&(objectClass=user)(userPrincipalName=%s))", user.c_str());
    flags->ldap->search(&mesg, flags->base_dn, LDAP_SCOPE_SUBTREE, filter, attrs);

    if (ldap_count_entries(flags->ldap->m_ldap, mesg) == 1) {
        mesg = ldap_first_entry(flags->ldap->m_ldap, mesg);
        dn = flags->ldap->get_one_val(mesg, "distinguishedName");
        VERBOSE("Determined executing user's DN to be %s", dn.c_str());

    }

    ldap_msgfree(mesg);
    return dn;
}


int ldap_check_account_strings(std::string dn, msktutil_flags *flags)
{
    int ret;
    LDAPMod *mod_attrs[6];
    LDAPMod attrDnsHostName;
//    LDAPMod attrDescription;
//    LDAPMod attrManagedBy;
//    LDAPMod attrOperatingSystem;
    char *vals_dnshostname[] = {NULL, NULL};
//    char *vals_description[] = {NULL, NULL};
//    char *vals_managedby[] = {NULL, NULL};
//    char *vals_operatingsystem[] = {NULL, NULL};
    int attr_count = 0;
    std::string owner_dn;
    std::string system_name;


    VERBOSE("Inspecting (and updating) computer account attributes");

    mod_attrs[attr_count++] = &attrDnsHostName;
    attrDnsHostName.mod_op = LDAP_MOD_REPLACE;
    attrDnsHostName.mod_type = "dNSHostName";
    attrDnsHostName.mod_values = vals_dnshostname;
    vals_dnshostname[0] = const_cast<char*>(flags->hostname.c_str());
/*
    if (!flags->description.empty()) {
        mod_attrs[attr_count++] = &attrDescription;
        attrDescription.mod_op = LDAP_MOD_REPLACE;
        attrDescription.mod_type = "description";
        attrDescription.mod_values = vals_description;
        vals_description[0] = const_cast<char*>(flags->description.c_str());
    }
    owner_dn = get_user_dn(flags);
    if (!owner_dn.empty()) {
        mod_attrs[attr_count++] = &attrManagedBy;
        attrManagedBy.mod_op = LDAP_MOD_REPLACE;
        attrManagedBy.mod_type = "managedBy";
        attrManagedBy.mod_values = vals_managedby;
        vals_managedby[0] = const_cast<char*>(owner_dn.c_str());
    }
    system_name = get_host_os();
    if (!system_name.empty()) {
        mod_attrs[attr_count++] = &attrOperatingSystem;
        attrOperatingSystem.mod_op = LDAP_MOD_REPLACE;
        attrOperatingSystem.mod_type = "operatingSystem";
        attrOperatingSystem.mod_values = vals_operatingsystem;
        vals_operatingsystem[0] = const_cast<char*>(system_name.c_str());
    }
*/
    mod_attrs[attr_count++] = NULL;
    VERBOSEldap("calling ldap_modify_ext_s");
    ret = ldap_modify_ext_s(flags->ldap->m_ldap, dn.c_str(), mod_attrs, NULL, NULL);
    if (ret != LDAP_SUCCESS) {
        VERBOSE("ldap_modify_ext_s failed (%s)", ldap_err2string(ret));
    }

    msktutil_val des_only;
    if (flags->supportedEncryptionTypes == (MS_KERB_ENCTYPE_DES_CBC_CRC|MS_KERB_ENCTYPE_DES_CBC_MD5))
        des_only = VALUE_ON;
    else
        des_only = VALUE_OFF;

    ldap_set_userAccountControl_flag(dn, UF_USE_DES_KEY_ONLY, des_only, flags);
    ldap_set_userAccountControl_flag(dn, UF_NO_AUTH_DATA_REQUIRED, flags->no_pac, flags);
    ldap_set_userAccountControl_flag(dn, UF_TRUSTED_FOR_DELEGATION, flags->delegate, flags);

    ldap_set_supportedEncryptionTypes(dn, flags);

    return 0;
}


int ldap_check_account(msktutil_flags *flags)
{
    int ret;
    LDAPMessage *mesg;
    char *attrs[] = {"distinguishedName", "msDs-supportedEncryptionTypes", "userAccountControl", NULL};
    int userAcctFlags;
    std::string dn;
    LDAPMod *mod_attrs[6];
    LDAPMod attrObjectClass;
    LDAPMod attrCN;
    LDAPMod attrUserAccountControl;
    LDAPMod attrSamAccountName;
    char *vals_objectClass[] = {"top", "person", "organizationalPerson", "user", "computer", NULL};
    char *vals_cn[] = {NULL, NULL};
    char *vals_useraccountcontrol[] = {NULL, NULL};
    char *vals_samaccountname[] = {NULL, NULL};
    int attr_count = 0;


    VERBOSE("Checking that a computer account for %s exists", flags->samAccountName.c_str());
    ldap_get_computer_attrs(flags, attrs, &mesg);

    if (ldap_count_entries(flags->ldap->m_ldap, mesg) > 0) {
        /* Account already exists */
        VERBOSE("Checking computer account - found");
        mesg = ldap_first_entry(flags->ldap->m_ldap, mesg);
        dn = flags->ldap->get_one_val(mesg, "distinguishedName");

        std::string uac = flags->ldap->get_one_val(mesg, "userAccountControl");
        if(!uac.empty()) {
            VERBOSE("Found userAccountControl = 0x%x\n",flags->ad_userAccountControl);
            flags->ad_userAccountControl = atoi(uac.c_str());
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
        ldap_msgfree(mesg);
    } else {
        ldap_msgfree(mesg);

        /* No computer account found, so let's add one in the OU specified */

        VERBOSE("Computer account not found, create the account\n");
        fprintf(stdout, "No computer account for %s found, creating a new one.\n", flags->samAccountName_nodollar.c_str());

        dn = sform("cn=%s,%s", flags->samAccountName_nodollar.c_str(), flags->ldap_ou.c_str());
        fprintf(stderr, "dn: %s\n", dn.c_str());
        mod_attrs[attr_count++] = &attrObjectClass;
        attrObjectClass.mod_op = LDAP_MOD_ADD;
        attrObjectClass.mod_type = "objectClass";
        attrObjectClass.mod_values = vals_objectClass;

        mod_attrs[attr_count++] = &attrCN;
        attrCN.mod_op = LDAP_MOD_ADD;
        attrCN.mod_type = "cn";
        attrCN.mod_values = vals_cn;
        vals_cn[0] = const_cast<char*>(flags->samAccountName_nodollar.c_str());

        mod_attrs[attr_count++] = &attrUserAccountControl;
        attrUserAccountControl.mod_op = LDAP_MOD_ADD;
        attrUserAccountControl.mod_type = "userAccountControl";
        attrUserAccountControl.mod_values = vals_useraccountcontrol;
        userAcctFlags = UF_DONT_EXPIRE_PASSWORD | UF_WORKSTATION_TRUST_ACCOUNT;
        std::string userAcctFlags_string = sform("%d", userAcctFlags);
        vals_useraccountcontrol[0] = const_cast<char*>(userAcctFlags_string.c_str());

        mod_attrs[attr_count++] = &attrSamAccountName;
        attrSamAccountName.mod_op = LDAP_MOD_ADD;
        attrSamAccountName.mod_type = "sAMAccountName";
        attrSamAccountName.mod_values = vals_samaccountname;
        vals_samaccountname[0] = const_cast<char*>(flags->samAccountName.c_str());

        mod_attrs[attr_count++] = NULL;

        // Defaults, will attempt to reset later
        flags->ad_supportedEncryptionTypes = MS_KERB_ENCTYPE_DES_CBC_CRC | MS_KERB_ENCTYPE_DES_CBC_MD5 |
            MS_KERB_ENCTYPE_RC4_HMAC_MD5;
        flags->ad_enctypes = VALUE_OFF;

        ret = ldap_add_ext_s(flags->ldap->m_ldap, dn.c_str(), mod_attrs, NULL, NULL);

        if (ret)
            throw LDAPException("ldap_add_ext_s", ret);

        flags->ad_userAccountControl = userAcctFlags;
    }

    ret = ldap_check_account_strings(dn, flags);
    if (ret) {
        fprintf(stderr, "Error: ldap_check_account failed\n");
    }
    return ret;

}
