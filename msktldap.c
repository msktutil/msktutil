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


void get_default_ou(msktutil_flags *flags)
{
    if (flags->ldap_ou.empty()) {
        /* Only do this on an empty value */
        flags->ldap_ou = "CN=Computers";
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


int try_ldap_connect(msktutil_flags *flags, int try_tls)
{
    LDAP *ldap = NULL;
    int version = LDAP_VERSION3;
    int ret;
    sasl_ssf_t ssf = -1; /* indicates we dont know what it is */
    sasl_ssf_t tryssf;


    VERBOSE("Connecting to LDAP server: %s try_tls=%s", flags->server.c_str(),
            (try_tls == ATTEMPT_SASL_NO_TLS)?"NO":"YES");
    std::string ldap_url = "ldap://" + flags->server;

#ifndef SOLARIS_LDAP_KERBEROS
    VERBOSEldap("calling ldap_initialize");
    ret = ldap_initialize(&ldap, ldap_url.c_str());
#else
    VERBOSEldap("calling ldap_init");
    ldap = ldap_init(flags->server, LDAP_PORT);
    if (ldap) ret = LDAP_SUCCESS;
    else ret = LDAP_OTHER;
#endif
    if (ret) {
        fprintf(stderr, "Error: ldap_initialize failed (%s)\n", ldap_err2string(ret));
        return ret;
    }
    ret = ldap_set_option(ldap, LDAP_OPT_PROTOCOL_VERSION, &version);
    if (ret) {
        fprintf(stderr, "Error: ldap_set_option LDAP_OPT_PROTOCOL_VERSION failed (%s)\n", ldap_err2string(ret));
        ldap_unbind_ext(ldap, NULL, NULL);
        return ret;
    }
    ret = ldap_set_option(ldap, LDAP_OPT_REFERRALS, LDAP_OPT_OFF);
    if (ret) {
        fprintf(stderr, "Error: ldap_set_option LDAP_OPT_REFERRALS failed (%s)\n", ldap_err2string(ret));
        ldap_unbind_ext(ldap, NULL, NULL);
        return -1;
    }

#ifdef LDAP_OPT_X_TLS
    switch (try_tls) {
        case ATTEMPT_SASL_PARAMS_TLS:
            tryssf=1;
            if (ldap_set_option(ldap, LDAP_OPT_X_SASL_SSF_MAX, &tryssf)) {
                ldap_unbind_ext(ldap, NULL, NULL);
                return try_ldap_connect(flags, ATTEMPT_SASL_NO_PARAMS_TLS);
            }
            /* fall thru */
        case ATTEMPT_SASL_NO_PARAMS_TLS:
            if (ldap_start_tls_s(ldap, NULL, NULL)) {
                ldap_unbind_ext(ldap, NULL, NULL);
                return try_ldap_connect(flags, ATTEMPT_SASL_NO_TLS);
            }
            break;
        case ATTEMPT_SASL_NO_TLS:
#if 0
            /* TLS did not work, mak sure we dont try it again */
            ret = ldap_set_option(ldap, LDAP_OPT_X_TLS, &notls);
            if (ret) {
                fprintf(stderr, "Error: ldap_set_option LDAP_OPT_X_TLS (%s)\n", ldap_err2string(ret));
            }
#endif

            tryssf=56; /* Will cause gssapi to use at least des encryption */
            ret = ldap_set_option(ldap, LDAP_OPT_X_SASL_SSF_MIN, &tryssf);
            if (ret) {
                fprintf(stderr, "Error: ldap_set_option failed 3 (%s)\n", ldap_err2string(ret));
            }
            break;
    }
#endif
    VERBOSEldap("calling ldap_sasl_interactive_bind_s");
    ret = ldap_sasl_interactive_bind_s(ldap, NULL, "GSSAPI", NULL, NULL,
#ifndef SOLARIS_LDAP_KERBEROS
                    g_verbose?0:LDAP_SASL_QUIET |
#endif
                    LDAP_SASL_INTERACTIVE, sasl_interact, NULL);
    if (ret) {
        fprintf(stderr, "Error: ldap_sasl_interactive_bind_s failed 4 (%s)\n", ldap_err2string(ret));
        ldap_unbind_ext(ldap, NULL, NULL);
        if (try_tls != ATTEMPT_SASL_NO_TLS)
            return try_ldap_connect(flags, ATTEMPT_SASL_NO_TLS);
        return ret;
    }
    ldap_get_option(ldap, LDAP_OPT_X_SASL_SSF,&ssf);
    VERBOSE("LDAP_OPT_X_SASL_SSF=%d\n",ssf)

    flags->ldap = ldap;
    return ret;
}


int ldap_connect(msktutil_flags *flags) {
#ifndef SOLARIS_LDAP_KERBEROS
    int debug = 0xffffff;
    if( g_verbose > 1)
        ldap_set_option( NULL, LDAP_OPT_DEBUG_LEVEL, &debug);
#endif
    VERBOSE("ldap_connect calling try_ldap_connect\n");
    return try_ldap_connect(flags, ATTEMPT_SASL_PARAMS_TLS);
}


void ldap_cleanup(msktutil_flags *flags)
{
    VERBOSE("Disconnecting from LDAP server");
    if (flags->ldap) {
        ldap_unbind_ext(flags->ldap, NULL, NULL);
        flags->ldap = NULL;
        sasl_done();
    }
}

void ldap_get_computer_attrs(msktutil_flags *flags, char **attrs, LDAPMessage **mesg_p) {
    std::string filter;
    filter = sform("(&(objectClass=computer)(sAMAccountName=%s))", flags->samAccountName.c_str());
    VERBOSEldap("calling ldap_search_ext_s %s %s", flags->base_dn.c_str(), filter.c_str());
    int ret = ldap_search_ext_s(flags->ldap, flags->base_dn.c_str(), LDAP_SCOPE_SUBTREE, filter.c_str(), attrs, 0, NULL, NULL, NULL, -1, mesg_p);
    if (ret)
        throw LDAPException("ldap_search_ext_s", ret);
}

int ldap_flush_principals(msktutil_flags *flags)
{
    BerValue **vals;
    std::string dn;
    LDAPMessage *mesg;
    char *attrs[] = {"distinguishedName", NULL};
    LDAPMod *mod_attrs[2];
    LDAPMod attrServicePrincipalName;
    char *vals_serviceprincipalname[] = {NULL};
    int ret;


    VERBOSE("Flushing principals from LDAP entry");
    ldap_get_computer_attrs(flags, attrs, &mesg);

    if (ldap_count_entries(flags->ldap, mesg) == 1) {
        mesg = ldap_first_entry(flags->ldap, mesg);
        vals = ldap_get_values_len(flags->ldap, mesg, "distinguishedName");
        if (vals) {
            if (ldap_count_values_len(vals) > 0) {
                dn = std::string(vals[0]->bv_val);
            }
            ldap_value_free_len(vals);
        }
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
    ret = ldap_modify_ext_s(flags->ldap, dn.c_str(), mod_attrs, NULL, NULL);

    /* Ignore if the attribute doesn't exist, that just means that it's already empty */
    if (ret != LDAP_SUCCESS && ret != LDAP_NO_SUCH_ATTRIBUTE) {
        fprintf(stderr, "Error: ldap_modify_ext_s failed (%s)\n", ldap_err2string(ret));
        return -1;
    }

    return 0;
}


char **ldap_list_principals(msktutil_flags *flags)
{
    BerValue **vals;
    LDAPMessage *mesg;
    char *attrs[] = {"servicePrincipalName", "userPrincipalName", NULL};
    char **principals = NULL;
    int i;
    int j;


    VERBOSE("Listing principals for LDAP entry");
    ldap_get_computer_attrs(flags, attrs, &mesg);

    if (ldap_count_entries(flags->ldap, mesg) == 1) {
        mesg = ldap_first_entry(flags->ldap, mesg);
        vals = ldap_get_values_len(flags->ldap, mesg, "servicePrincipalName");
        if (vals) {
            i = ldap_count_values_len(vals);
            principals = (char **) malloc((i + 2) * sizeof(char *));
            if (!principals) {
                fprintf(stderr, "Error: malloc failed\n");
                ldap_value_free_len(vals);
                ldap_msgfree(mesg);
                return NULL;
            }
            memset(principals, 0, (i + 1) * sizeof(char *));
            for (i = 0; i < ldap_count_values_len(vals); i++) {
                principals[i] = (char *) malloc(strlen(vals[i]->bv_val) + 1);
                if (!principals[i]) {
                    fprintf(stderr, "Error: malloc failed\n");
                    for (i--; i >= 0; i--) {
                        free(principals[i]);
                    }
                    free(principals);
                    ldap_value_free_len(vals);
                    ldap_msgfree(mesg);
                    return NULL;
                }
                memset(principals[i], 0, strlen(vals[i]->bv_val) + 1);
                strcpy(principals[i], vals[i]->bv_val);
                VERBOSE("  Found Principal: %s", principals[i]);
            }
            ldap_value_free_len(vals);
            i++;
            vals = ldap_get_values_len(flags->ldap, mesg, "userPrincipalName");
            if (vals) {
                if (ldap_count_values_len(vals) > 0) {
                    principals[i] = (char *) malloc(strlen(vals[0]->bv_val) + 1);
                    if (!principals[i]) {
                        fprintf(stderr, "Error: malloc failed\n");
                        for (i--; i >= 0; i--) {
                            free(principals[i]);
                        }
                        free(principals);
                        ldap_value_free_len(vals);
                        ldap_msgfree(mesg);
                        return NULL;
                    }
                    memset(principals[i], 0, strlen(vals[0]->bv_val) + 1);
                    strcpy(principals[i], vals[0]->bv_val);
                    for (j = 0; *(principals[i] + j); j++) {
                        if (*(principals[i] + j) == '@') {
                            *(principals[i] + j) = '\0';
                            break;
                        }
                    }
                }
                ldap_value_free_len(vals);
            }
        } else {
            principals = (char **) malloc(2 * sizeof(char *));
            if (!principals) {
                fprintf(stderr, "Error: malloc failed\n");
                ldap_value_free_len(vals);
                ldap_msgfree(mesg);
                return NULL;
            }
            memset(principals, 0, 2 * sizeof(char *));
            vals = ldap_get_values_len(flags->ldap, mesg, "userPrincipalName");
            if (vals) {
                if (ldap_count_values_len(vals) > 0) {
                    principals[0] = (char *) malloc(strlen(vals[0]->bv_val) + 1);
                    if (!principals[0]) {
                        fprintf(stderr, "Error: malloc failed\n");
                        free(principals);
                        ldap_value_free_len(vals);
                        ldap_msgfree(mesg);
                        return NULL;
                    }
                    memset(principals[0], 0, strlen(vals[0]->bv_val) + 1);
                    strcpy(principals[0], vals[0]->bv_val);
                    for (j = 0; *(principals[0] + j); j++) {
                        if (*(principals[0] + j) == '@') {
                            *(principals[0] + j) = '\0';
                            break;
                        }
                    }
                    VERBOSE("  Found Principal: %s", principals[0]);
                    ldap_value_free_len(vals);
                }
            }
        }
    }
    ldap_msgfree(mesg);

    return principals;
}


krb5_kvno ldap_get_kvno(msktutil_flags *flags)
{
    krb5_kvno kvno = KVNO_FAILURE;
    BerValue **vals;
    LDAPMessage *mesg;
    char *attrs[] = {"distinguishedName", "msDS-KeyVersionNumber", NULL};

    ldap_get_computer_attrs(flags, attrs, &mesg);
    if (ldap_count_entries(flags->ldap, mesg) == 1) {
        mesg = ldap_first_entry(flags->ldap, mesg);
        vals = ldap_get_values_len(flags->ldap, mesg, "msDS-KeyVersionNumber");
        if (vals) {
            if (ldap_count_values_len(vals) > 0) {
                kvno = (krb5_kvno) atoi(vals[0]->bv_val);
            }
            ldap_value_free_len(vals);
        } else {
            /* This must be a Windows 2000 domain, which does support have KVNO's. */
            kvno = KVNO_WIN_2000;
            VERBOSE("Unable to find KVNO attribute on domain controller %s - This must be running windows 2000", flags->server.c_str());
        }
    }
    ldap_msgfree(mesg);

    VERBOSE("KVNO is %d", kvno);
    return kvno;
}


int ldap_get_des_bit(msktutil_flags *flags)
{
    int des_bit = 0;
    BerValue **vals;
    LDAPMessage *mesg;
    char *attrs[] = {"userAccountControl", NULL};


    ldap_get_computer_attrs(flags, attrs, &mesg);
    if (ldap_count_entries(flags->ldap, mesg) == 1) {
        mesg = ldap_first_entry(flags->ldap, mesg);
        vals = ldap_get_values_len(flags->ldap, mesg, "userAccountControl");
        if (vals) {
            if (ldap_count_values_len(vals) > 0) {
                des_bit = (atoi(vals[0]->bv_val) & UF_USE_DES_KEY_ONLY) ? 1 : 0;
            }
            ldap_value_free_len(vals);
        }
    }
    ldap_msgfree(mesg);

    VERBOSE("Determined DES-only flag is %d", des_bit);
    return des_bit;
}

char *ldap_get_pwdLastSet(msktutil_flags *flags)
{
    char *pwdLastSet = NULL;
    BerValue **vals;
    LDAPMessage *mesg;
    char *attrs[] = {"pwdLastSet", NULL};


    ldap_get_computer_attrs(flags, attrs, &mesg);

    if (ldap_count_entries(flags->ldap, mesg) == 1) {
        mesg = ldap_first_entry(flags->ldap, mesg);
        vals = ldap_get_values_len(flags->ldap, mesg, "pwdLastSet");
        if (vals) {
            if (ldap_count_values_len(vals) > 0) {
                pwdLastSet = (char *) malloc(strlen(vals[0]->bv_val) + 1);
                if (!pwdLastSet) {
                    fprintf(stderr, "Error: malloc failed\n");
                    ldap_value_free_len(vals);
                    ldap_msgfree(mesg);
                    return pwdLastSet;
                }
                memset(pwdLastSet, 0, strlen(vals[0]->bv_val) + 1);
                strcpy(pwdLastSet, vals[0]->bv_val);
                VERBOSE("pwdLastSet is %s", pwdLastSet);
            }
            ldap_value_free_len(vals);
        }
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
        vals_supportedEncryptionTypes[0] = (char *) malloc(17);
        if (!vals_supportedEncryptionTypes[0]) {
            fprintf(stderr, "Error: malloc failed\n");
            return ENOMEM;
        }
        memset(vals_supportedEncryptionTypes[0], 0, 17);
        sprintf(vals_supportedEncryptionTypes[0], "%d", flags->supportedEncryptionTypes);

        mod_attrs[1] = NULL;

        VERBOSE("DEE dn=%s mod_op=%s old=%d new=%d\n",
                dn.c_str(), (attrsupportedEncryptionTypes.mod_op==LDAP_MOD_REPLACE)?"replace":"add",
                flags->ad_supportedEncryptionTypes, flags->supportedEncryptionTypes);

        VERBOSEldap("calling ldap_modify_ext_s");
        ret = ldap_modify_ext_s(flags->ldap, dn.c_str(), mod_attrs, NULL, NULL);
        free(vals_supportedEncryptionTypes[0]);
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
    vals_useraccountcontrol[0] = (char *) malloc(17);
    if (!vals_useraccountcontrol[0]) {
        fprintf(stderr, "Error: malloc failed\n");
        return ENOMEM;
    }
    memset(vals_useraccountcontrol[0], 0, 17);
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
    sprintf(vals_useraccountcontrol[0], "%d", new_userAcctFlags);

    mod_attrs[1] = NULL;

    if (new_userAcctFlags != old_userAcctFlags) {
        VERBOSEldap("calling ldap_modify_ext_s");
        ret = ldap_modify_ext_s(flags->ldap, dn.c_str(), mod_attrs, NULL, NULL);
        if (ret != LDAP_SUCCESS) {
            VERBOSE("ldap_modify_ext_s failed (%s)", ldap_err2string(ret));
        } else {
            flags->ad_userAccountControl = new_userAcctFlags;
        }
    } else {
        VERBOSE(" userAccountControl not changed 0x%x\n", new_userAcctFlags);
        ret = LDAP_SUCCESS;
    }

    free(vals_useraccountcontrol[0]);
    return ret;
}



int ldap_add_principal(const std::string &principal, msktutil_flags *flags)
{
    BerValue **vals;
    char *dn = NULL;
    LDAPMessage *mesg;
    char *attrs[] = {"distinguishedName", NULL};
    LDAPMod *mod_attrs[2];
    LDAPMod attrServicePrincipalName;
    char *vals_serviceprincipalname[] = { NULL, NULL};
    int ret;


    ldap_get_computer_attrs(flags, attrs, &mesg);
    if (ldap_count_entries(flags->ldap, mesg) == 1) {
        mesg = ldap_first_entry(flags->ldap, mesg);
        vals = ldap_get_values_len(flags->ldap, mesg, "distinguishedName");
        if (vals) {
            if (ldap_count_values_len(vals) > 0) {
                dn = (char *) malloc(strlen(vals[0]->bv_val) + 1);
                if (!dn) {
                    fprintf(stderr, "Error: malloc failed\n");
                    ldap_msgfree(mesg);
                    return ENOMEM;
                }
                memset(dn, 0, strlen(vals[0]->bv_val) + 1);
                strcpy(dn, vals[0]->bv_val);
            }
            ldap_value_free_len(vals);
        }
    }
    ldap_msgfree(mesg);
    if (!dn) {
        fprintf(stderr, "Error: an account for %s was not found\n", flags->hostname.c_str());
        return -1;
    }

    VERBOSE("Checking that adding principal %s to %s won't cause a conflict", principal.c_str(), flags->short_hostname.c_str());
    std::string filter = sform("(servicePrincipalName=%s)", principal.c_str());
    VERBOSEldap("calling ldap_search_ext_s");
    ret = ldap_search_ext_s(flags->ldap, flags->base_dn.c_str(), LDAP_SCOPE_SUBTREE, filter.c_str(), attrs, 0, NULL, NULL, NULL, -1, &mesg);

    if (ret) {
        fprintf(stderr, "Error: ldap_search_ext_s failed (%s)\n", ldap_err2string(ret));
        return ret;
    }
    switch (ldap_count_entries(flags->ldap, mesg)) {
        case 0:
            VERBOSE("Adding principal %s to LDAP entry", principal.c_str());
            mod_attrs[0] = &attrServicePrincipalName;
            attrServicePrincipalName.mod_op = LDAP_MOD_ADD;
            attrServicePrincipalName.mod_type = "servicePrincipalName";
            attrServicePrincipalName.mod_values = vals_serviceprincipalname;
            vals_serviceprincipalname[0] = const_cast<char*>(principal.c_str());

            mod_attrs[1] = NULL;

            VERBOSEldap("calling ldap_modify_ext_s");
            ret = ldap_modify_ext_s(flags->ldap, dn, mod_attrs, NULL, NULL);
            free(dn);
            if (ret != LDAP_SUCCESS) {
                VERBOSE("ldap_modify_ext_s failed (%s)", error_message(ret));
            }

            return ret;
        case 1:
            /* Check if we are the owner of the this principal or not */
            mesg = ldap_first_entry(flags->ldap, mesg);
            vals = ldap_get_values_len(flags->ldap, mesg, "distinguishedName");
            if (vals) {
                if (ldap_count_values_len(vals) > 0) {
                    ret = strcmp(dn, vals[0]->bv_val);
                    if (ret) {
                        fprintf(stderr, "Error: Another computer account (%s) has the principal %s\n",
                                vals[0]->bv_val, principal.c_str());
                    }
                } else {
                    fprintf(stderr, "Error: Inconsistent LDAP entry: No DN value present\n");
                    ret = -1;
                }
                ldap_value_free_len(vals);
            }
            free(dn);
            ldap_msgfree(mesg);
            return ret;
        default:
            ret = ldap_count_entries(flags->ldap, mesg);
            fprintf(stderr, "Error: Multiple (%d) LDAP entries were found containing the principal %s\n",
                    ret, principal.c_str());
            ldap_msgfree(mesg);
            free(dn);
            return ret;
    }
}


std::string get_user_dn(msktutil_flags *flags)
{
    int ret;
    std::string dn;
    std::string user;
    char *attrs[] = {"distinguishedName", NULL};
    BerValue **vals;
    LDAPMessage *mesg;


    user = get_user_principal();

    std::string filter = sform("(&(objectClass=user)(userPrincipalName=%s))", user.c_str());
    VERBOSEldap("calling ldap_search_ext_s");
    ret = ldap_search_ext_s(flags->ldap, flags->base_dn.c_str(), LDAP_SCOPE_SUBTREE, filter.c_str(), attrs, 0, NULL, NULL, NULL, -1, &mesg);

    if (ret) {
        fprintf(stderr, "Error: ldap_search_ext_s failed (%s)\n", ldap_err2string(ret));
        return NULL;
    }
    if (ldap_count_entries(flags->ldap, mesg) == 1) {
        mesg = ldap_first_entry(flags->ldap, mesg);
        vals = ldap_get_values_len(flags->ldap, mesg, "distinguishedName");
        if (vals) {
            if (ldap_count_values_len(vals) > 0) {
                dn = std::string(vals[0]->bv_val);
                VERBOSE("Determined executing user's DN to be %s", dn.c_str());
            }
            ldap_value_free_len(vals);
        }
    }

    ldap_msgfree(mesg);
    return dn;
}


int ldap_check_account_strings(std::string dn, msktutil_flags *flags)
{
    int ret;
    LDAPMod *mod_attrs[6];
    LDAPMod attrUserPrincipalName;
    LDAPMod attrDnsHostName;
    LDAPMod attrDescription;
    LDAPMod attrManagedBy;
    LDAPMod attrOperatingSystem;
    char *vals_userprincipalname[] = {NULL, NULL};
    char *vals_dnshostname[] = {NULL, NULL};
    char *vals_description[] = {NULL, NULL};
    char *vals_managedby[] = {NULL, NULL};
    char *vals_operatingsystem[] = {NULL, NULL};
    int attr_count = 0;
    std::string owner_dn;
    std::string system_name;


    VERBOSE("Inspecting (and updating) computer account attributes");
    /* Set the UPN value, just in case something has changed it */
    mod_attrs[attr_count++] = &attrUserPrincipalName;
    attrUserPrincipalName.mod_op = LDAP_MOD_REPLACE;
    attrUserPrincipalName.mod_type = "userPrincipalName";
    attrUserPrincipalName.mod_values = vals_userprincipalname;
    vals_userprincipalname[0] = const_cast<char*>(flags->userPrincipalName.c_str());

    mod_attrs[attr_count++] = &attrDnsHostName;
    attrDnsHostName.mod_op = LDAP_MOD_REPLACE;
    attrDnsHostName.mod_type = "dNSHostName";
    attrDnsHostName.mod_values = vals_dnshostname;
    vals_dnshostname[0] = const_cast<char*>(flags->hostname.c_str());

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

    mod_attrs[attr_count++] = NULL;
    VERBOSEldap("calling ldap_modify_ext_s");
    ret = ldap_modify_ext_s(flags->ldap, dn.c_str(), mod_attrs, NULL, NULL);
    if (ret != LDAP_SUCCESS) {
        VERBOSE("ldap_modify_ext_s failed (%s)", error_message(ret));
    }

    ldap_set_userAccountControl_flag(dn, UF_USE_DES_KEY_ONLY, flags->des_bit, flags);
    ldap_set_userAccountControl_flag(dn, UF_NO_AUTH_DATA_REQUIRED, flags->no_pac, flags);
    ldap_set_userAccountControl_flag(dn, UF_TRUSTED_FOR_DELEGATION, flags->delegate, flags);

    ldap_set_supportedEncryptionTypes(dn, flags);

    return 0;
}


int ldap_check_account(msktutil_flags *flags)
{
    BerValue **vals;
    LDAPMessage *mesg;
    char *attrs[] = {"distinguishedName", "msDs-supportedEncryptionTypes", "userAccountControl", NULL};
    int ret;
    int userAcctFlags;
    std::string dn;
    LDAPMod *mod_attrs[6];
    LDAPMod attrObjectClass;
    LDAPMod attrCN;
    LDAPMod attrUserAccountControl;
    LDAPMod attrSamAccountName;
    LDAPMod attrsupportedEncryptionTypes;
    char *vals_objectClass[] = {"top", "person", "organizationalPerson", "user", "computer", NULL};
    char *vals_cn[] = {NULL, NULL};
    char *vals_useraccountcontrol[] = {NULL, NULL};
    char *vals_samaccountname[] = {NULL, NULL};
    char *vals_supportedEncryptionTypes[] = {NULL, NULL};
    int attr_count = 0;


    VERBOSE("Checking that a computer account for %s exists", flags->samAccountName.c_str());
    ldap_get_computer_attrs(flags, attrs, &mesg);

    if (ldap_count_entries(flags->ldap, mesg) > 0) {
        /* Account already exists */
        VERBOSE("Checking computer account - found");
        mesg = ldap_first_entry(flags->ldap, mesg);
        vals = ldap_get_values_len(flags->ldap, mesg, "distinguishedName");
        if (vals) {
            if (ldap_count_values_len(vals) > 0) {
                dn = std::string(vals[0]->bv_val);
            }
            ldap_value_free_len(vals);
        }
        /* save the current userAccountControl */
        vals = ldap_get_values_len(flags->ldap, mesg, "userAccountControl");
        if (vals) {
            if (ldap_count_values_len(vals) > 0) {
                flags->ad_userAccountControl = atoi(vals[0]->bv_val);
                VERBOSE("Found userAccountControl = 0x%x\n",flags->ad_userAccountControl);
            }
            ldap_value_free_len(vals);
        }
        /* save the current msDs-supportedEncryptionTypes */
        vals = ldap_get_values_len(flags->ldap, mesg, "msDs-supportedEncryptionTypes");
        if (vals) {
            if (ldap_count_values_len(vals) > 0) {
                flags->ad_supportedEncryptionTypes = atoi(vals[0]->bv_val);
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
                VERBOSE("Defaulting supportedEncryptionTypes = %d\n",
                        flags->ad_supportedEncryptionTypes);
            }
            ldap_value_free_len(vals);
        }

        ldap_msgfree(mesg);
    } else {
        ldap_msgfree(mesg);

        /* No computer account found, so let's add one in the OU specified */

        VERBOSE("Computer account not found, create the account\n");
        fprintf(stdout, "No computer account for %s found, creating a new one.\n", flags->samAccountName_nodollar.c_str());

        dn = sform("cn=%s,%s,%s", flags->samAccountName_nodollar.c_str(), flags->ldap_ou.c_str(), flags->base_dn.c_str());

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
        vals_useraccountcontrol[0] = (char *) malloc(17);
        if (!vals_useraccountcontrol[0]) {
            fprintf(stderr, "Error: malloc failed\n");
            return ENOMEM;
        }
        memset(vals_useraccountcontrol[0], 0, 17);
        userAcctFlags = UF_DONT_EXPIRE_PASSWORD | UF_WORKSTATION_TRUST_ACCOUNT;
        sprintf(vals_useraccountcontrol[0], "%d", userAcctFlags);

        mod_attrs[attr_count++] = &attrSamAccountName;
        attrSamAccountName.mod_op = LDAP_MOD_ADD;
        attrSamAccountName.mod_type = "sAMAccountName";
        attrSamAccountName.mod_values = vals_samaccountname;
        vals_samaccountname[0] = const_cast<char*>(flags->samAccountName.c_str());

        if (flags->enctypes != VALUE_IGNORE) {
            mod_attrs[attr_count++] = &attrsupportedEncryptionTypes;
            attrsupportedEncryptionTypes.mod_op = LDAP_MOD_ADD;
            attrsupportedEncryptionTypes.mod_type = "msDs-supportedEncryptionTypes";
            attrsupportedEncryptionTypes.mod_values = vals_supportedEncryptionTypes;
            vals_supportedEncryptionTypes[0] = (char *) malloc(17);
            if (!vals_supportedEncryptionTypes[0]) {
                fprintf(stderr, "Error: malloc failed\n");
                return ENOMEM;
            }
            memset(vals_supportedEncryptionTypes[0], 0, 17);
            sprintf(vals_supportedEncryptionTypes[0], "%d", flags->supportedEncryptionTypes);
        }
        mod_attrs[attr_count++] = NULL;

        ret = ldap_add_ext_s(flags->ldap, dn.c_str(), mod_attrs, NULL, NULL);
        free(vals_useraccountcontrol[0]);
        if (vals_supportedEncryptionTypes[0])
            free(vals_supportedEncryptionTypes[0]);
        if (ret) {
            fprintf(stderr, "Error: ldap_add_ext_s failed (%s)\n", ldap_err2string(ret));
            return ret;

        }
        flags->ad_userAccountControl = userAcctFlags;
        if (flags->enctypes != VALUE_IGNORE) { /* we wrote one above */
            flags->ad_enctypes = VALUE_ON;
            flags->ad_supportedEncryptionTypes = flags->supportedEncryptionTypes;
        } else {
            flags->ad_enctypes = VALUE_OFF; /* did not write one, so the default */
            flags->ad_supportedEncryptionTypes = flags->supportedEncryptionTypes;
        }
    }

    ret = ldap_check_account_strings(dn, flags);
    if (ret) {
        fprintf(stderr, "Error: ldap_check_account failed\n");
    }
    return ret;

}
