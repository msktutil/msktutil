/*
 *----------------------------------------------------------------------------
 *
 * msktldap.cpp
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
#include <algorithm>
#include <sstream>
#include <iostream>

/* Check if string <s> ends with string <suffix> */
static bool endswith(std::string const &s, std::string const &suffix)
{
    if (s.length() < suffix.length())
        return false;
    return s.compare(s.length() - suffix.length(),
                     suffix.length(), suffix) == 0;
}

void get_default_ou(msktutil_flags *flags)
{
    /* If OU was given explicitly, we just need to make sure it's a
     * valid dn below our base dn.
     */
    if (!flags->ldap_ou.empty()) {
        if (!endswith(flags->ldap_ou, flags->base_dn))
            flags->ldap_ou = flags->ldap_ou + "," + flags->base_dn;
        VERBOSE("Using OU: %s", flags->ldap_ou.c_str());
	return;
    }

    /* Otherwise, probe AD for its default OU */

    LDAPConnection *ldap = flags->ldap;

    std::string wkguid;
    if (flags->use_service_account) {
        wkguid = sform("<WKGUID=a9d1ca15768811d1aded00c04fd8d5cd,%s>",
                       flags->base_dn.c_str());
    } else {
        wkguid = sform("<WKGUID=aa312825768811d1aded00c04fd8d5cd,%s>",
                       flags->base_dn.c_str());
    }
    LDAPMessage *mesg = ldap->search(wkguid, LDAP_SCOPE_BASE,
                                     "objectClass=*",
                                     "distinguishedName");

    std::string dn;
    if (ldap->count_entries(mesg) == 1) {
        mesg = ldap->first_entry(mesg);
        dn = ldap->get_one_val(mesg, "distinguishedName");
    }
    ldap_msgfree(mesg);
    if (dn.empty()) {
        fprintf(stderr,
                "Warning: could not get default computer OU from AD.\n"
            );
        std::string default_ou = flags->use_service_account ?
                                 "CN=Users," : "CN=Computers,";
        flags->ldap_ou = default_ou + flags->base_dn;
    } else {
        flags->ldap_ou = dn;
    }
    VERBOSE("Determining default OU: %s", flags->ldap_ou.c_str());
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

void ldap_cleanup(msktutil_flags *flags)
{
    VERBOSE("Disconnecting from LDAP server");
    delete flags->ldap;
    flags->ldap = NULL;
}

LDAPMessage* ldap_get_account_attrs(const msktutil_flags* flags,
                                    const char **attrs)
{
    std::string filter = sform("(&(|(objectCategory=Computer)"
                               "(objectCategory=User))(sAMAccountName=%s))",
                               flags->sAMAccountName.c_str());
    return flags->ldap->search(flags->base_dn,
                               LDAP_SCOPE_SUBTREE,
                               filter,
                               attrs);
}

LDAPMessage* ldap_get_account_attrs(const msktutil_flags* flags,
                                    const std::string& attr)
{
    std::string filter = sform("(&(|(objectCategory=Computer)"
                               "(objectCategory=User))"
                               "(sAMAccountName=%s))",
                               flags->sAMAccountName.c_str());
    return flags->ldap->search(flags->base_dn,
                               LDAP_SCOPE_SUBTREE,
                               filter, attr);
}


int ldap_flush_principals(msktutil_flags *flags)
{
    std::string dn;

    int ret;

    VERBOSE("Flushing principals from LDAP entry");
    LDAPMessage *mesg = ldap_get_account_attrs(flags, "distinguishedName");

    if (flags->ldap->count_entries(mesg) == 1) {
        mesg = flags->ldap->first_entry(mesg);
        dn = flags->ldap->get_one_val(mesg, "distinguishedName");
    }
    ldap_msgfree(mesg);
    if (dn.empty()) {
        fprintf(stderr,
                "Error: an account for %s was not found\n",
                flags->sAMAccountName.c_str()
            );
        return -1;
    }

    ret = flags->ldap->flush_attr_no_check(dn, "servicePrincipalName");

    /* Ignore if the attribute doesn't exist, that just means that
     * it's already empty */
    if (ret != LDAP_SUCCESS && ret != LDAP_NO_SUCH_ATTRIBUTE) {
        flags->ldap->print_diagnostics("ldap_modify_ext_s failed", ret);
        return -1;
    }

    return 0;
}


krb5_kvno ldap_get_kvno(msktutil_flags *flags)
{
    krb5_kvno kvno = KVNO_FAILURE;
    LDAPConnection *ldap = flags->ldap;

    LDAPMessage *mesg = ldap_get_account_attrs(flags, "msDS-KeyVersionNumber");
    if (ldap->count_entries(mesg) == 1) {
        mesg = flags->ldap->first_entry(mesg);
        std::string kvno_str = flags->ldap->get_one_val(mesg,
                                                        "msDS-KeyVersionNumber");
        if (!kvno_str.empty())
            kvno = (krb5_kvno) atoi(kvno_str.c_str());
        else {
            /* This must be a Windows 2000 domain, which does support
             * have KVNO's. */
            kvno = KVNO_WIN_2000;
            VERBOSE("Unable to find KVNO attribute on domain controller "
                    "%s - This must be running windows 2000",
                    flags->server.c_str());
        }
    }
    ldap_msgfree(mesg);

    VERBOSE("KVNO is %d", kvno);
    return kvno;
}


std::string ldap_get_pwdLastSet(msktutil_flags *flags)
{
    std::string pwdLastSet;

    const char *attrs[] = {"pwdLastSet", NULL};
    LDAPConnection *ldap = flags->ldap;

    LDAPMessage *mesg = ldap_get_account_attrs(flags, attrs);

    if (ldap->count_entries(mesg) == 1) {
        mesg = ldap->first_entry(mesg);
        pwdLastSet = ldap->get_one_val(mesg, "pwdLastSet");
        VERBOSE("pwdLastSet is %s", pwdLastSet.c_str());
    }
    ldap_msgfree(mesg);
    return pwdLastSet;
}


int ldap_simple_set_attr(const std::string &dn,
                         const std::string &attrName,
                         const std::string &val,
                         msktutil_flags *flags)
{
    int ret = flags->ldap->simple_set_attr(dn, attrName, val);

    if (ret != LDAP_SUCCESS) {
        fprintf(stderr, "WARNING: ldap modification of %s\n", dn.c_str());
        fprintf(stderr, "         failed while trying to change %s to %s.\n",
                attrName.c_str(), val.c_str());
        fprintf(stderr, "         Error was: %s\n", ldap_err2string(ret));
        fprintf(stderr, "         --> Do you have enough privileges?\n");
        fprintf(stderr, "         --> You might try re-\"kinit\"ing.\n");
        if (!flags->user_creds_only) {
            fprintf(stderr, "         --> Maybe you should try again with "
                    "--user-creds-only?\n");
        }

        if (attrName == "userPrincipalName") {
            fprintf(stderr, "ERROR:   Can't continue with wrong UPN\n");
            exit(1);
        } else {
            fprintf(stderr, "         Continuing anyway ...\n");
        }
    }

    return ret;
}


int ldap_set_supportedEncryptionTypes(const std::string &dn,
                                      msktutil_flags *flags)
{
    int ret;

    if (flags->ad_supportedEncryptionTypes !=
        flags->supportedEncryptionTypes) {
        std::string supportedEncryptionTypes = sform("%d",
                                                     flags->supportedEncryptionTypes);

        ret = ldap_simple_set_attr(dn, "msDs-supportedEncryptionTypes",
                                   supportedEncryptionTypes, flags);
        if (ret == LDAP_SUCCESS) {
            flags->ad_enctypes = VALUE_ON;
            flags->ad_supportedEncryptionTypes =
                flags->supportedEncryptionTypes;
        }
    } else {
        VERBOSE("No need to change msDs-supportedEncryptionTypes they "
                "are %d",
                flags->ad_supportedEncryptionTypes);
        ret = LDAP_SUCCESS;
    }

    return ret;
}


int ldap_set_userAccountControl_flag(const std::string &dn,
                                     int mask,
                                     msktutil_val value,
                                     msktutil_flags *flags)
{
    int ret;
    unsigned new_userAcctFlags;

    /* Skip this value if its not to change */
    if (value == VALUE_IGNORE) {
        return 0;
    }
    new_userAcctFlags = flags->ad_userAccountControl;

    switch (value) {
        case VALUE_ON:
            VERBOSE("Setting userAccountControl bit at 0x%x to 0x%x",
                    mask,
                    value);
            new_userAcctFlags |= mask;
            break;
        case VALUE_OFF:
            VERBOSE("Setting userAccountControl bit at 0x%x to 0x%x",
                    mask,
                    value);
            new_userAcctFlags &= ~mask;
            break;
        case VALUE_IGNORE:
            /* Unreachable */
            break;
    }

    if (new_userAcctFlags != flags->ad_userAccountControl) {
        std::string new_userAcctFlags_string = sform("%d", new_userAcctFlags);

        ret = flags->ldap->simple_set_attr(dn,
                                           "userAccountControl",
                                           new_userAcctFlags_string);
        if (ret == LDAP_SUCCESS) {
            flags->ad_userAccountControl = new_userAcctFlags;
        }
    } else {
        VERBOSE("userAccountControl not changed 0x%x", new_userAcctFlags);
        ret = LDAP_SUCCESS;
    }

    return ret;
}


int ldap_add_principal(const std::string &principal, msktutil_flags *flags)
{
    int ret;
    LDAPConnection *ldap = flags->ldap;
    std::string dn = flags->ad_computerDn;

    VERBOSE("Checking that adding principal %s to %s won't cause a conflict",
            principal.c_str(),
            flags->sAMAccountName.c_str());
    std::string filter = sform("(servicePrincipalName=%s)", principal.c_str());
    LDAPMessage *mesg = ldap->search(flags->base_dn,
                                     LDAP_SCOPE_SUBTREE,
                                     filter,
                                     "distinguishedName");
    int num_entries = ldap->count_entries(mesg);
    switch (num_entries) {
        case 0:
            VERBOSE("Adding principal %s to LDAP entry", principal.c_str());
            ret = ldap->add_attr(dn, "servicePrincipalName", principal);
            if (ret != LDAP_SUCCESS) {
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
            break;
        case 1: {
            /* Check if we are the owner of the this principal or
             * not */
            mesg = ldap->first_entry(mesg);
            std::string found_dn = flags->ldap->get_one_val(mesg,
                                                            "distinguishedName");
            if (found_dn.empty()) {
                fprintf(stderr,
                        "Error: Inconsistent LDAP entry: No DN value present\n"
                    );
                ret = -1;
            } else if (dn != found_dn) {
                fprintf(stderr,
                        "Error: Another computer account (%s) has the "
                        "principal %s\n",
                        found_dn.c_str(),
                        principal.c_str()
                    );
                ret = -1;
            } else
                ret = 0;
            break;
        }
        default:
            fprintf(stderr,
                    "Error: Multiple (%d) LDAP entries were found containing "
                    "the principal %s\n",
                    num_entries,
                    principal.c_str()
                );
            ret = num_entries;
    }
    ldap_msgfree(mesg);
    return ret;
}

int ldap_remove_principal(const std::string &principal, msktutil_flags *flags)
{
    VERBOSE("Removing servicePrincipalName %s from %s",
            principal.c_str(),
            flags->ad_computerDn.c_str());

    int ret = flags->ldap->remove_attr(flags->ad_computerDn,
                                       "servicePrincipalName",
                                       principal);
    if (ret == LDAP_SUCCESS) {
        flags->ad_principals.erase(
            std::remove(flags->ad_principals.begin(),
                        flags->ad_principals.end(),
                        principal),
            flags->ad_principals.end()
            );
    }
    return ret;
}


void ldap_check_account_strings(msktutil_flags *flags)
{
    const std::string &dn = flags->ad_computerDn;
    LDAPConnection *ldap = flags->ldap;

    if (flags->use_service_account) {
        VERBOSE("Inspecting (and updating) service account attributes");
    } else {
        VERBOSE("Inspecting (and updating) computer account attributes");
    }

    /*  NOTE: failures to set all the attributes in this function are
     *  ignored, for better or worse... But failure to set
     *  userPrincipalName is not ignored */

    /* don't set dnsHostName on service accounts or if requested not to do it */
    if (!flags->use_service_account && !flags->dont_update_dnshostname) {
        if (!flags->hostname.empty() &&
            flags->hostname != flags->ad_dnsHostName) {
            ldap_simple_set_attr(dn, "dNSHostName", flags->hostname, flags);
        }
    }

    if (!flags->description.empty()) {
        ldap_simple_set_attr(dn, "description", flags->description, flags);
    }

    if (flags->set_userPrincipalName) {
        std::string userPrincipalName_string = "";
        std::string upn_found = "";
        const char *attrs[] = {"userPrincipalName", NULL};
        if (flags->userPrincipalName.find("@") != std::string::npos) {
            userPrincipalName_string = sform("%s",
                                             flags->userPrincipalName.c_str());
        } else {
            userPrincipalName_string = sform("%s@%s",
                                             flags->userPrincipalName.c_str(),
                                             flags->realm_name.c_str());
        }
        /* let's see if userPrincipalName is already set to the
         * desired value in AD... */
        LDAPMessage *mesg = ldap_get_account_attrs(flags, attrs);
        if (ldap->count_entries(mesg) == 1) {
            mesg = ldap->first_entry(mesg);
            upn_found = ldap->get_one_val(mesg, "userPrincipalName");
        }
        ldap_msgfree(mesg);
        VERBOSE("Found userPrincipalName = %s", upn_found.c_str());
        VERBOSE("userPrincipalName should be %s",
                userPrincipalName_string.c_str());
        if (upn_found.compare(userPrincipalName_string)) {
            ldap_simple_set_attr(dn,
                                 "userPrincipalName",
                                 userPrincipalName_string,
                                 flags);
        } else {
            VERBOSE("Nothing to do");
        }
    }
    ldap_set_supportedEncryptionTypes(dn, flags);

    msktutil_val des_only;
    if (flags->supportedEncryptionTypes == MS_KERB_DES_ENCTYPES) {
        des_only = VALUE_ON;
    } else {
        des_only = VALUE_OFF;
    }

    ldap_set_userAccountControl_flag(dn, UF_USE_DES_KEY_ONLY, des_only, flags);
    /* If msDS-supportedEncryptionTypes isn't set, ad_enctypes will be
     * VALUE_OFF. In that case, reset ad_supportedEncryptionTypes
     * according to the DES flag, in case we changed it. */
    if (flags->ad_enctypes == VALUE_OFF) {
        flags->ad_supportedEncryptionTypes = MS_KERB_DES_ENCTYPES;
        if (!(flags->ad_userAccountControl & UF_USE_DES_KEY_ONLY)) {
            flags->ad_supportedEncryptionTypes |= MS_KERB_ENCTYPE_RC4_HMAC_MD5;
        }
    }

    ldap_set_userAccountControl_flag(dn,
                                     UF_NO_AUTH_DATA_REQUIRED,
                                     flags->no_pac,
                                     flags);
    ldap_set_userAccountControl_flag(dn,
                                     UF_TRUSTED_FOR_DELEGATION,
                                     flags->delegate,
                                     flags);
    ldap_set_userAccountControl_flag(dn,
                                     UF_DONT_EXPIRE_PASSWORD,
                                     flags->dont_expire_password,
                                     flags);
    ldap_set_userAccountControl_flag(dn,
                                     UF_ACCOUNT_DISABLE,
                                     flags->disable_account,
                                     flags);
}

template<typename T, size_t N>
T * myend(T (&ra)[N]) {
    return ra + N;
}

bool ldap_check_account(msktutil_flags *flags)
{
    LDAPMessage *mesg;
    const char *machine_attrs[] = {"distinguishedName",
                                   "dNSHostName",
                                   "msDs-supportedEncryptionTypes",
                                   "userAccountControl",
                                   "servicePrincipalName",
                                   "userPrincipalName",
                                   NULL};
    const char *user_attrs[] = {"distinguishedName",
                                "msDs-supportedEncryptionTypes",
                                "userAccountControl",
                                "servicePrincipalName",
                                "userPrincipalName",
                                "unicodePwd",
                                NULL};

    std::string dn;

    const char *vals_objectClass[] = {"top",
                                      "person",
                                      "organizationalPerson",
                                      "user"};

    std::vector<std::string> v_user_objectClass(vals_objectClass,
                                                myend(vals_objectClass));
    std::vector<std::string> v_machine_objectClass(vals_objectClass,
                                                   myend(vals_objectClass));
    v_machine_objectClass.push_back("computer");

    LDAPConnection *ldap = flags->ldap;

    if (flags->use_service_account) {
        VERBOSE("Checking that a service account for %s exists",
                flags->sAMAccountName.c_str());
        mesg = ldap_get_account_attrs(flags, user_attrs);
    } else {
        VERBOSE("Checking that a computer account for %s exists",
                flags->sAMAccountName.c_str());
        mesg = ldap_get_account_attrs(flags, machine_attrs);
    }

    if (ldap->count_entries(mesg) == 0) {
        return false;
    }

    /* Account already exists */
    if (flags->use_service_account) {
        VERBOSE("Checking service account - found");
    } else {
        VERBOSE("Checking computer account - found");
    }
    mesg = ldap->first_entry(mesg);
    flags->ad_computerDn = ldap->get_one_val(mesg, "distinguishedName");

    std::string uac = ldap->get_one_val(mesg, "userAccountControl");
    if (!uac.empty()) {
        flags->ad_userAccountControl = atoi(uac.c_str());
        VERBOSE("Found userAccountControl = 0x%x", flags->ad_userAccountControl);
    }

    /* save the current msDs-supportedEncryptionTypes */
    std::string supportedEncryptionTypes =
        flags->ldap->get_one_val(mesg, "msDs-supportedEncryptionTypes");
    if (!supportedEncryptionTypes.empty()) {
        flags->ad_supportedEncryptionTypes = atoi(supportedEncryptionTypes.c_str());
        flags->ad_enctypes = VALUE_ON; /* actual value found in AD */
        VERBOSE("Found supportedEncryptionTypes = %d",
                flags->ad_supportedEncryptionTypes);
    } else {
        /* Not in current LDAP entry set defaults */
        flags->ad_supportedEncryptionTypes = MS_KERB_DES_ENCTYPES;
        if (!(flags->ad_userAccountControl & UF_USE_DES_KEY_ONLY)) {
            flags->ad_supportedEncryptionTypes |= MS_KERB_ENCTYPE_RC4_HMAC_MD5;
        }
        flags->ad_enctypes = VALUE_OFF; /* this is the assumed default */
        VERBOSE("Found default supportedEncryptionTypes = %d",
                flags->ad_supportedEncryptionTypes);
    }

    if (!flags->use_service_account) {
        /* Save current dNSHostName */
        flags->ad_dnsHostName = ldap->get_one_val(mesg, "dNSHostName");
        VERBOSE("Found dNSHostName = %s", flags->ad_dnsHostName.c_str());
    }

    /* Save current servicePrincipalName and userPrincipalName
     * attrs */
    if (ldap->count_entries(mesg) == 1) {
        mesg = ldap->first_entry(mesg);  /* TODO Why first_entry ??
                                          * already at first entry! */
        std::vector<std::string> vals = ldap->get_all_vals(mesg,
                                                           "servicePrincipalName");
        for (size_t i = 0; i < vals.size(); ++i) {
            /* translate HOST/ to host/ */
            if (vals[i].compare(0, 5, "HOST/") == 0) {
                vals[i].replace(0, 5, "host/");
            }
            flags->ad_principals.push_back(vals[i]);
            VERBOSE("Found Principal: %s", vals[i].c_str());
        }

        if (flags->set_userPrincipalName) {
            VERBOSE("userPrincipal specified on command line");
        } else {
            std::string upn = ldap->get_one_val(mesg, "userPrincipalName");
            if (!upn.empty()) {
                size_t pos = upn.find('@');
                if (pos != std::string::npos) {
                    upn.erase(pos);
                }
                VERBOSE("Found User Principal: %s", upn.c_str());
                /* update userPrincipalName for salt generation */
                flags->userPrincipalName = upn.c_str();
            }
        }
    }
    ldap_msgfree(mesg);
    ldap_check_account_strings(flags);
    return true;
}

void ldap_create_account(msktutil_flags *flags)
{

    const char *vals_objectClass[] = {"top",
                                      "person",
                                      "organizationalPerson",
                                      "user"};

    std::vector<std::string> v_user_objectClass(vals_objectClass,
                                                myend(vals_objectClass));
    std::vector<std::string> v_machine_objectClass(vals_objectClass,
                                                   myend(vals_objectClass));
    v_machine_objectClass.push_back("computer");
    LDAPConnection *ldap = flags->ldap;
    /* No computer account found, so let's add one in the OU specified */
    if (flags->use_service_account) {
        VERBOSE("Service account not found, create the account");
        fprintf(stdout,
                "No service account for %s found, creating a new one.\n",
                flags->sAMAccountName.c_str()
            );
    } else {
        VERBOSE("Computer account not found, create the account");
        fprintf(stdout,
                "No computer account for %s found, creating a new one.\n",
                flags->sAMAccountName_nodollar.c_str()
            );
    }
    flags->ad_computerDn = sform("cn=%s,%s",
                                 flags->sAMAccountName_nodollar.c_str(),
                                 flags->ldap_ou.c_str());
    LDAP_mod mod_attrs;

    if (flags->use_service_account) {
        mod_attrs.add("objectClass", v_user_objectClass);
    } else {
        mod_attrs.add("objectClass", v_machine_objectClass);
    }

    mod_attrs.add("cn", flags->sAMAccountName_nodollar);

    int userAcctFlags;
    if (flags->use_service_account) {
        userAcctFlags = UF_NORMAL_ACCOUNT;
    } else {
        userAcctFlags = UF_WORKSTATION_TRUST_ACCOUNT;
    }
    mod_attrs.add("userAccountControl", sform("%d", userAcctFlags));

    mod_attrs.add("sAMAccountName", flags->sAMAccountName);
    mod_attrs.add("unicodePwd", "\"" + flags->password  + "\"", true);
    ldap->add(flags->ad_computerDn, mod_attrs);

    /* Defaults, will attempt to reset later */
    flags->ad_supportedEncryptionTypes =
        MS_KERB_DES_ENCTYPES |
        MS_KERB_ENCTYPE_RC4_HMAC_MD5;
    flags->ad_enctypes = VALUE_OFF;
    flags->ad_userAccountControl = userAcctFlags;
    ldap_check_account_strings(flags);
}
