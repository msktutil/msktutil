/*
 *----------------------------------------------------------------------------
 *
 * msktutil.cpp
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
#include <cctype>
#include <memory>
#include <algorithm>

// GLOBALS

int g_verbose = 0;

std::string sform(const char* format, ...)
{
    va_list args;
    va_start(args, format);

    char *buf;
    int result = vasprintf(&buf, format, args);
    if(result < 0) {
        throw Exception("vasprintf error");
    }
    std::string outstr(buf, result);
    free(buf);
    va_end(args);
    return outstr;
}


void remove_files_at_exit() {
    remove_fake_krb5_conf();
    remove_ccache();
}

void catch_int(int)
{
    remove_files_at_exit();
    exit(1);
}


void set_samAccountName(msktutil_exec *exec, const std::string &samAccountName)
{
    exec->flags->samAccountName_nodollar = samAccountName;
    if (exec->flags->use_service_account) {
        exec->flags->samAccountName = samAccountName;
    } else {
        exec->flags->samAccountName = samAccountName + "$";
    }
}

void set_supportedEncryptionTypes(msktutil_exec *exec, char * value)
{
    exec->flags->enctypes = VALUE_ON;
    exec->flags->supportedEncryptionTypes = strtol(value, NULL, 0);
}

void do_verbose()
{
    g_verbose++; /* allow for ldap debuging */
}

void qualify_principal_vec(std::vector<std::string> &principals, const std::string &hostname) {
    for(size_t i = 0; i < principals.size(); ++i) {
        // If no hostname part, add it:
        if (principals[i].find('/') == std::string::npos) {
            if (hostname.empty()) {
                fprintf(stderr, "Error: default hostname unspecified, and service argument missing hostname.\n");
                exit(1);
            }
            principals[i].append("/").append(hostname);
        }
    }
}

int finalize_exec(msktutil_exec *exec)
{
    msktutil_flags *flags = exec->flags;


    init_password(flags);
    char *temp_realm;
    if (flags->realm_name.empty()) {
        if (krb5_get_default_realm(g_context.get(), &temp_realm)) {
            fprintf(stderr, "Error: krb5_get_default_realm failed\n");
            exit(1);
        }
        flags->realm_name = std::string(temp_realm);
#ifdef HEIMDAL
        krb5_xfree(temp_realm);
#else
        krb5_free_default_realm(g_context.get(), temp_realm);
#endif
    }

    flags->lower_realm_name = flags->realm_name;
    for(std::string::iterator it = flags->lower_realm_name.begin();
        it != flags->lower_realm_name.end(); ++it)
        *it = std::tolower(*it);

    if (flags->server.empty()) {
        flags->server = get_dc_host(flags->realm_name);
        if (flags->server.empty()) {
            fprintf(stderr, "Error: get_dc_host failed\n");
            exit(1);
        }
    }
    get_default_keytab(flags);

    signal(SIGINT, catch_int);
    atexit(remove_files_at_exit);
    create_fake_krb5_conf(flags);

    if (exec->mode == MODE_PRECREATE && exec->flags->hostname.empty()) {
        /* Don't set a default hostname if none provided in precreate mode. */
        if (exec->flags->samAccountName.empty()) {
            fprintf(stderr, "You must supply either --computer-name or --hostname when using --precreate.\n");
            exit(1);
        }
    } else if (exec->flags->hostname.empty())
        /* Canonicalize the hostname if need be */
        exec->flags->hostname = get_default_hostname();
    else
        exec->flags->hostname = complete_hostname(flags->hostname);

    /* Determine the samAccountName, if not set */
    if (flags->samAccountName.empty()) {
        set_samAccountName(exec, get_short_hostname(flags));
    }

    /* The samAccountName will cause win 9x, NT problems if longer than MAX_SAM_ACCOUNT_LEN characters */
    if (flags->samAccountName.length() > MAX_SAM_ACCOUNT_LEN) {
        fprintf(stderr, "Error: The SAM name (%s) for this host is longer than the maximum of MAX_SAM_ACCOUNT_LEN characters\n",
                flags->samAccountName.c_str());
        fprintf(stderr, "You can specify a shorter name using --computer-name\n");
        exit(1);
    }
    VERBOSE("SAM Account Name is: %s", flags->samAccountName.c_str());

    /* Qualify entries in the principals list */
    qualify_principal_vec(exec->add_principals, flags->hostname);
    qualify_principal_vec(exec->remove_principals, flags->hostname);

    // Now, try to get kerberos credentials in order to connect to LDAP.
    /* We try 3 ways, in order:
       1) Use principal from keytab. Try both:
         a) samAccountName
         b) host/full-hostname (for compat with older msktutil which didn't write the first).
       2) Use principal samAccountName with default password (samAccountName_nodollar)
       3) Calling user's existing credentials from their credential cache.
    */

    flags->auth_type = find_working_creds(flags);
    if (flags->auth_type == AUTH_NONE) {
        fprintf(stderr, "Error: could not find any credentials to authenticate with. Neither keytab,\n\
     default machine password, nor calling user's tickets worked. Try\n\
     \"kinit\"ing yourself some tickets with permission to create computer\n\
     objects, or pre-creating the computer object in AD and selecting\n\
     'reset account'.\n");
        exit(1);
    }
    VERBOSE("Authenticated using method %d\n", flags->auth_type);

    flags->ldap = ldap_connect(flags->server, flags->no_reverse_lookups);
    if (!flags->ldap.get()) {
        fprintf(stderr, "Error: ldap_connect failed\n");
        // Print a hint as to the likely cause:
        if (flags->auth_type == AUTH_FROM_USER_CREDS)
            fprintf(stderr, "--> Is your kerberos ticket expired? You might try re-\"kinit\"ing.\n");
        exit(1);
    }
    ldap_get_base_dn(flags);
    get_default_ou(flags);

    return 0;
}

int add_and_remove_principals(msktutil_exec *exec) {
    int ret = 0;
    std::vector<std::string> &cur_princs(exec->flags->ad_principals);

    for (size_t i = 0; i < exec->add_principals.size(); ++i) {
        std::string principal = exec->add_principals[i];
        if (std::find(cur_princs.begin(), cur_princs.end(), principal) == cur_princs.end()) {
            // Not already in the list, so add it.
            int loc_ret = ldap_add_principal(principal, exec->flags);
            if (loc_ret) {
                fprintf(stderr, "Error: ldap_add_principal failed\n");
                ret = 1;
                continue;
            }
        }
    }

    for (size_t i = 0; i < exec->remove_principals.size(); ++i) {
        std::string principal = exec->remove_principals[i];
        if (std::find(cur_princs.begin(), cur_princs.end(), principal) != cur_princs.end()) {
            int loc_ret = ldap_remove_principal(principal, exec->flags);
            if (loc_ret) {
                fprintf(stderr, "Error: ldap_remove_principal failed\n");
                ret = 1;
                continue;
            }
        } else {
            fprintf(stderr, "Error: principal %s cannot be removed, was not in servicePrincipalName.\n", principal.c_str());
            for (size_t i = 0; i < cur_princs.size(); ++i)
                fprintf(stderr, "  %s\n", cur_princs[i].c_str());
            ret = 1;
        }
    }
    return ret;
}

void do_help() {
    fprintf(stdout, "Usage: %s [OPTIONS]\n", PACKAGE_NAME);
    fprintf(stdout, "\n");
    fprintf(stdout, "Mode options: \n");
    fprintf(stdout, "  --help                   Displays this message\n");
    fprintf(stdout, "  -v, --version            Display the current version\n");
    fprintf(stdout, "\n");
    fprintf(stdout, "  -c, --create   Creates a keytab for the current host or a given service account.\n");
    fprintf(stdout, "                 (same as -u -s host).\n");
    fprintf(stdout, "\n");
    fprintf(stdout, "  -f, --flush    Flushes all principals for the current host or service account\n");
    fprintf(stdout, "                 from the keytab, and deletes servicePrincipalName from AD.\n");
    fprintf(stdout, "\n");
    fprintf(stdout, "  -u, --update   Updates the keytab for the current host or service account. This\n");
    fprintf(stdout, "                 changes the account's password and updates the keytab with entries\n");
    fprintf(stdout, "                 for all principals in servicePrincipalName and userPrincipalName.\n");
    fprintf(stdout, "                 It also updates LDAP attributes for supportedEncryptionTypes,\n");
    fprintf(stdout, "                 dNSDomainName, and applies other options you specify.\n");
    fprintf(stdout, "\n");
    fprintf(stdout, "  --auto-update  Same as --update, but only if keytab fails to authenticate, or\n");
    fprintf(stdout, "                 the last password change was more than 30 days ago. Useful to run\n");
    fprintf(stdout, "                 from a daily cron job.\n");
    fprintf(stdout, "\n");
    fprintf(stdout, "  --precreate    Pre-create an account for the given host with default password\n");
    fprintf(stdout, "                 but do not update local keytab.\n");
    fprintf(stdout, "                 Requires -h or --computer-name argument.\n");
    fprintf(stdout, "                 Implies --user-creds-only.\n");
    fprintf(stdout, "\n");
    fprintf(stdout, "Connection/setup options: \n");
    fprintf(stdout, "  -b, --base <base ou>   Sets the LDAP base OU to use when creating an account.\n");
    fprintf(stdout, "                         The default is read from AD (often CN=computers).\n");
    fprintf(stdout, "  --computer-name <name>, --account-name <name>\n");
    fprintf(stdout, "                         Sets the computer account name or service account name\n");
    fprintf(stdout, "                         to <name>.\n");
    fprintf(stdout, "  --old-account-password <password>\n");
    fprintf(stdout, "                         Use supplied computer account password or service\n");
    fprintf(stdout, "                         account password for authentication.\n");
    fprintf(stdout, "  -h, --hostname <name>  Use <name> as current hostname.\n");
    fprintf(stdout, "  -k, --keytab <file>    Use <file> for the keytab (both read and write).\n");
    fprintf(stdout, "  --server <address>     Use a specific domain controller instead of looking\n");
    fprintf(stdout, "                         up in DNS based upon realm.\n");
    fprintf(stdout, "  --realm <realm>        Use a specific kerberos realm instead of using\n");
    fprintf(stdout, "                         default_realm from krb5.conf.\n");
    fprintf(stdout, "  -N, --no-reverse-lookups\n");
    fprintf(stdout, "                         Don't reverse-lookup the domain controller.\n");
    fprintf(stdout, "  --user-creds-only      Don't attempt to authenticate with machine keytab:\n");
    fprintf(stdout, "                         only use user's credentials (from e.g. kinit).\n");
    fprintf(stdout, "  --verbose              Enable verbose messages.\n");
    fprintf(stdout, "                         More then once to get LDAP debugging.\n");
    fprintf(stdout, "\n");
    fprintf(stdout, "Object type/attribute-setting options:\n");
    fprintf(stdout, "  --use-service-account  Create and maintain service account instead of\n");
    fprintf(stdout, "                         machine account. (EXPERIMENTAL, NOT YET IMPLEMENTED).\n");
    fprintf(stdout, "  --delegation           Set the computer account to be trusted for delegation.\n");
    fprintf(stdout, "  --disable-delegation   Set the computer account to not be trusted for\n");
    fprintf(stdout, "                         delegation.\n");
    fprintf(stdout, "  --description <text>   Sets the description field on the computer account.\n");
    fprintf(stdout, "  --dont-expire-password Disables password expiration for the computer account.\n");
    fprintf(stdout, "  --do-expire-password   Undisables (puts back to default) password expiration.\n");
    fprintf(stdout, "  --enctypes <int>       Sets msDs-supportedEncryptionTypes\n");
    fprintf(stdout, "                         (OR of: 0x1=des-cbc-crc 0x2=des-cbc-md5\n");
    fprintf(stdout, "                                 0x4=rc4-hmac-md5 0x8=aes128-ctc-hmac-sha1\n");
    fprintf(stdout, "                                 0x10=aes256-cts-hmac-sha1)\n");
    fprintf(stdout, "                         Sets des-only in userAccountControl if set to 0x3.\n");
    fprintf(stdout, "  --no-pac               Sets the service principal to not include a PAC.\n");
    fprintf(stdout, "  --disable-no-pac       Sets the service principal to include a PAC.\n");
    fprintf(stdout, "  -s, --service <name>   Adds the service <name> for the current host or the\n");
    fprintf(stdout, "                         given service account. The service is of the form\n");
    fprintf(stdout, "                         <service>/<hostname>.\n");
    fprintf(stdout, "                         If the hostname is omitted, assumes current hostname.\n");
    fprintf(stdout, "  --remove-service <name> Same, but removes instead of adds.\n");
    fprintf(stdout, "  --upn <principal>      Set the user principal name to be <principal>.\n");
    fprintf(stdout, "                         The realm name will be appended to this principal.\n");


}

void do_version() {
    fprintf(stdout, "%s version %s\n", PACKAGE_NAME, PACKAGE_VERSION);
}

int execute(msktutil_exec *exec)
{
    int ret = 0;
    msktutil_flags *flags = exec->flags;

    ret = finalize_exec(exec);
    if (ret) {
        fprintf(stderr, "Error: finalize_exec failed\n");
        exit(ret);
    }

    if (exec->mode == MODE_FLUSH) {
        fprintf(stdout, "Flushing all entries for %s from the keytab %s\n", flags->hostname.c_str(),
                flags->keytab_writename.c_str());
        ret = flush_keytab(flags);
        return ret;
    } else if (exec->mode == MODE_UPDATE || exec->mode == MODE_AUTO_UPDATE) {
        if (exec->mode == MODE_AUTO_UPDATE) {
            // Don't bother doing anything if the auth was from the keytab (and not e.g. default password), and the
            if (exec->flags->auth_type == AUTH_FROM_SAM_KEYTAB) {
                std::string pwdLastSet = ldap_get_pwdLastSet(exec->flags);
                // Windows timestamp is in 100-nanoseconds-since-1601. (or, tenths of microseconds)
                long long windows_timestamp = strtoll(pwdLastSet.c_str(), NULL, 10);
                long long epoch_bias_1601_to_1970 = 116444736000000000LL;
                // Unix timestamp is seconds since 1970.
                long long unix_timestamp;
                if (windows_timestamp < epoch_bias_1601_to_1970)
                    unix_timestamp = 0;
                else
                    unix_timestamp = (windows_timestamp - epoch_bias_1601_to_1970) / 10000000;
                time_t current_unix_time = time(NULL);
                long long days_since_password_change = (current_unix_time - unix_timestamp) / 86400;
                VERBOSE("Password last set %lld days ago.", days_since_password_change);
                if (days_since_password_change < 30) {
                    VERBOSE("Exiting because password was changed recently.");
                    return 0;
                }
            }
        }

        // Generate a random password and store it.
        ret = generate_new_password(flags);
        if (ret) {
            fprintf(stderr, "Error: generate_new_password failed\n");
            return ret;
        }

        // Check if computer account exists, update if so, create if not.
        ldap_check_account(flags);

        // Set the password.
        ret = set_password(flags);
        if (ret) {
            fprintf(stderr, "Error: set_password failed\n");
            return ret;
        }

        // And add and remove principals to servicePrincipalName in LDAP.
        add_and_remove_principals(exec);

        VERBOSE("Updating all entries for %s in the keytab %s\n", flags->hostname.c_str(),
                flags->keytab_writename.c_str());
        update_keytab(flags);

        return ret;
    } else if (exec->mode == MODE_PRECREATE) {
        // Change account password to default value:
        flags->password = flags->samAccountName_nodollar;
        // Check if computer account exists, update if so, create if not.
        ldap_check_account(flags);

        // Set the password.
        ret = set_password(flags);
        if (ret) {
            fprintf(stderr, "Error: set_password failed\n");
            return ret;
        }

        // And add and remove principals to servicePrincipalName in LDAP.
        add_and_remove_principals(exec);
        return ret;
    }

    return 0;
}

void set_mode(msktutil_exec *exec, msktutil_mode mode) {
    if (exec->mode != MODE_NONE) {
        fprintf(stderr, "Error: only one mode argument may be provided.\n");
        fprintf(stderr, "\nFor help, try running %s --help\n\n", PACKAGE_NAME);
        exit(1);
    }
    exec->mode = mode;
}

int main(int argc, char *argv [])
{
    // unbuffer stdout.
    setbuf(stdout, NULL);

    int i;
    std::auto_ptr<msktutil_exec> exec(new msktutil_exec());

    for (i = 1; i < argc; i++) {
        /* Display Version Message and exit */
        if (!strcmp(argv[i], "-v") || !strcmp(argv[i], "--version")) {
            do_version();
            return 0;
        }

        /* Display Help Messages and exit */
        if (!strcmp(argv[i], "--help") || !strcmp(argv[i], "--usage")) {
            do_help();
            return 0;
        }

        /* Flush the keytab */
        if (!strcmp(argv[i], "--flush") || !strcmp(argv[i], "-f")) {
            set_mode(exec.get(), MODE_FLUSH);
            continue;
        }

        /* Update All Principals */
        if (!strcmp(argv[i], "--update") || !strcmp(argv[i], "-u")) {
            set_mode(exec.get(), MODE_UPDATE);
            continue;
        }

        /* Update All Principals, if needed */
        if (!strcmp(argv[i], "--auto-update")) {
            set_mode(exec.get(), MODE_AUTO_UPDATE);
            continue;
        }

        /* Create 'Default' Keytab */
        if (!strcmp(argv[i], "--create") || !strcmp(argv[i], "-c")) {
            set_mode(exec.get(), MODE_UPDATE);
            exec->add_principals.push_back("host");
            continue;
        }

        /* Pre-create computer account for another host */
        if (!strcmp(argv[i], "--precreate")) {
            set_mode(exec.get(), MODE_PRECREATE);
            exec->flags->user_creds_only = true;
            continue;
        }



        /* Service Principal Name */
        if (!strcmp(argv[i], "--service") || !strcmp(argv[i], "-s")) {
            if (++i < argc) {
                exec->add_principals.push_back(argv[i]);
            } else {
                fprintf(stderr, "Error: No service principal given after '%s'\n", argv[i - 1]);
                goto error;
            }
            continue;
        }
        if (!strcmp(argv[i], "--remove-service")) {
            if (++i < argc) {
                exec->remove_principals.push_back(argv[i]);
            } else {
                fprintf(stderr, "Error: No service principal given after '%s'\n", argv[i - 1]);
                goto error;
            }
            continue;
        }

        /* Host name */
        if (!strcmp(argv[i], "--host") || !strcmp(argv[i], "--hostname") || !strcmp(argv[i], "-h")) {
            if (++i < argc) {
                exec->flags->hostname = argv[i];
            } else {
                fprintf(stderr, "Error: No name given after '%s'\n", argv[i - 1]);
                goto error;
            }
            continue;
        }

        /* computer password */
        if (!strcmp(argv[i], "--old-account-password")) {
            if (++i < argc) {
                exec->flags->old_account_password = argv[i];
            } else {
                fprintf(stderr, "Error: No password given after '%s'\n", argv[i - 1]);
                goto error;
            }
            continue;
        }

        /* W2008 msDs-supportedEncryptionTypes */
        if (!strcmp(argv[i], "--enctypes")) {
            if (++i < argc) {
                set_supportedEncryptionTypes(exec.get(), argv[i]);
            } else {
                fprintf(stderr, "Error: No enctype after '%s'\n", argv[i - 1]);
                goto error;
            }
            continue;
        }

        /* Disable the PAC ? */
        if (!strcmp(argv[i], "--no-pac")) {
            exec->flags->no_pac = VALUE_ON;
            continue;
        }
        if (!strcmp(argv[i], "--disable-no-pac")) {
            exec->flags->no_pac = VALUE_OFF;
            continue;
        }

        /* Use service account */
        if (!strcmp(argv[i], "--use-service-account")) {
            exec->flags->use_service_account = true;
            exec->flags->set_userPrincipalName = true;
            continue;
        }

        /* Trust for delegation ? */
        if (!strcmp(argv[i], "--delegation")) {
            exec->flags->delegate = VALUE_ON;
            continue;
        }
        if (!strcmp(argv[i], "--disable-delegation")) {
            exec->flags->delegate = VALUE_OFF;
            continue;
        }

        /* Password expiry (is rotation required?) */
        if (!strcmp(argv[i], "--dont-expire-password")) {
            exec->flags->dont_expire_password = VALUE_ON;
            continue;
        }

        if (!strcmp(argv[i], "--do-expire-password")) {
            exec->flags->dont_expire_password = VALUE_OFF;
            continue;
        }

        /* Use a certain sam account name */
        if (!strcmp(argv[i], "--computer-name") || !strcmp(argv[i], "--account-name")) {
            if (++i < argc) {
                set_samAccountName(exec.get(), argv[i]);
            } else {
                fprintf(stderr, "Error: No name given after '%s'\n", argv[i - 1]);
                goto error;
            }
            continue;
        }

        if (!strcmp(argv[i], "--upn")) {
            if (++i < argc) {
                exec->flags->set_userPrincipalName = true;
                exec->flags->userPrincipalName = argv[i];
            } else {
                fprintf(stderr, "Error: No principal given after '%s'\n", argv[i - 1]);
                goto error;
            }
            continue;
        }

        /* Use certain keytab file */
        if (!strcmp(argv[i], "--keytab") || !strcmp(argv[i], "-k")) {
            if (++i < argc) {
                exec->flags->keytab_file = argv[i];
            } else {
                fprintf(stderr, "Error: No file given after '%s'\n", argv[i - 1]);
                goto error;
            }
            continue;
        }

        /* Use a certain LDAP base OU ? */
        if (!strcmp(argv[i], "--base") || !strcmp(argv[i], "-b")) {
            if (++i < argc) {
                exec->flags->ldap_ou = argv[i];
            } else {
                fprintf(stderr, "Error: No base given after '%s'\n", argv[i - 1]);
                goto error;
            }
            continue;
        }

        /* Set the description on the computer account */
        if (!strcmp(argv[i], "--description")) {
            if (++i < argc) {
                exec->flags->set_description = true;
                exec->flags->description = argv[i];
            } else {
                fprintf(stderr, "Error: No description given after '%s'\n", argv[i - 1]);
                goto error;
            }
            continue;
        }

        /* Use a certain LDAP server */
        if (!strcmp(argv[i], "--server")) {
            if (++i < argc) {
                exec->flags->server = argv[i];
            } else {
                fprintf(stderr, "Error: No server given after '%s'\n", argv[i - 1]);
                goto error;
            }
            continue;
        }

        /* Use a certain realm */
        if (!strcmp(argv[i], "--realm")) {
            if (++i < argc) {
                exec->flags->realm_name = argv[i];
            } else {
                fprintf(stderr, "Error: No realm given after '%s'\n", argv[i - 1]);
                goto error;
            }
            continue;
        }

        /* do not reverse lookup server names */
        if (!strcmp(argv[i], "--no-reverse-lookups") || !strcmp(argv[i], "-N")) {
            exec->flags->no_reverse_lookups = true;
            continue;
        }

        /* Use user kerberos credentials only */
        if (!strcmp(argv[i], "--user-creds-only")) {
            exec->flags->user_creds_only = true;
            continue;
        }

        /* Display Verbose Messages */
        if (!strcmp(argv[i], "--verbose")) {
            do_verbose();
            continue;
        }

        /* Unrecognized */
        fprintf(stderr, "Error: Unknown parameter (%s)\n", argv[i]);
        goto error;
    }

    if (exec->flags->enctypes == VALUE_ON) {
        unsigned known= MS_KERB_ENCTYPE_DES_CBC_CRC |
                        MS_KERB_ENCTYPE_DES_CBC_MD5 |
                        MS_KERB_ENCTYPE_RC4_HMAC_MD5 |
                        MS_KERB_ENCTYPE_AES128_CTC_HMAC_SHA1_96 |
                        MS_KERB_ENCTYPE_AES256_CTS_HMAC_SHA1_96;

        if ((exec->flags->supportedEncryptionTypes|known) != known) {
            fprintf(stderr, " Unsupported --enctypes must be integer that fits mask=0x%x\n", known);
            goto error;
        }
        if (exec->flags->supportedEncryptionTypes == 0) {
            fprintf(stderr, " --enctypes must not be zero\n");
            goto error;
        }
    }

    if (exec->mode == MODE_NONE && !exec->add_principals.empty())
        set_mode(exec.get(), MODE_UPDATE);

    if (exec->mode == MODE_NONE) {
        /* Default, no options present */
        fprintf(stderr, "Error: No command given\n");
        goto error;
    }

    try {
        return execute(exec.get());
    } catch (Exception &e) {
        fprintf(stderr, "%s\n", e.what());
        exit(1);
    }

error:
    fprintf(stderr, "\nFor help, try running %s --help\n\n", PACKAGE_NAME);
    return 1;
}


msktutil_flags::msktutil_flags() :
    password(), ldap(), set_description(false), set_userPrincipalName(false),
    dont_expire_password(VALUE_IGNORE), no_pac(VALUE_IGNORE), delegate(VALUE_IGNORE),
    ad_userAccountControl(0), ad_enctypes(VALUE_IGNORE), ad_supportedEncryptionTypes(0),
    enctypes(VALUE_IGNORE),
    /* default values we *want* to support */
    supportedEncryptionTypes(MS_KERB_ENCTYPE_RC4_HMAC_MD5 |
                             MS_KERB_ENCTYPE_AES128_CTC_HMAC_SHA1_96 |
                             MS_KERB_ENCTYPE_AES256_CTS_HMAC_SHA1_96),
    auth_type(0), user_creds_only(false)
{}

msktutil_flags::~msktutil_flags() {
    ldap_cleanup(this);
    init_password(this);
}


msktutil_exec::msktutil_exec() :
    mode(MODE_NONE), flags(new msktutil_flags())
{
    /* Check for environment variables as well.  These variables will be overriden
     * By command line arguments. */
    if (getenv("MSKTUTIL_KEYTAB"))
        flags->keytab_file = getenv("MSKTUTIL_KEYTAB");
    if (getenv("MSKTUTIL_NO_PAC"))
        flags->no_pac = VALUE_ON;
    if (getenv("MSKTUTIL_DELEGATION"))
        flags->delegate = VALUE_ON;
    if (getenv("MSKTUTIL_LDAP_BASE"))
        flags->ldap_ou = getenv("MSKTUTIL_LDAP_BASE");
    if (getenv("MSKTUTIL_SERVER"))
        flags->server = getenv("MSKTUTIL_SERVER");
}

msktutil_exec::~msktutil_exec() {
    VERBOSE("Destroying msktutil_exec");
    remove_fake_krb5_conf();
    remove_ccache();

    delete flags;
}
