/*
 *----------------------------------------------------------------------------
 *
 * msktutil.cpp
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
#ifndef HAVE_STRTOLL
#include "strtoll.h"
#endif
#include <cctype>
#include <memory>
#include <algorithm>

/* GLOBALS */

int g_verbose = 0;

/* Fatal error */
void error_exit( const char *text) {
    v_error_exit("error_exit: %s: %s\n", text, strerror(errno));
}

void v_error_exit(const char* format, ...) {
    va_list args;
    va_start(args, format);
    vfprintf(stderr, format, args);
    va_end(args);
    exit(1);
}

std::string sform(const char* format, ...)
{
    va_list args;
    va_start(args, format);

    char *buf;
#if !defined(HAVE_VASPRINTF)
#  ifdef HAVE_VSNPRINTF
    buf = (char *) malloc(10000);
    memset(buf, 0, 10000);
    int result =  vsnprintf(buf, 10000-1, format, args);
#  else
#   error need either vasprintf or vsnprintf
#  endif
#else
    int result = vasprintf(&buf, format, args);
#endif
    if (result < 0) {
        error_exit("vasprintf failed");
    }
    std::string outstr(buf, result);
    free(buf);
    va_end(args);
    return outstr;
}

void remove_files_at_exit()
{
    remove_fake_krb5_conf();
    remove_ccache();
}


void catch_int(int)
{
    remove_files_at_exit();
    exit(1);
}

void set_supportedEncryptionTypes(msktutil_flags *flags, char * value)
{
    flags->enctypes = VALUE_ON;
    flags->supportedEncryptionTypes = strtol(value, NULL, 0);
}

void set_cleanup_enctype(msktutil_flags *flags, char * value)
{
    int enctype = -1;
    if (sform(value).compare(sform("des-cbc-crc")) == 0) {
        enctype = 1;
    } else if (sform(value).compare(sform("des-cbc-md5")) == 0) {
        enctype = 3;
    } else if ((sform(value).compare(sform("arcfour-hmac-md5")) == 0) ||
               (sform(value).compare(sform("arcfour-hmac")) == 0) ||
               (sform(value).compare(sform("arcfour")) == 0) ||
               (sform(value).compare(sform("rc4-hmac-md5")) == 0) ||
               (sform(value).compare(sform("rc4-hmac")) == 0) ||
               (sform(value).compare(sform("rc4")) == 0)) {
        enctype = 23;
    } else if ((sform(value).compare(sform("aes128-cts-hmac-sha1-96")) == 0) ||
               (sform(value).compare(sform("aes128-cts-hmac-sha1")) == 0) ||
               (sform(value).compare(sform("aes128-cts-hmac")) == 0) ||
               (sform(value).compare(sform("aes128-cts")) == 0) ||
               (sform(value).compare(sform("aes128")) == 0)) {
        enctype = 17;
    } else if ((sform(value).compare(sform("aes256-cts-hmac-sha1-96")) == 0) ||
               (sform(value).compare(sform("aes256-cts-hmac-sha1")) == 0) ||
               (sform(value).compare(sform("aes256-cts-hmac")) == 0) ||
               (sform(value).compare(sform("aes256-cts")) == 0) ||
               (sform(value).compare(sform("aes256")) == 0)) {
        enctype = 18;
    } else {
        fprintf(stderr,
                "Error: enctype = %s not supported. "
                "Supported enctype strings are\n", value
            );
        fprintf(stderr, "  des-cbc-crc\n");
        fprintf(stderr, "  des-cbc-md5\n");
        fprintf(stderr, "  arcfour\n");
        fprintf(stderr, "  aes128\n");
        fprintf(stderr, "  aes256\n");
        exit(1);
    }
    flags->cleanup_enctype = enctype;
}

void do_verbose()
{
    g_verbose++; /* allow for ldap debuging */
}


void qualify_principal_vec(std::vector<std::string> &principals,
                           const std::string &hostname)
{
    for(size_t i = 0; i < principals.size(); ++i) {
        /* If no hostname part, add it: */
        if (principals[i].find('/') == std::string::npos) {
            if (hostname.empty()) {
                fprintf(stderr,
                        "Error: default hostname unspecified, "
                        "and service argument missing hostname.\n"
                    );
                exit(1);
            }
            principals[i].append("/").append(hostname);
        }
    }
}


int finalize_exec(msktutil_exec *exec, msktutil_flags *flags)
{
    int ret;

    char *temp_realm;
    if (flags->realm_name.empty()) {
        if (krb5_get_default_realm(g_context, &temp_realm)) {
            fprintf(stderr, "Error: krb5_get_default_realm failed\n");
            exit(1);
        }
        flags->realm_name = std::string(temp_realm);
#ifdef HEIMDAL
        krb5_xfree(temp_realm);
#else
        krb5_free_default_realm(g_context, temp_realm);
#endif
    }

    flags->lower_realm_name = flags->realm_name;
    for(std::string::iterator it = flags->lower_realm_name.begin();
        it != flags->lower_realm_name.end(); ++it) {
            *it = std::tolower(*it);
    }
    if (exec->mode == MODE_CLEANUP) {
        VERBOSE("cleanup mode: don't need AD server");
        flags->server = "dummy";
    } else {
        if (flags->server.empty()) {
            flags->server = get_dc_host(flags->realm_name,
                                        flags->site,
                                        flags->no_reverse_lookups);
            if (flags->server.empty()) {
                fprintf(stderr, "Error: get_dc_host failed\n");
                exit(1);
            }
        }
    }

    get_default_keytab(flags);
    signal(SIGINT, catch_int);
    atexit(remove_files_at_exit);
    create_fake_krb5_conf(flags);

    if (exec->mode == MODE_CLEANUP) {
        VERBOSE("cleanup mode: nothing more to do");
        return (0);
    }

    if (exec->mode == MODE_PRECREATE && flags->hostname.empty()) {
        /* Don't set a default hostname if none provided in pre-create
         * mode. */
        if (flags->sAMAccountName.empty()) {
            fprintf(stderr,
                    "Error: You must supply either --computer-name "
                    "or --hostname when using pre-create mode.\n"
                );
            exit(1);
        }
    } else if (flags->hostname.empty()) {
        /* Canonicalize the hostname if need be */
        flags->hostname = get_default_hostname(flags->no_canonical_name);
    } else {
        flags->hostname = complete_hostname(flags->hostname);
    }

    /* Determine the sAMAccountName, if not set */
    if (flags->sAMAccountName.empty()) {
        if (flags->use_service_account) {
            fprintf(stderr,
                    "Error: You must supply --account-name "
                    "when using --use-service-account.\n"
                );
            exit(1);
        } else {
            flags->sAMAccountName = get_default_samaccountname(flags)  + "$";
        }
    }

    /* Determine sAMAccountName_nodollar */
    flags->sAMAccountName_nodollar = flags->sAMAccountName;
    if (flags->sAMAccountName_nodollar[
            flags->sAMAccountName_nodollar.size()-1] == '$') {
        flags->sAMAccountName_nodollar.erase(
            flags->sAMAccountName_nodollar.size()-1);
    }

    /* Add a "$" to machine accounts */
    if ((!flags->use_service_account)
        && (flags->sAMAccountName[flags->sAMAccountName.size()-1] != '$')) {
        flags->sAMAccountName += "$";
    }

    /* Determine uppercase version of sAMAccountName */
    flags->sAMAccountName_uppercase = flags->sAMAccountName;
    for (std::string::size_type i=0;
         i<flags->sAMAccountName_uppercase.length();
         ++i) {
        flags->sAMAccountName_uppercase[i]
            = toupper(flags->sAMAccountName_uppercase[i]);
    }

    /* The sAMAccountName will cause win 9x, NT problems if longer
     * than MAX_SAM_ACCOUNT_LEN characters */
    if (flags->sAMAccountName.length() > MAX_SAM_ACCOUNT_LEN) {
        fprintf(stderr,
                "Error: The SAM name (%s) for this host is longer "
                "than the maximum of MAX_SAM_ACCOUNT_LEN characters\n",
                flags->sAMAccountName.c_str()
            );
        fprintf(stderr,
                "Error: You can specify a shorter name using "
                "--computer-name\n"
            );
        exit(1);
    }
    VERBOSE("SAM Account Name is: %s", flags->sAMAccountName.c_str());

    /* Qualify entries in the principals list */
    qualify_principal_vec(exec->add_principals, flags->hostname);
    qualify_principal_vec(exec->remove_principals, flags->hostname);

    /* Now, try to get kerberos credentials in order to connect to
     * LDAP. */
    flags->auth_type = find_working_creds(flags);
    if (flags->auth_type == AUTH_NONE) {
        fprintf(stderr,
                "Error: could not find any credentials to authenticate with. "
                "Neither keytab,\n"
                "default machine password, nor calling user's tickets worked. "
                "Try\n\"kinit\"ing yourself some tickets with permission to "
                "create computer\nobjects, or pre-creating the computer "
                "object in AD and selecting\n'reset account'.\n"
            );
        exit(1);
    }

    /* If we didn't get kerberos credentials because the old passord
     * has expired we need to change it now */
    if (flags->auth_type == AUTH_FROM_SUPPLIED_EXPIRED_PASSWORD) {
        VERBOSE("Account password expired, changing it now...");
        ret = set_password(flags);
        if (ret) {
            fprintf(stderr, "Error: failed to change password\n");
            exit(1);
        }
        if (!get_creds(flags)) {
            fprintf(stderr, "Error: failed to get kerberos credentials\n");
            exit(1);
        }
    }

    VERBOSE("Authenticated using method %d", flags->auth_type);

    flags->ldap = new LDAPConnection(flags->server,
                                     flags->sasl_mechanisms,
                                     flags->no_reverse_lookups);

    if (!flags->ldap->is_connected()) {
        fprintf(stderr, "Error: ldap_connect failed\n");
        /* Print a hint as to the likely cause: */
        if (flags->auth_type == AUTH_FROM_USER_CREDS) {
            fprintf(stderr, "--> Is your kerberos ticket expired? "
                    "You might try re-\"kinit\"ing.\n"
                );
        }
        if (flags->no_reverse_lookups == false) {
            fprintf(stderr, "--> Is DNS configured correctly? ");
            fprintf(stderr, "You might try options \"--server\" "
                    "and \"--no-reverse-lookups\".\n"
                );
        }
        exit(1);
    }
    ldap_get_base_dn(flags);
    get_default_ou(flags);

    return 0;
}


int add_and_remove_principals(msktutil_exec *exec)
{
    int ret = 0;

    std::vector<std::string> &cur_princs(Globals::flags()->ad_principals);

    for (size_t i = 0; i < exec->add_principals.size(); ++i) {
        std::string principal = exec->add_principals[i];
        if (std::find(cur_princs.begin(),
                      cur_princs.end(),
                      principal) == cur_princs.end()) {
            /* Not already in the list, so add it. */
            int loc_ret = ldap_add_principal(principal, Globals::flags());
            if (loc_ret) {
                fprintf(stderr, "Error: ldap_add_principal failed\n");
                ret = 1;
                continue;
            }
        }
    }

    for (size_t i = 0; i < exec->remove_principals.size(); ++i) {
        std::string principal = exec->remove_principals[i];
        if (std::find(cur_princs.begin(), cur_princs.end(), principal)
            != cur_princs.end()) {
            int loc_ret = ldap_remove_principal(principal, Globals::flags());
            if (loc_ret) {
                fprintf(stderr, "Error: ldap_remove_principal failed\n");
                ret = 1;
                continue;
            }
        } else {
            fprintf(stderr,
                    "Error: principal %s cannot be removed, was not in "
                    "servicePrincipalName.\n",
                    principal.c_str()
                );
            for (size_t i = 0; i < cur_princs.size(); ++i)
                fprintf(stderr, "  %s\n", cur_princs[i].c_str());
            ret = 1;
        }
    }
    return ret;
}


void do_help()
{
    fprintf(stdout, "Usage: %s [MODE] [OPTIONS]\n", PACKAGE_NAME);
    fprintf(stdout, "\n");
    fprintf(stdout, "Modes: \n");
    fprintf(stdout, "\n");
    fprintf(stdout, "  create                 Creates a keytab for the current host or a given service account.\n");
    fprintf(stdout, "                         (same as update -s host).\n");
    fprintf(stdout, "\n");
    fprintf(stdout, "  update                 Updates the keytab for the current host or service account. This\n");
    fprintf(stdout, "                         changes the account's password and updates the keytab with entries\n");
    fprintf(stdout, "                         for all principals in servicePrincipalName and userPrincipalName.\n");
    fprintf(stdout, "                         It also updates LDAP attributes for msDS-supportedEncryptionTypes,\n");
    fprintf(stdout, "                         dNSHostName, and applies other options you specify.\n");
    fprintf(stdout, "\n");
    fprintf(stdout, "  auto-update            Same as update, but only if keytab fails to authenticate, or\n");
    fprintf(stdout, "                         the last password change was more than 30 days ago\n");
    fprintf(stdout, "                         (see --auto-update-interval). Useful to run from a daily cron job.\n");
    fprintf(stdout, "\n");
    fprintf(stdout, "  pre-create             Pre-create an account for the given host with default password\n");
    fprintf(stdout, "                         but do not update local keytab.\n");
    fprintf(stdout, "                         Requires -h or --computer-name argument.\n");
    fprintf(stdout, "                         Implies --user-creds-only.\n");
    fprintf(stdout, "\n");
    fprintf(stdout, "  flush                  Flushes all principals for the current host or service account\n");
    fprintf(stdout, "                         from the keytab, and deletes servicePrincipalName from AD.\n");
    fprintf(stdout, "\n");
    fprintf(stdout, "  delete                 Deletes the host or service account from Active Directory.\n");
    fprintf(stdout, "\n");
    fprintf(stdout, "  cleanup                Deletes entries from the keytab that are no longer needed.\n");
    fprintf(stdout, "\n");
    fprintf(stdout, "Common options: \n");
    fprintf(stdout, "  --help                 Displays this message\n");
    fprintf(stdout, "  -v, --version          Display the current version\n");
    fprintf(stdout, "  --verbose              Enable verbose messages.\n");
    fprintf(stdout, "                         More then once to get LDAP debugging.\n");
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
    fprintf(stdout, "                         This option is mutually exclusive with --user-creds-only.\n");
    fprintf(stdout, "  -h, --hostname <name>  Use <name> as current hostname.\n");
    fprintf(stdout, "  --password <new_password>\n");
    fprintf(stdout, "                         Specify the new account password instead of generating\n");
    fprintf(stdout, "                         a random one. Consider the password policy settings when\n");
    fprintf(stdout, "                         defining the string.\n");
    fprintf(stdout, "  --dont-change-password Do not create a new password. Try to use existing keys\n");
    fprintf(stdout, "                         when performing keytab updates (update and create mode only).\n");
    fprintf(stdout, "  -k, --keytab <file>    Use <file> for the keytab (both read and write).\n");
    fprintf(stdout, "  --keytab-auth-as <name>\n");
    fprintf(stdout, "                         First try to authenticate to AD as principal <name>, using\n");
    fprintf(stdout, "                         creds from the keytab, instead of using the account name\n");
    fprintf(stdout, "                         principal or the host principal, etc.\n");
    fprintf(stdout, "  --server <address>     Use a specific domain controller instead of looking\n");
    fprintf(stdout, "                         up in DNS based upon realm.\n");
    fprintf(stdout, "  --server-behind-nat    Ignore server IP validation error caused by NAT.\n");
    fprintf(stdout, "  --realm <realm>        Use a specific kerberos realm instead of using\n");
    fprintf(stdout, "                         default_realm from krb5.conf.\n");
    fprintf(stdout, "  --site <site>          Find and use domain controller in specific AD site.\n");
    fprintf(stdout, "                         This option is ignored if option --server is used.\n");
    fprintf(stdout, "  -N, --no-reverse-lookups\n");
    fprintf(stdout, "                         Don't reverse-lookup the domain controller.\n");
    fprintf(stdout, "  -n, --no-canonical-name\n");
    fprintf(stdout, "                         Do not attempt to canonicalize hostname while\n");
    fprintf(stdout, "                         creating Kerberos principal(s).\n");
    fprintf(stdout, "  --user-creds-only      Don't attempt to authenticate with machine keytab:\n");
    fprintf(stdout, "                         only use user's credentials (from e.g. kinit).\n");
    fprintf(stdout, "  --auto-update-interval <days>\n");
    fprintf(stdout, "                         Number of <days> when auto-update will change the\n");
    fprintf(stdout, "                         account password. Defaults to 30 days.\n");
    fprintf(stdout, "  -m, --sasl-mechanisms <mechanisms list>\n");
    fprintf(stdout, "                         Candidate SASL mechanisms to use when performing\n");
    fprintf(stdout, "                         the LDAP bind. Defaults to \"GSS-SPNEGO GSSAPI\".\n");
    fprintf(stdout, "\n");
    fprintf(stdout, "Object type/attribute-setting options:\n");
    fprintf(stdout, "  --use-service-account  Create and maintain service account instead of\n");
    fprintf(stdout, "                         machine account.\n");
    fprintf(stdout, "  --enable               Enable the account.\n");
    fprintf(stdout, "  --delegation           Set the account to be trusted for delegation.\n");
    fprintf(stdout, "  --disable-delegation   Set the account to not be trusted for\n");
    fprintf(stdout, "                         delegation.\n");
    fprintf(stdout, "  --description <text>   Sets the description field on the account.\n");
    fprintf(stdout, "  --dont-expire-password Disables password expiration for the account.\n");
    fprintf(stdout, "  --dont-update-dnshostname\n");
    fprintf(stdout, "                         Do not update dNSHostName attribute.\n");
    fprintf(stdout, "  --do-expire-password   Undisables (puts back to default) password expiration.\n");
    fprintf(stdout, "  --enctypes <int>       Sets msDs-supportedEncryptionTypes\n");
    fprintf(stdout, "                         (OR of: 0x1=des-cbc-crc 0x2=des-cbc-md5\n");
    fprintf(stdout, "                                 0x4=rc4-hmac-md5 0x8=aes128-cts-hmac-sha1\n");
    fprintf(stdout, "                                 0x10=aes256-cts-hmac-sha1)\n");
    fprintf(stdout, "                         Sets des-only in userAccountControl if set to 0x3.\n");
    fprintf(stdout, "  --allow-weak-crypto    Enables the usage of DES keys for authentication\n");
    fprintf(stdout, "  --no-pac               Sets the service principal to not include a PAC.\n");
    fprintf(stdout, "  --disable-no-pac       Sets the service principal to include a PAC.\n");
    fprintf(stdout, "  -s, --service <name>   Adds the service <name> for the current host or the\n");
    fprintf(stdout, "                         given service account. The service is of the form\n");
    fprintf(stdout, "                         <service>/<hostname>.\n");
    fprintf(stdout, "                         If the hostname is omitted, assumes current hostname.\n");
    fprintf(stdout, "  --remove-service <name> Same, but removes instead of adds.\n");
    fprintf(stdout, "  --upn <principal>      Set the user principal name to be <principal>.\n");
    fprintf(stdout, "                         The realm name will be appended to this principal.\n");
    fprintf(stdout, "  --set-samba-secret     Use the net changesecretpw command to locally set the\n");
    fprintf(stdout, "                         machine account password in samba's secrets.tdb.\n");
    fprintf(stdout, "                         $PATH need to include Samba's net command.\n");
    fprintf(stdout, "  --use-samba-cmd <command> Use the supplied command instead of samba\n");
    fprintf(stdout, "                         net changesecretpw.\n");
    fprintf(stdout, "  --check-replication    Wait until password change is reflected in LDAP.\n");
    fprintf(stdout, "\n");
    fprintf(stdout, "Cleanup options:\n");
    fprintf(stdout, "  --remove-old <number>  Removes entries older than <number> days\n");
    fprintf(stdout, "  --remove-enctype <enctype>\n");
    fprintf(stdout, "                         Removes entries with given <enctype>. Supported enctype\n");
    fprintf(stdout, "                         strings are: des-cbc-crc,des-cbc-md5, arcfour, aes128\n");
    fprintf(stdout, "                         and aes256\n");
}


void do_version()
{
    fprintf(stdout, "%s version %s\n", PACKAGE_NAME, PACKAGE_VERSION);
}


static int wait_for_new_kvno(msktutil_flags *flags)
{
    if (!flags->check_replication) {
        return 0;
    }

    if (flags->auth_type == AUTH_FROM_SUPPLIED_EXPIRED_PASSWORD) {
        VERBOSE("Warning: authenticated with expired password -- "
                "no way to verify the password change in LDAP.");
        return 0;
    }

    VERBOSE("Checking new kvno via ldap");

    /* Loop and wait for the account and password set to replicate */
    for (int this_time = 0; ; this_time += 5) {
        krb5_kvno current_kvno = ldap_get_kvno(flags);
        if (current_kvno == flags->kvno) {
            return 0;
        }

        fprintf(stdout,
                "Waiting for account replication (%d seconds past)\n",
                this_time);
        sleep(5);
    }
}


int execute(msktutil_exec *exec, msktutil_flags *flags)
{
    int ret = 0;
    if (flags->password_from_cmdline) {
        VERBOSE("Using password from command line");
    } else if (flags->dont_change_password) {
        VERBOSE("Skipping creation of new password");
        flags->password = flags->old_account_password;
    } else if (exec->mode == MODE_CLEANUP) {
        VERBOSE("cleanup mode: don't need a new password");
    } else if (exec->mode == MODE_DELETE) {
        VERBOSE("delete mode: don't need a new password");
    } else {
        /* Generate a random password and store it. */
        ret = generate_new_password(flags);
        if (ret) {
            fprintf(stderr, "Error: generate_new_password failed\n");
            return ret;
        }
    }
    ret = finalize_exec(exec, flags);

    if (ret) {
        fprintf(stderr, "Error: finalize_exec failed\n");
        exit(ret);
    }
    if (exec->mode == MODE_FLUSH) {
        if (flags->use_service_account) {
            fprintf(stdout,
                    "Flushing all entries for service account %s from the keytab %s\n",
                    flags->sAMAccountName.c_str(),
                    flags->keytab_writename.c_str());
        } else {
            fprintf(stdout,
                    "Flushing all entries for %s from the keytab %s\n",
                    flags->hostname.c_str(),
                    flags->keytab_writename.c_str());
        }
        ret = flush_keytab(flags);
        return ret;
    } else if (exec->mode == MODE_CREATE ||
               exec->mode == MODE_UPDATE ||
               exec->mode == MODE_AUTO_UPDATE) {
        if (exec->mode == MODE_AUTO_UPDATE) {
            if (flags->auth_type == AUTH_FROM_SAM_KEYTAB ||
                flags->auth_type == AUTH_FROM_SAM_UPPERCASE_KEYTAB ||
                flags->auth_type == AUTH_FROM_EXPLICIT_KEYTAB) {
                std::string pwdLastSet = ldap_get_pwdLastSet(flags);
                /* Windows timestamp is in
                 * 100-nanoseconds-since-1601. (or, tenths of
                 * microseconds) */
                long long windows_timestamp = strtoll(pwdLastSet.c_str(),
                                                      NULL,
                                                      10);
                long long epoch_bias_1601_to_1970 = 116444736000000000LL;
                /* Unix timestamp is seconds since 1970. */
                long long unix_timestamp;
                if (windows_timestamp < epoch_bias_1601_to_1970) {
                    unix_timestamp = 0;
                } else {
                    unix_timestamp = (windows_timestamp -
                                      epoch_bias_1601_to_1970) / 10000000;
                }
                time_t current_unix_time = time(NULL);
                long long days_since_password_change = (current_unix_time -
                                                        unix_timestamp) / 86400;
                VERBOSE("Password last set %lld days ago.",
                        days_since_password_change);
                if (days_since_password_change < flags->auto_update_interval) {
                    VERBOSE("Exiting because password was changed recently.");
                    return 0;
                }
            }
        }

        /* Check if computer account exists, update if so, create if
         * not. */
        if (! ldap_check_account(flags)) {
            if (flags->password.empty()) {
                fprintf(stderr,
                        "Error: a new AD account needs to be created "
                        "but there is no password.");
                if (flags->dont_change_password) {
                    fprintf(stderr,
                            " Please provide a password with "
                            "--old-account-password <password>");
                }
                fprintf(stderr, "\n");
                exit(1);
            } else {
                ldap_create_account(flags);
                flags->kvno = ldap_get_kvno(flags);
            }

        } else {
            /* We retrieve the kvno _before_ the password change and
             * increment it. */
            flags->kvno = ldap_get_kvno(flags);
            if ((flags->auth_type != AUTH_FROM_SUPPLIED_EXPIRED_PASSWORD) &&
                (!flags->dont_change_password)) {
                flags->kvno++;
            }

            if ((flags->auth_type != AUTH_FROM_SUPPLIED_EXPIRED_PASSWORD) &&
                (!flags->dont_change_password)) {
                /* Set the password. */
                ret = set_password(flags);
                if (ret) {
                    fprintf(stderr, "Error: set_password failed\n");
                    if (flags->use_service_account) {
                        fprintf(stderr,
                                "Hint: Does your password policy allow to "
                                "change %s's password?\n",
                                flags->sAMAccountName.c_str()
                            );
                        fprintf(stderr, "      For example, there could be a "
                                "\"Minimum password age\" policy preventing\n"
                            );
                        fprintf(stderr, "      passwords from being changed "
                                "too frequently. If so, you can reset the\n"
                            );
                        fprintf(stderr, "      password instead of changing "
                                "it using the --user-creds-only option.\n"
                            );
                        fprintf(stderr, "      Be aware that you need a "
                                "ticket of a user with administrative "
                                "privileges\n"
                            );
                        fprintf(stderr, "      for that.\n");
                    }
                    return ret;
                }
            }
        }

        /* Add and remove principals to servicePrincipalName in LDAP.*/
        add_and_remove_principals(exec);

        remove_keytab_entries(flags, exec->remove_principals);

        /* update keytab */
        if (flags->use_service_account) {
            VERBOSE("Updating all entries for service account %s in the keytab %s",
                    flags->sAMAccountName.c_str(),
                    flags->keytab_writename.c_str());
        } else {
            VERBOSE("Updating all entries for computer account %s in the keytab %s",
                    flags->sAMAccountName.c_str(),
                    flags->keytab_writename.c_str());
        }
        update_keytab(flags);

        add_keytab_entries(flags);

        wait_for_new_kvno(flags);
        return ret;
    } else if (exec->mode == MODE_PRECREATE) {
        /* Change account password to default value: */
        flags->password = create_default_machine_password(
            flags->sAMAccountName);
        /* Check if computer account exists, update if so, create if
         * not. */
        if (! ldap_check_account(flags)) {
            ldap_create_account(flags);
        }

        /* Set the password. */
        ret = set_password(flags);
        if (ret) {
            fprintf(stderr, "Error: set_password failed\n");
            return ret;
        }

        /* And add and remove principals to servicePrincipalName in
         * LDAP. */
        add_and_remove_principals(exec);
        wait_for_new_kvno(flags);
        return ret;
    } else if (exec->mode == MODE_CLEANUP) {
        fprintf(stdout, "Cleaning keytab %s\n",
                flags->keytab_writename.c_str());
        cleanup_keytab(flags);
        return 0;
    }

    return 0;
}


void msktutil_exec::set_mode(msktutil_mode mode) {
    if (this->mode != MODE_NONE) {
        fprintf(stderr, "Error: only one mode argument may be provided.\n");
        fprintf(stderr, "\nFor help, try running %s --help\n\n", PACKAGE_NAME);
        exit(1);
    }
    this->mode = mode;
}

Globals *Globals::instance;

int main(int argc, char *argv [])
{
    /* unbuffer stdout. */
    setbuf(stdout, NULL);
    initialize_g_context();

    int i;
    int start_i;
    start_i = 2;
    msktutil_exec *exec = Globals::exec();
    msktutil_flags *flags = Globals::flags();

    if (argc > 1) {
        /* determine MODE */
        if (!strcmp(argv[1], "create")) {
            exec->set_mode(MODE_CREATE);
        } else if (!strcmp(argv[1], "update")) {
            exec->set_mode(MODE_UPDATE);
        } else if (!strcmp(argv[1], "auto-update")) {
            exec->set_mode(MODE_AUTO_UPDATE);
        } else if (!strcmp(argv[1], "pre-create")) {
            exec->set_mode(MODE_PRECREATE);
        } else if (!strcmp(argv[1], "flush")) {
            exec->set_mode(MODE_FLUSH);
        } else if (!strcmp(argv[1], "cleanup")) {
            exec->set_mode(MODE_CLEANUP);
        } else if (!strcmp(argv[1], "delete")) {
            exec->set_mode(MODE_DELETE);
        }
    }

    if (exec->mode == MODE_NONE) {
        /* compatibility for old command line syntax (e.g. "--create"
         * or "-c" instead of "create") */
        start_i = 1;
    }

    for (i = start_i; i < argc; i++) {

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
            exec->set_mode(MODE_FLUSH);
            continue;
        }

        /* Update All Principals */
        if (!strcmp(argv[i], "--update") || !strcmp(argv[i], "-u")) {
            exec->set_mode(MODE_UPDATE);
            continue;
        }

        /* Update All Principals, if needed */
        if (!strcmp(argv[i], "--auto-update")) {
            exec->set_mode(MODE_AUTO_UPDATE);
            continue;
        }

        /* Create 'Default' Keytab */
        if (!strcmp(argv[i], "--create") || !strcmp(argv[i], "-c")) {
            exec->set_mode(MODE_CREATE);
            continue;
        }

        /* Pre-create computer account for another host */
        if (!strcmp(argv[i], "--precreate")) {
            exec->set_mode(MODE_PRECREATE);
            flags->user_creds_only = true;
            continue;
        }

        /* Service Principal Name */
        if (!strcmp(argv[i], "--service") || !strcmp(argv[i], "-s")) {
            if (++i < argc) {
                exec->add_principals.push_back(argv[i]);
            } else {
                fprintf(stderr,
                        "Error: No service principal given after '%s'\n",
                        argv[i - 1]
                    );
                goto error;
            }
            continue;
        }
        if (!strcmp(argv[i], "--remove-service")) {
            if (++i < argc) {
                exec->remove_principals.push_back(argv[i]);
            } else {
                fprintf(stderr,
                        "Error: No service principal given after '%s'\n",
                        argv[i - 1]
                    );
                goto error;
            }
            continue;
        }

        /* Host name */
        if (!strcmp(argv[i], "--host") ||
            !strcmp(argv[i], "--hostname") ||
            !strcmp(argv[i], "-h")) {
            if (++i < argc) {
                flags->hostname = argv[i];
            } else {
                fprintf(stderr,
                        "Error: No name given after '%s'\n",
                        argv[i - 1]
                    );
                goto error;
            }
            continue;
        }

        /* no canonical name */
        if (!strcmp(argv[i], "--no-canonical-name") ||
            !strcmp(argv[i], "-n")) {
            flags->no_canonical_name = true;
            continue;
        }

        /* computer password */
        if (!strcmp(argv[i], "--old-account-password")) {
            if (++i < argc) {
                flags->old_account_password = argv[i];
            } else {
                fprintf(stderr,
                        "Error: No password given after '%s'\n",
                        argv[i - 1]
                    );
                goto error;
            }
            continue;
        }

        if (!strcmp(argv[i], "--password")) {
            if (++i < argc) {
                                flags->password_from_cmdline = true;
                                flags->password = argv[i];
            } else {
                fprintf(stderr,
                        "Error: No password given after '%s'\n",
                        argv[i - 1]
                    );
                goto error;
            }
            continue;
        }

        /* do not change the password */
        if (!strcmp(argv[i], "--dont-change-password")) {
            flags->dont_change_password = true;
            continue;
        }

        /* site */
        if (!strcmp(argv[i], "--site")) {
            if (++i < argc) {
                flags->site = argv[i];
            } else {
                fprintf(stderr,
                        "Error: No site given after '%s'\n",
                        argv[i - 1]
                    );
                goto error;
            }
            continue;
        }

        /* W2008 msDs-supportedEncryptionTypes */
        if (!strcmp(argv[i], "--enctypes")) {
            if (++i < argc) {
                set_supportedEncryptionTypes(flags, argv[i]);
            } else {
                fprintf(stderr,
                        "Error: No enctype after '%s'\n",
                        argv[i - 1]
                    );
                goto error;
            }
            continue;
        }

        /* Re-activate DES encryption in fake krb5.conf */
        if (!strcmp(argv[i], "--allow-weak-crypto")) {
            flags->allow_weak_crypto = true;
            continue;
        }

        /* Enable the account */
        if (!strcmp(argv[i], "--enable")) {
            flags->disable_account = VALUE_OFF;
            continue;
        }

        /* Disable the PAC ? */
        if (!strcmp(argv[i], "--no-pac")) {
            flags->no_pac = VALUE_ON;
            continue;
        }
        if (!strcmp(argv[i], "--disable-no-pac")) {
            flags->no_pac = VALUE_OFF;
            continue;
        }

        /* Use service account */
        if (!strcmp(argv[i], "--use-service-account")) {
            flags->use_service_account = true;
            continue;
        }

        /* Trust for delegation ? */
        if (!strcmp(argv[i], "--delegation")) {
            flags->delegate = VALUE_ON;
            continue;
        }
        if (!strcmp(argv[i], "--disable-delegation")) {
            flags->delegate = VALUE_OFF;
            continue;
        }

        /* Password expiry (is rotation required?) */
        if (!strcmp(argv[i], "--dont-expire-password")) {
            flags->dont_expire_password = VALUE_ON;
            continue;
        }

        /* Prevent dnsHostName attribute update */
        if (!strcmp(argv[i], "--dont-update-dnshostname")) {
            flags->dont_update_dnshostname = VALUE_ON;
            continue;
        }

        if (!strcmp(argv[i], "--do-expire-password")) {
            flags->dont_expire_password = VALUE_OFF;
            continue;
        }

        /* Use a certain sam account name */
        if (!strcmp(argv[i], "--computer-name") ||
            !strcmp(argv[i], "--account-name")) {
            if (++i < argc) {
                flags->sAMAccountName = argv[i];
            } else {
                fprintf(stderr,
                        "Error: No name given after '%s'\n",
                        argv[i - 1]
                    );
                goto error;
            }
            continue;
        }

        if (!strcmp(argv[i], "--upn")) {
            if (++i < argc) {
                flags->set_userPrincipalName = true;
                flags->userPrincipalName = argv[i];
            } else {
                fprintf(stderr,
                        "Error: No principal given after '%s'\n",
                        argv[i - 1]
                    );
                goto error;
            }
            continue;
        }

        /* Use certain keytab file */
        if (!strcmp(argv[i], "--keytab") || !strcmp(argv[i], "-k")) {
            if (++i < argc) {
                flags->keytab_file = argv[i];
            } else {
                fprintf(stderr,
                        "Error: No file given after '%s'\n",
                        argv[i - 1]
                    );
                goto error;
            }
            continue;
        }

        /* Use a certain LDAP base OU ? */
        if (!strcmp(argv[i], "--base") || !strcmp(argv[i], "-b")) {
            if (++i < argc) {
                flags->ldap_ou = argv[i];
            } else {
                fprintf(stderr,
                        "Error: No base given after '%s'\n",
                        argv[i - 1]
                    );
                goto error;
            }
            continue;
        }

        /* Set the description on the computer account */
        if (!strcmp(argv[i], "--description")) {
            if (++i < argc) {
                flags->description = argv[i];
            } else {
                fprintf(stderr,
                        "Error: No description given after '%s'\n",
                        argv[i - 1]
                    );
                goto error;
            }
            continue;
        }

        /* Use a certain LDAP server */
        if (!strcmp(argv[i], "--server")) {
            if (++i < argc) {
                flags->server = argv[i];
            } else {
                fprintf(stderr,
                        "Error: No server given after '%s'\n",
                        argv[i - 1]
                    );
                goto error;
            }
            continue;
        }

        /* ignore server IP validation error caused by NAT */
        if (!strcmp(argv[i], "--server-behind-nat")) {
            flags->server_behind_nat = true;
            continue;
        }

        /* Use a certain realm */
        if (!strcmp(argv[i], "--realm")) {
            if (++i < argc) {
                flags->realm_name = argv[i];
            } else {
                fprintf(stderr,
                        "Error: No realm given after '%s'\n",
                        argv[i - 1]
                    );
                goto error;
            }
            continue;
        }

        /* do not reverse lookup server names */
        if (!strcmp(argv[i], "--no-reverse-lookups") ||
            !strcmp(argv[i], "-N")) {
            flags->no_reverse_lookups = true;
            continue;
        }

        /* synchronize machine password with samba */
        if (!strcmp(argv[i], "--set-samba-secret")) {
            flags->set_samba_secret = true;
            continue;
        }

        /* use supplied command instead of samba net */
        if (!strcmp(argv[i], "--use-samba-cmd")) {
            if (++i < argc) {
                flags->samba_cmd = argv[i];
            } else {
                fprintf(stderr,
                        "Error: No command given after '%s'\n",
                        argv[i -1]
                    );
                goto error;
            }
            continue;
        }

        /* Use user kerberos credentials only */
        if (!strcmp(argv[i], "--user-creds-only")) {
            flags->user_creds_only = true;
            continue;
        }

        if (!strcmp(argv[i], "--keytab-auth-as")) {
            if (++i < argc) {
                flags->keytab_auth_princ = argv[i];
            } else {
                fprintf(stderr,
                        "Error: No principal given after '%s'\n",
                        argv[i - 1]
                    );
                goto error;
            }
            continue;
        }

        if (!strcmp(argv[i], "--auto-update-interval")) {
            if (++i < argc) {
                flags->auto_update_interval = atoi(argv[i]);
            } else {
                fprintf(stderr,
                        "Error: No number given after '%s'\n",
                        argv[i - 1]
                    );
                goto error;
            }
            continue;
        }

        if (!strcmp(argv[i], "--sasl-mechanisms") || !strcmp(argv[i], "-m")) {
            if (++i < argc) {
                flags->sasl_mechanisms = argv[i];
            } else {
                fprintf(stderr,
                        "Error: No SASL candidate mechanisms list given after '%s'\n",
                        argv[i - 1]
                    );
                goto error;
            }
            continue;
        }

        if (!strcmp(argv[i], "--remove-old")) {
            if (++i < argc) {
                flags->cleanup_days = atoi(argv[i]);
            } else {
                fprintf(stderr,
                        "Error: No number given after '%s'\n",
                        argv[i - 1]
                    );
                goto error;
            }
            continue;
        }

        if (!strcmp(argv[i], "--remove-enctype")) {
            if (++i < argc) {
                set_cleanup_enctype(flags, argv[i]);
            } else {
                fprintf(stderr,
                        "Error: No number given after '%s'\n",
                        argv[i - 1]
                    );
                goto error;
            }
            continue;
        }

        /* wait for LDAP replication */
        if (!strcmp(argv[i], "--check-replication")) {
            flags->check_replication = true;
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

    /* make --old-account-password and --user-creds-only mutually
     * exclusive: */
    if (strlen(flags->old_account_password.c_str()) &&
        flags->user_creds_only) {
        fprintf(stderr,
                "Error: --old-account-password and --user-creds-only "
                "are mutually exclusive\n");
        goto error;
    }

    if (strcmp(flags->samba_cmd.c_str(),DEFAULT_SAMBA_CMD) &&
        !flags->set_samba_secret) {
        fprintf(stderr,
                "Error: --use-samba-cmd (or MSKTUTIL_SAMBA_CMD "
                "environment variable) can only be used with "
                "--set-samba-secret\n");
        goto error;
    }

    /* allow --dont-change-password only in update mode or when create
     * mode is called with --old-account-password */
    if (flags->dont_change_password &&
        !(exec->mode == MODE_UPDATE || exec->mode == MODE_CREATE)
        ) {
        fprintf(stderr,
                "Error: --dont-change-password can only be used in update or create mode\n"
            );
        goto error;
    }

    if (flags->dont_change_password && exec->mode == MODE_CREATE && flags->old_account_password.empty()) {
        fprintf(stderr,
                "Error: --dont-change-password needs --old-account-password <password> in create mode\n"
            );
        goto error;
    }

    /* allow --remove-enctype only in cleanup mode */
    if (exec->mode != MODE_CLEANUP &&
        flags->cleanup_enctype != VALUE_IGNORE) {
        fprintf(stderr,
                "Error: --remove-enctype can only be used in cleanup mode\n"
            );
        goto error;
    }

    /* allow --remove-old only in cleanup mode */
    if (exec->mode != MODE_CLEANUP && flags->cleanup_days != -1) {
        fprintf(stderr,
                "Error: --remove-old can only be used in cleanup mode\n"
            );
        goto error;
    }

    if (flags->enctypes == VALUE_ON) {
        if ((flags->supportedEncryptionTypes | ALL_MS_KERB_ENCTYPES) != ALL_MS_KERB_ENCTYPES) {
            fprintf(stderr,
                    "Error: Unsupported --enctypes must be integer that "
                    "fits mask=0x%x\n",
                    ALL_MS_KERB_ENCTYPES
                );
            goto error;
        }
        if (flags->supportedEncryptionTypes == 0) {
            fprintf(stderr, "Error: --enctypes must not be zero\n");
            goto error;
        }
    }

    if (exec->mode == MODE_CREATE && !flags->use_service_account) {
        exec->add_principals.push_back("host");
    }

    if (exec->mode == MODE_NONE && !exec->add_principals.empty()) {
        exec->set_mode(MODE_UPDATE);
    }

    if (exec->mode == MODE_CLEANUP &&
        flags->cleanup_days == -1 &&
        flags->cleanup_enctype == VALUE_IGNORE) {
            fprintf(stderr,
                    "Error: cleanup mode needs --remove-old or "
                    "--remove-enctype\n"
                );
            goto error;
    }

    if (exec->mode == MODE_NONE) {
        /* Default, no options present */
        fprintf(stderr, "Error: No command given\n");
        goto error;
    }

    try {
        return execute(exec, flags);
    } catch (Exception &e) {
        fprintf(stderr, "%s\n", e.what());
        exit(1);
    }

error:
    fprintf(stderr, "\nFor help, try running %s --help\n\n", PACKAGE_NAME);
    return 1;
}

Globals*
Globals::get() {
    if (instance==NULL) {
        instance = new Globals();
        instance->_flags = new msktutil_flags;
        instance->_exec = new msktutil_exec;
    }
    return instance;
}

void
Globals::set_supportedEncryptionTypes(char * value)
{
    _flags->enctypes = VALUE_ON;
    _flags->supportedEncryptionTypes = strtol(value, NULL, 0);
}


msktutil_flags::msktutil_flags() :
    password(),
    password_from_cmdline(false),
    ldap(NULL),
    set_userPrincipalName(false),
    no_reverse_lookups(false),
    no_canonical_name(false),
    server_behind_nat(false),
    set_samba_secret(false),
    samba_cmd(DEFAULT_SAMBA_CMD),
    check_replication(false),
    dont_change_password(false),
    dont_expire_password(VALUE_IGNORE),
    dont_update_dnshostname(VALUE_OFF),
    disable_account(VALUE_IGNORE),
    no_pac(VALUE_IGNORE),
    delegate(VALUE_IGNORE),
    ad_userAccountControl(0),
    ad_enctypes(VALUE_IGNORE),
    ad_supportedEncryptionTypes(0),
    enctypes(VALUE_IGNORE),
    /* default values we *want* to support */
    supportedEncryptionTypes(DEFAULT_MS_KERB_ENCTYPES),
    auth_type(0),
    user_creds_only(false),
    use_service_account(false),
    allow_weak_crypto(false),
    password_expired(false),
    auto_update_interval(30),
    sasl_mechanisms(DEFAULT_SASL_MECHANISMS),
    kvno(0),
    cleanup_days(-1),
    cleanup_enctype(VALUE_IGNORE)
{
    /* Check for environment variables as well.  These variables will
     * be overriden by command line arguments. */
    if (getenv("MSKTUTIL_KEYTAB")) {
        keytab_file = getenv("MSKTUTIL_KEYTAB");
    }
    if (getenv("MSKTUTIL_NO_PAC")) {
        no_pac = VALUE_ON;
    }
    if (getenv("MSKTUTIL_DELEGATION")) {
        delegate = VALUE_ON;
    }
    if (getenv("MSKTUTIL_LDAP_BASE")) {
        ldap_ou = getenv("MSKTUTIL_LDAP_BASE");
    }
    if (getenv("MSKTUTIL_SERVER")) {
        server = getenv("MSKTUTIL_SERVER");
    }
    if (getenv("MSKTUTIL_SAMBA_CMD")) {
        samba_cmd = getenv("MSKTUTIL_SAMBA_CMD");
    }
}


msktutil_flags::~msktutil_flags()
{
    ldap_cleanup(this);
    init_password(this);
}


msktutil_exec::msktutil_exec() :
    mode(MODE_NONE)
{
}


msktutil_exec::~msktutil_exec()
{
    VERBOSE("Destroying msktutil_exec");
    remove_fake_krb5_conf();
    remove_ccache();
}
