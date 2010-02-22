/*
 *----------------------------------------------------------------------------
 *
 * msktutil.c
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
#include <cctype>
#include <memory>

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


void catch_int(int)
{
    remove_fake_krb5_conf();
    exit(1);
}


void set_samAccountName(msktutil_exec *exec, const std::string &samAccountName)
{
    exec->flags->samAccountName_nodollar = samAccountName;
    exec->flags->samAccountName = samAccountName + "$";
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



void create_default(msktutil_exec *exec)
{
    exec->update = 1;
    exec->principals.push_back("host");
}



int finalize_exec(msktutil_exec *exec)
{
    msktutil_flags *flags = exec->flags;


    init_password(flags);
    char *temp_realm;
    if (krb5_get_default_realm(g_context.get(), &temp_realm)) {
        fprintf(stderr, "Error: krb5_get_default_realm failed\n");
        exit(-1);
    }
    flags->realm_name = std::string(temp_realm);
#ifdef HEIMDAL
    krb5_xfree(temp_realm);
#else
    krb5_free_default_realm(g_context.get(), temp_realm);
#endif

    flags->lower_realm_name = flags->realm_name;
    for(std::string::iterator it = flags->lower_realm_name.begin();
        it != flags->lower_realm_name.end(); ++it)
        *it = std::tolower(*it);

    if (get_dc(flags)) {
        fprintf(stderr, "Error: get_dc failed\n");
        exit(-1);
    }
    get_default_keytab(flags);

    signal(SIGINT, catch_int);
    create_fake_krb5_conf(flags);

    /* Canonicalize the hostname if need be */
    if (exec->flags->hostname.empty())
        exec->flags->hostname = get_default_hostname();
    else
        exec->flags->hostname = complete_hostname(flags->hostname);

    flags->short_hostname = get_short_hostname(flags);

    /* Determine the samAccountName, if not set */
    if (flags->samAccountName.empty()) {
        set_samAccountName(exec, flags->short_hostname);
    }
    /* The samAccountName will cause win 9x, NT problems if longer than MAX_SAM_ACCOUNT_LEN characters */
    if (flags->samAccountName.length() > MAX_SAM_ACCOUNT_LEN) {
        fprintf(stderr, "Error: The SAM name (%s) for this host is longer than the maximum of MAX_SAM_ACCOUNT_LEN characters\n",
                flags->samAccountName.c_str());
        fprintf(stderr, "You can specify a shorter name using --computer-name\n");
        exit(-1);
    }
    VERBOSE("SAM Account Name is: %s", flags->samAccountName.c_str());

    /* Qualify all remaining entries in the principals list */
    for(size_t i = 0; i < exec->principals.size(); ++i) {
        // If no hostname part, add it:
        if (exec->principals[i].find('/') == std::string::npos)
            exec->principals[i].append("/").append(flags->hostname);
    }

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

    flags->ldap = ldap_connect(flags->server);
    if (!flags->ldap.get()) {
        fprintf(stderr, "Error: ldap_connect failed\n");
        exit(-1);
    }
    if (ldap_get_base_dn(flags)) {
        fprintf(stderr, "Error: get_ldap_base_dn failed\n");
        exit(-1);
    }
    get_default_ou(flags);

    return 0;
}


int execute(msktutil_exec *exec)
{
    int ret = 0;
    msktutil_flags *flags = exec->flags;

    if (exec->show_help) {

        fprintf(stdout, "Usage: %s [OPTIONS]\n", PACKAGE_NAME);
        fprintf(stdout, "\n");
        fprintf(stdout, "Options: \n");
        fprintf(stdout, "  -b, --base <base ou>     Sets the LDAP base OU to use when creating an account.\n");
        fprintf(stdout, "                           The default is read from AD (often CN=computers)\n");
        fprintf(stdout, "  -c, --create             Creates a default keytab for the local host\n");
        fprintf(stdout, "                           A default keytab contains a HOST principal\n");
        fprintf(stdout, "  --computer-name <name>   Sets the computer account name to <name>\n");
        fprintf(stdout, "  --delegation             Set the computer account to be trusted for delegation\n");
        fprintf(stdout, "  --description <text>     Sets the description field on the computer account\n");
        fprintf(stdout, "  --disable-delegation     Set the computer account to not be trusted for delegation\n");
        fprintf(stdout, "  --disable-no-pac         Sets the service principal to include a PAC\n");
        fprintf(stdout, "  --enctypes <int>         Sets msDs-supportedEncryptionTypes\n");
        fprintf(stdout, "                           (OR of: 0x1=des-cbc-crc 0x2=des-cbc-md5 0x4=rc4-hmac-md5\n");
        fprintf(stdout, "                                   0x8=aes128-ctc-hmac-sha1 0x10=aes256-cts-hmac-sha1)\n");
        fprintf(stdout, "                           Also sets des-bit in userAccountControl if set to 0x3.\n");
        fprintf(stdout, "  -f, --flush              Flushes all principals for the current host\n");
        fprintf(stdout, "  -h, --hostname <name>    Sets the current hostname to <name>\n");
        fprintf(stdout, "  --help                   Displays this message\n");
        fprintf(stdout, "  -k, --keytab <file>      Use <file> for the keytab\n");
        fprintf(stdout, "  --no-pac                 Sets the service principal to not include a PAC\n");
        fprintf(stdout, "  -s, --service <service>  Adds the service <service> for the current host\n");
        fprintf(stdout, "                           The service is of the form <service>/<hostname>\n");
        fprintf(stdout, "                           If the hostname is omitted, the hostname given to '-h' is used\n");
        fprintf(stdout, "  --server <name>          Attempt to use a specific domain controller\n");
        fprintf(stdout, "  -u, --update             Updates all principals for the current host\n");
        fprintf(stdout, "                           This changes the host's secret and updates the keytab for all entries\n");
        fprintf(stdout, "  --upn <principal>        Set the user principal name to be <principal>\n");
        fprintf(stdout, "                           The realm name will be appended to this principal\n");
        fprintf(stdout, "  -v, --version            Display the current version\n");
        fprintf(stdout, "  --verbose                Enable verbose messages\n");
        fprintf(stdout, "                           More then once to get LDAP debugging\n");

        return 0;
    }

    if (exec->show_version) {
        fprintf(stdout, "%s version %s\n", PACKAGE_NAME, PACKAGE_VERSION);
        return 0;
    }

    if (exec->flush || exec->update || exec->principals.size()) {
        ret = finalize_exec(exec);
        if (ret) {
            fprintf(stderr, "Error: finalize_exec failed\n");
            exit(ret);
        }
    }

    if (exec->flush) {
        fprintf(stdout, "Flushing all entries for %s from the keytab %s\n", flags->hostname.c_str(),
                flags->keytab_file.c_str());
        ret = flush_keytab(flags);
        return ret;
    }

    if (!exec->principals.empty()) {
        /* Adding a principal will cause the machine account password to be reset - we don't
         * store the current password anywhere - so we need to update any other principals
         * the machine has before adding new ones. */
        exec->update = true;
    }

    if (exec->update) {
        fprintf(stdout, "Updating all entries for %s in the keytab %s\n", flags->hostname.c_str(),
                flags->keytab_file.c_str());
        ret = update_keytab(flags);
        if (ret) {
            fprintf(stderr, "Error: update_keytab failed\n");
            return ret;
        }
    }

    if (!exec->principals.empty()) {
        for (size_t i = 0; i < exec->principals.size(); ++i) {
            std::string principal = exec->principals[i];
            int loc_ret = ldap_add_principal(principal, flags);
            if (loc_ret) {
                fprintf(stderr, "Error: ldap_add_principal failed\n");
                ret = 1;
                continue;
            }

            fprintf(stdout, "Adding principal %s to the keytab %s\n", principal.c_str(),
                    flags->keytab_file.c_str());
            ret |= add_principal(principal, flags);
        }
    }

    /* Default, no options present */
    fprintf(stderr, "Error: No command given\n");
    fprintf(stderr, "\nFor help, try running %s --help\n\n", PACKAGE_NAME);

    return 0;
}


int main(int argc, char *argv [])
{
    int i;
    std::auto_ptr<msktutil_exec> exec(new msktutil_exec());

    for (i = 1; i < argc; i++) {

        /* Service Principal Name */
        if (!strcmp(argv[i], "--service") || !strcmp(argv[i], "-s")) {
            if (++i < argc) {
                exec->principals.push_back(argv[i]);
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

        /* Trust for delegation ? */
        if (!strcmp(argv[i], "--delegation")) {
            exec->flags->delegate = VALUE_ON;
            continue;
        }
        if (!strcmp(argv[i], "--disable-delegation")) {
            exec->flags->delegate = VALUE_OFF;
            continue;
        }

        /* Flush the keytab */
        if (!strcmp(argv[i], "--flush") || !strcmp(argv[i], "-f")) {
            exec->flush = true;
            continue;
        }

        /* Use a certain sam account name */
        if (!strcmp(argv[i], "--computer-name")) {
            if (++i < argc) {
                set_samAccountName(exec.get(), argv[i]);
            } else {
                fprintf(stderr, "Error: No name given after '%s'\n", argv[i - 1]);
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

        /* Update All Principals */
        if (!strcmp(argv[i], "--update") || !strcmp(argv[i], "-u")) {
            exec->update = true;
            continue;
        }

        /* Create 'Default' Keytab */
        if (!strcmp(argv[i], "--create") ||
            !strcmp(argv[i], "-c")) {
            create_default(exec.get());
            continue;
        }

        /* Display Version Message */
        if (!strcmp(argv[i], "-v") || !strcmp(argv[i], "--version")) {
            exec->show_version = true;
            continue;
        }

        /* Display Verbose Messages */
        if (!strcmp(argv[i], "--verbose")) {
            do_verbose();
            continue;
        }

        /* Display Help Messages */
        if (!strcmp(argv[i], "--help") || !strcmp(argv[i], "--usage")) {
            exec->show_help = true;
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
            fprintf(stderr, " Unsupported --enctypes must be integer that fits mask=0x%x", known);
            goto error;
        }
        if (exec->flags->supportedEncryptionTypes == 0) {
            fprintf(stderr, " --enctypes must not be zero\n");
            goto error;
        }
    }

    return execute(exec.get());

error:
    fprintf(stderr, "\nFor help, try running %s --help\n\n", PACKAGE_NAME);
    return -1;
}


msktutil_flags::msktutil_flags() :
    password(), ldap(), no_pac(VALUE_IGNORE), delegate(VALUE_IGNORE),
    ad_userAccountControl(0), ad_enctypes(VALUE_IGNORE), ad_supportedEncryptionTypes(0),
    enctypes(VALUE_IGNORE),
    /* default values we *want* to support */
    supportedEncryptionTypes(MS_KERB_ENCTYPE_RC4_HMAC_MD5 |
                             MS_KERB_ENCTYPE_AES128_CTC_HMAC_SHA1_96 |
                             MS_KERB_ENCTYPE_AES256_CTS_HMAC_SHA1_96)
{}

msktutil_flags::~msktutil_flags() {
    ldap_cleanup(this);
    init_password(this);
}


msktutil_exec::msktutil_exec() :
    show_help(0), show_version(0), update(0), flush(0), flags(new msktutil_flags())
{
    /* Check for environment variables as well.  These variables will be overriden
     * By command line arguments. */
    if (getenv("MSKTUTIL_DESCRIPTION"))
        flags->description = getenv("MSKTUTIL_DESCRIPTION");
    if (getenv("MSKTUTIL_KEYTAB"))
        flags->keytab_file = getenv("MSKTUTIL_KEYTAB");
    if (getenv("MSKTUTIL_NO_PAC"))
        flags->no_pac = VALUE_ON;
    if (getenv("MSKTUTIL_DELEGATION"))
        flags->delegate = VALUE_ON;
    if (getenv("MSKTUTIL_LDAP_BASE"))
        flags->ldap_ou = getenv("MSKTUTIL_LDAP_BASE");
    if (getenv("MSKTUTIL_HOSTNAME"))
        flags->hostname = getenv("MSKTUTIL_HOSTNAME");
    if (getenv("MSKTUTIL_SERVER"))
        flags->server = getenv("MSKTUTIL_SERVER");
    if (getenv("MSKTUTIL_SAM_NAME"))
        set_samAccountName(this, getenv("MSKTUTIL_SAM_NAME"));
}

msktutil_exec::~msktutil_exec() {
    remove_fake_krb5_conf();

    delete flags;
}
