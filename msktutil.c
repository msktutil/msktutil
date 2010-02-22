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


void set_ldap_ou(msktutil_exec *exec, const std::string &ou)
{
    exec->flags->ldap_ou = ou;
}


void set_hostname(msktutil_exec *exec, const std::string &hostname)
{
    exec->flags->hostname = hostname;
}


void set_keytab_file(msktutil_exec *exec, const std::string &file)
{
    exec->flags->keytab_file = file;
}


void set_description(msktutil_exec *exec, const std::string &description)
{
    exec->flags->description = description;
}


void set_server(msktutil_exec *exec, const std::string server)
{
    exec->flags->server = server;
}


void set_samAccountName(msktutil_exec *exec, const std::string &samAccountName)
{
    exec->flags->samAccountName_nodollar = samAccountName;
    exec->flags->samAccountName = samAccountName + "$";
}



void set_desbit(msktutil_exec *exec, msktutil_val value)
{
    exec->flags->des_bit = value;
}

void set_supportedEncryptionTypes(msktutil_exec *exec, char * value)
{
    exec->flags->enctypes = VALUE_ON;
    exec->flags->supportedEncryptionTypes = atoi(value);
}


void set_no_pac(msktutil_exec *exec, msktutil_val value)
{
    exec->flags->no_pac = value;
}


void set_delegate(msktutil_exec *exec, msktutil_val value)
{
    exec->flags->delegate = value;
}


void flush_all(msktutil_exec *exec)
{
    exec->flush = 1;
}


void update_all(msktutil_exec *exec)
{
    exec->update = 1;
}

void do_verbose()
{
    g_verbose++; /* allow for ldap debuging */
}


void display_version(msktutil_exec *exec)
{
    exec->show_version = 1;
}


void display_help(msktutil_exec *exec)
{
    exec->show_help = 1;
}


void create_default(msktutil_exec *exec)
{
    exec->principals.clear();

    exec->show_help = 0;
    exec->flush = 0;
    exec->update = 1;
    exec->show_version = 0;
    exec->flags->hostname = get_default_hostname();
    exec->principals.push_back("host");
    get_default_keytab(exec->flags);
    get_default_ou(exec->flags);
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
    krb5_free_default_realm(g_context.get(), temp_realm);

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
    set_hostname(exec, complete_hostname(flags->hostname));

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
    msktutil_flags *flags;


    if (exec && exec->flags) {
        flags = exec->flags;
        if (exec->show_help) {

            fprintf(stdout, "Usage: %s [OPTIONS]\n", PACKAGE_NAME);
            fprintf(stdout, "\n");
            fprintf(stdout, "Options: \n");
            fprintf(stdout, "  -b <base ou>             Sets the LDAP base OU to use when creating an account.\n");
            fprintf(stdout, "                           The default base OU is 'CN=Computers'\n");
            fprintf(stdout, "  --base <base ou>         Same as '-b' <base ou>\n");
            fprintf(stdout, "  -c                       Creates a default keytab for the local host\n");
            fprintf(stdout, "                           A default keytab contains a HOST principal\n");
            fprintf(stdout, "  --create                 Same as '-c'\n");
            fprintf(stdout, "  --computer-name <name>   Sets the computer account name to <name>\n");
            fprintf(stdout, "  --createdefault          Same as '-c'\n");
            fprintf(stdout, "  -d                       Sets the current host account to be DES-only\n");
            fprintf(stdout, "  --delegation             Set the computer account to be trusted for delegation\n");
            fprintf(stdout, "  --des-only               Same as '-d'\n");
            fprintf(stdout, "  --description <text>     Sets the description field on the computer account\n");
            fprintf(stdout, "  --disable-delegation     Set the computer account to not be trusted for delegation\n");
            fprintf(stdout, "  --disable-des-only       Sets the current host account to not be DES-only\n");
            fprintf(stdout, "  --disable-no-pac         Sets the service principal to include a PAC\n");
            fprintf(stdout, "  --enctypes <int>         Sets msDs-supportedEncryptionTypes as defined for W2008\n");
            fprintf(stdout, "  -f                       Flushes all principals for the current host\n");
            fprintf(stdout, "  --flush                  Same as '-f'\n");
            fprintf(stdout, "  -h <name>                Sets the current hostname to <name>\n");
            fprintf(stdout, "  --help                   Same as '-?'\n");
            fprintf(stdout, "  --host <name>            Same as '-h' <name>\n");
            fprintf(stdout, "  --hostname <name>        Same as '-h' <name>\n");
            fprintf(stdout, "  -k <file>                Use <file> for the keytab\n");
            fprintf(stdout, "  --keytab <file>          Same as '-k' <file>\n");
            fprintf(stdout, "  --no-pac                 Sets the service principal to not include a PAC\n");
            fprintf(stdout, "  -s <service>             Adds the service <service> for the current host\n");
            fprintf(stdout, "                           The service is of the form <service>/<hostname>\n");
            fprintf(stdout, "                           If the hostname is omitted, the hostname given to '-h' is used\n");
            fprintf(stdout, "  --service <service>      Same as '-s' <service>\n");
            fprintf(stdout, "  --server <name>          Attempt to use a specific domain controller\n");
            fprintf(stdout, "  -u                       Updates all principals for the current host\n");
            fprintf(stdout, "                           This changes the host's secret and updates the keytab for all entries\n");
            fprintf(stdout, "  --update                 Same as '-u'\n");
            fprintf(stdout, "  --upn <principal>        Set the user principal name to be <principal>\n");
            fprintf(stdout, "                           The realm name will be appended to this principal\n");
            fprintf(stdout, "  --usage                  Same as '-?'\n");
            fprintf(stdout, "  -v                       Display the current version\n");
            fprintf(stdout, "  --verbose                Enable verbose messages\n");
            fprintf(stdout, "                           More then once to get LDAP debugging\n");
            fprintf(stdout, "  --version                Same as '-v'\n");
            fprintf(stdout, "  -?                       Displays this message\n");
            fprintf(stdout, "  --?                      Same as '-?'\n");

            return 0;
        }

        if (exec->show_version) {
            fprintf(stdout, "%s version %s\n", PACKAGE_NAME, PACKAGE_VERSION);
            return 0;
        }

        if (exec->flush || exec->update || exec->principals.size()) {
            if (flags->hostname.empty()) {
                fprintf(stderr, "Error: No hostname specified.\n");
                fprintf(stderr, "       Please specify a hostname using '-h'.\n");
                return -2;
            }
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

        if (exec->update) {
            fprintf(stdout, "Updating all entries for %s in the keytab %s\n", flags->hostname.c_str(),
                    flags->keytab_file.c_str());
            ret = update_keytab(flags);
            return ret;
        }

        if (!exec->principals.empty()) {
            if (!exec->update) {
                /* Adding a principal will cause the machine account password to be reset - we don't
                 * store the current password anywhere - so we need to update any other principals
                 * the machine has before adding new ones. */
                ret = update_keytab(flags);
                if (ret) {
                    fprintf(stderr, "Error: update_keytab failed\n");
                    return ret;
                }
            }

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
            return ret;
        }

        /* Default, no options present */
        fprintf(stderr, "Error: No command given\n");
        fprintf(stderr, "\nFor help, try running %s --help\n\n", PACKAGE_NAME);

        return 0;
    }
    return -1;
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
                set_hostname(exec.get(), argv[i]);
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

        /* DES-Only Bit enabled ? */
        if (!strcmp(argv[i], "--des-only") || !strcmp(argv[i], "-d")) {
            set_desbit(exec.get(), VALUE_ON);
            continue;
        }
        if (!strcmp(argv[i], "--disable-des-only")) {
            set_desbit(exec.get(), VALUE_OFF);
            continue;
        }

        /* Disable the PAC ? */
        if (!strcmp(argv[i], "--no-pac")) {
            set_no_pac(exec.get(), VALUE_ON);
            continue;
        }
        if (!strcmp(argv[i], "--disable-no-pac")) {
            set_no_pac(exec.get(), VALUE_OFF);
            continue;
        }

        /* Trust for delegation ? */
        if (!strcmp(argv[i], "--delegation")) {
            set_delegate(exec.get(), VALUE_ON);
            continue;
        }
        if (!strcmp(argv[i], "--disable-delegation")) {
            set_delegate(exec.get(), VALUE_OFF);
            continue;
        }

        /* Flush the keytab */
        if (!strcmp(argv[i], "--flush") || !strcmp(argv[i], "-f")) {
            flush_all(exec.get());
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
                set_keytab_file(exec.get(), argv[i]);
            } else {
                fprintf(stderr, "Error: No file given after '%s'\n", argv[i - 1]);
                goto error;
            }
            continue;
        }

        /* Use a certain LDAP base OU ? */
        if (!strcmp(argv[i], "--base") || !strcmp(argv[i], "-b")) {
            if (++i < argc) {
                set_ldap_ou(exec.get(), argv[i]);
            } else {
                fprintf(stderr, "Error: No base given after '%s'\n", argv[i - 1]);
                goto error;
            }
            continue;
        }

        /* Set the description on the computer account */
        if (!strcmp(argv[i], "--description")) {
            if (++i < argc) {
                set_description(exec.get(), argv[i]);
            } else {
                fprintf(stderr, "Error: No description given after '%s'\n", argv[i - 1]);
                goto error;
            }
            continue;
        }

        /* Use a certain LDAP server */
        if (!strcmp(argv[i], "--server")) {
            if (++i < argc) {
                set_server(exec.get(), argv[i]);
            } else {
                fprintf(stderr, "Error: No server given after '%s'\n", argv[i - 1]);
                goto error;
            }
            continue;
        }

        /* Update All Principals */
        if (!strcmp(argv[i], "--update") || !strcmp(argv[i], "-u")) {
            update_all(exec.get());
            continue;
        }

        /* Create 'Default' Keytab */
        if (!strcmp(argv[i], "--create") || !strcmp(argv[i], "--createdefault") ||
            !strcmp(argv[i], "-c")) {
            create_default(exec.get());
            continue;
        }

        /* Display Version Message */
        if (!strcmp(argv[i], "-v") || !strcmp(argv[i], "--version")) {
            display_version(exec.get());
            continue;
        }

        /* Display Verbose Messages */
        if (!strcmp(argv[i], "--verbose")) {
            do_verbose();
            continue;
        }

        /* Display Help Messages */
        if (!strcmp(argv[i], "--help") || !strcmp(argv[i], "--?") ||
            !strcmp(argv[i], "-?") || !strcmp(argv[i], "--usage")) {
            display_help(exec.get());
            continue;
        }

        /* Unrecognized */
        fprintf(stderr, "Error: Unknown parameter (%s)\n", argv[i]);
        goto error;
    }

    /*
     * the userAccountControl des-only bit needs to match the enctypes
     * if --des-only, set default supportedEncryptionType to only des
     * If --enctypes 3, i.e. des only, use the des-only flag instead.
     */

    if (exec->flags->des_bit != VALUE_IGNORE &&
        exec->flags->enctypes != VALUE_IGNORE) {
        fprintf(stderr, "conflicting use of --des-only|--disable-des-only des and --enctypes options\n");
        goto error;
    }

    if (exec->flags->des_bit == VALUE_ON) {
         exec->flags->supportedEncryptionTypes=MS_KERB_ENCTYPE_DES_CBC_CRC|MS_KERB_ENCTYPE_DES_CBC_MD5;
    }
    if (exec->flags->enctypes == VALUE_ON &&
            exec->flags->supportedEncryptionTypes ==
            (MS_KERB_ENCTYPE_DES_CBC_CRC|MS_KERB_ENCTYPE_DES_CBC_MD5)) {
        exec->flags->enctypes = VALUE_IGNORE;
        exec->flags->des_bit = VALUE_ON;
    }
    if (exec->flags->enctypes == VALUE_ON) {
        unsigned known= MS_KERB_ENCTYPE_DES_CBC_CRC
                        |MS_KERB_ENCTYPE_DES_CBC_MD5
                        |MS_KERB_ENCTYPE_RC4_HMAC_MD5;
#ifdef ENCTYPE_AES128_CTS_HMAC_SHA1_96
        known |= MS_KERB_ENCTYPE_AES128_CTC_HMAC_SHA1_96;
#endif
#ifdef ENCTYPE_AES256_CTS_HMAC_SHA1_96
        known |= MS_KERB_ENCTYPE_AES256_CTS_HMAC_SHA1_96;
#endif

        if ((exec->flags->supportedEncryptionTypes|known) != known) {
            fprintf(stderr, " Unsupported --enctypes must be decimal integer that fits mask=0x%x", known);
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
    password(), ldap(), des_bit(VALUE_IGNORE), no_pac(VALUE_IGNORE), delegate(VALUE_IGNORE),
    ad_userAccountControl(0), ad_enctypes(VALUE_IGNORE), ad_supportedEncryptionTypes(0),
    enctypes(VALUE_IGNORE),
    supportedEncryptionTypes(MS_KERB_ENCTYPE_RC4_HMAC_MD5) /* default values for w2000, w2003 */
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
    if (getenv("MSKTUTIL_DESCRIPTION")) {
        set_description(this, getenv("MSKTUTIL_DESCRIPTION"));
    }
    if (getenv("MSKTUTIL_KEYTAB")) {
        set_keytab_file(this, getenv("MSKTUTIL_KEYTAB"));
    }
    if (getenv("MSKTUTIL_DES_ONLY")) {
        set_desbit(this, VALUE_ON);
    }
    if (getenv("MSKTUTIL_NO_PAC")) {
        set_no_pac(this, VALUE_ON);
    }
    if (getenv("MSKTUTIL_DELEGATION")) {
        set_delegate(this, VALUE_ON);
    }
    if (getenv("MSKTUTIL_LDAP_BASE")) {
        set_ldap_ou(this, getenv("MSKTUTIL_LDAP_BASE"));
    }
    if (getenv("MSKTUTIL_HOSTNAME")) {
        set_hostname(this, getenv("MSKTUTIL_HOSTNAME"));
    }
    if (getenv("MSKTUTIL_SERVER")) {
        set_server(this, getenv("MSKTUTIL_SERVER"));
    }
    if (getenv("MSKTUTIL_SAM_NAME")) {
        set_samAccountName(this, getenv("MSKTUTIL_SAM_NAME"));
    }
}

msktutil_exec::~msktutil_exec() {
    remove_fake_krb5_conf();

    delete flags;
}
