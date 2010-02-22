/*
 *----------------------------------------------------------------------------
 *
 * msktutil.c
 *
 * (C) 2004-2006 Dan Perry (dperry@pppl.gov)
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


void catch_int(int)
{
    remove_fake_krb5_conf();
    untry_machine_keytab();
    exit(1);
}


void cleanup_exec(msktutil_exec *exec)
{
    int i = 0;

    if (exec) {
        remove_fake_krb5_conf();
        untry_machine_keytab();
        if (exec->flags) {
            if (exec->flags->keytab_file) {
                free(exec->flags->keytab_file);
                exec->flags->keytab_file = NULL;
            }
            if (exec->flags->ldap_ou) {
                free(exec->flags->ldap_ou);
                exec->flags->ldap_ou = NULL;
            }
            if (exec->flags->hostname) {
                free(exec->flags->hostname);
                exec->flags->hostname = NULL;
            }
            if (exec->flags->description) {
                free(exec->flags->description);
                exec->flags->description = NULL;
            }
            if (exec->flags->server) {
                free(exec->flags->server);
                exec->flags->server = NULL;
            }
            if (exec->flags->short_hostname) {
                free(exec->flags->short_hostname);
                exec->flags->short_hostname = NULL;
            }
            if (exec->flags->realm_name) {
                free(exec->flags->realm_name);
                exec->flags->realm_name = NULL;
            }
            if (exec->flags->lower_realm_name) {
                free(exec->flags->lower_realm_name);
                exec->flags->lower_realm_name = NULL;
            }
            if (exec->flags->base_dn) {
                free(exec->flags->base_dn);
                exec->flags->base_dn = NULL;
            }
            if (exec->flags->userPrincipalName) {
                free(exec->flags->userPrincipalName);
                exec->flags->userPrincipalName = NULL;
            }
            if (exec->flags->samAccountName) {
                free(exec->flags->samAccountName);
                exec->flags->samAccountName = NULL;
            }
            if (exec->flags->samAccountName_nodollar) {
                free(exec->flags->samAccountName_nodollar);
                exec->flags->samAccountName_nodollar = NULL;
            }
            krb5_cleanup(exec->flags);
            ldap_cleanup(exec->flags);
            init_password(exec->flags);

            free(exec->flags);
            exec->flags = NULL;
        }
        if (exec->principals) {
            while (exec->principals[i]) {
                free(exec->principals[i]);
                exec->principals[i++] = NULL;
            }
            free(exec->principals);
        }
        free(exec);
    }
}


void add_spn(msktutil_exec *exec, char *principal)
{
    int count = 0;
    char **new_princ;


    if (exec) {
        if (exec->principals) {
            while (exec->principals[count]) {
                count++;
            }
        }
        count += 2;
        new_princ = (char **) malloc(sizeof(char *) * count);
        if (!new_princ) {
            fprintf(stderr, "Error: Out of memory\n");
            cleanup_exec(exec);
            exit(ENOMEM);
        }
        memset(new_princ, 0, count  * sizeof(char *));
        count = 0;
        if (exec->principals) {
            while (exec->principals[count]) {
                new_princ[count] = exec->principals[count];
                count++;
            }
        }
        new_princ[count] = (char*)malloc(strlen(principal) + 1);
        if (!new_princ[count]) {
            fprintf(stderr, "Error: Out of memory\n");
            cleanup_exec(exec);
            exit(ENOMEM);
        }
        memset(new_princ[count], 0, strlen(principal) + 1);
        strcpy(new_princ[count], principal);
        if (exec->principals) {
            free(exec->principals);
        }
        exec->principals = new_princ;
    }
}


void set_ldap_ou(msktutil_exec *exec, char *ou)
{
    if (exec && exec->flags) {
        if (exec->flags->ldap_ou) {
            free(exec->flags->ldap_ou);
        }
        exec->flags->ldap_ou = (char *) malloc(strlen(ou) + 1);
        if (!exec->flags->ldap_ou) {
            fprintf(stderr, "Error: Out of memory\n");
            cleanup_exec(exec);
            exit(ENOMEM);
        }
        memset(exec->flags->ldap_ou, 0, strlen(ou) + 1);
        strcpy(exec->flags->ldap_ou, ou);
    }
}


void set_hostname(msktutil_exec *exec, char *hostname)
{
    if (exec && exec->flags) {
        if (exec->flags->hostname) {
            free(exec->flags->hostname);
        }
        exec->flags->hostname = (char *) malloc(strlen(hostname) + 1);
        if (!exec->flags->hostname) {
            fprintf(stderr, "Error: Out of memory\n");
            cleanup_exec(exec);
            exit(ENOMEM);
        }
        memset(exec->flags->hostname, 0, strlen(hostname) + 1);
        sprintf(exec->flags->hostname, "%s", hostname);
    }
}


void set_keytab_file(msktutil_exec *exec, char *file)
{
    if (exec && exec->flags) {
        if (exec->flags->keytab_file) {
            free(exec->flags->keytab_file);
        }
        exec->flags->keytab_file = (char *) malloc(strlen(file) + 1);
        if (!exec->flags->keytab_file) {
            fprintf(stderr, "Error: Out of memory\n");
            cleanup_exec(exec);
            exit(ENOMEM);
        }
        memset(exec->flags->keytab_file, 0, strlen(file) + 1);
        strcpy(exec->flags->keytab_file, file);
    }
}


void set_description(msktutil_exec *exec, char *description)
{
    if (exec && exec->flags) {
        if (exec->flags->description) {
            free(exec->flags->description);
        }
        exec->flags->description = (char *) malloc(strlen(description) + 1);
        if (!exec->flags->description) {
            fprintf(stderr, "Error: Out of memory\n");
            cleanup_exec(exec);
            exit(ENOMEM);
        }
        memset(exec->flags->description, 0, strlen(description) + 1);
        strcpy(exec->flags->description, description);
    }
}


void set_server(msktutil_exec *exec, char *server)
{
    if (exec && exec->flags) {
        if (exec->flags->server) {
            free(exec->flags->server);
        }
        exec->flags->server = (char *) malloc(strlen(server) + 1);
        if (!exec->flags->server) {
            fprintf(stderr, "Error: Out of memory\n");
            cleanup_exec(exec);
            exit(ENOMEM);
        }
        memset(exec->flags->server, 0, strlen(server) + 1);
        strcpy(exec->flags->server, server);
    }
}


void set_samAccountName(msktutil_exec *exec, char *samAccountName)
{
    if (exec && exec->flags) {
        if (exec->flags->samAccountName) {
            free(exec->flags->samAccountName);
        }
        if (exec->flags->samAccountName_nodollar) {
            free(exec->flags->samAccountName_nodollar);
        }
        exec->flags->samAccountName = (char *) malloc(strlen(samAccountName) + 2);
        if (!exec->flags->samAccountName) {
            fprintf(stderr, "Error: Out of memory\n");
            cleanup_exec(exec);
            exit(ENOMEM);
        }
        exec->flags->samAccountName_nodollar = (char *) malloc(strlen(samAccountName) + 1);
        if (!exec->flags->samAccountName_nodollar) {
            fprintf(stderr, "Error: Out of memory\n");
            cleanup_exec(exec);
            exit(ENOMEM);
        }
        memset(exec->flags->samAccountName, 0, strlen(samAccountName) + 2);
        sprintf(exec->flags->samAccountName, "%s$", samAccountName);
        memset(exec->flags->samAccountName_nodollar, 0, strlen(samAccountName) + 1);
        sprintf(exec->flags->samAccountName_nodollar, "%s", samAccountName);
    }
}


void set_userPrincipalName(msktutil_exec *exec, char *userPrincipalName)
{
    if (exec && exec->flags) {
        if (exec->flags->userPrincipalName) {
            free(exec->flags->userPrincipalName);
        }
        exec->flags->userPrincipalName = (char *) malloc(strlen(userPrincipalName) + 1);
        if (!exec->flags->userPrincipalName) {
            fprintf(stderr, "Error: Out of memory\n");
            cleanup_exec(exec);
            exit(ENOMEM);
        }
        memset(exec->flags->userPrincipalName, 0, strlen(userPrincipalName) + 1);
        strcpy(exec->flags->userPrincipalName, userPrincipalName);
    }
}


void set_desbit(msktutil_exec *exec, msktutil_val value)
{
    if (exec && exec->flags) {
        exec->flags->des_bit = value;
    }
}

void set_supportedEncryptionTypes(msktutil_exec *exec, char * value)
{
    if (exec && exec->flags) {
        exec->flags->enctypes = VALUE_ON;
        exec->flags->supportedEncryptionTypes = atoi(value);
    }
}


void set_no_pac(msktutil_exec *exec, msktutil_val value)
{
    if (exec && exec->flags) {
        exec->flags->no_pac = value;
    }
}


void set_delegate(msktutil_exec *exec, msktutil_val value)
{
    if (exec && exec->flags) {
        exec->flags->delegate = value;
    }
}


void flush_all(msktutil_exec *exec)
{
    if (exec && exec->flags) {
        exec->flush = 1;
    }
}


void update_all(msktutil_exec *exec)
{
    if (exec) {
        exec->update = 1;
    }
}


void do_verbose(msktutil_exec *exec)
{
    if (exec && exec->flags) {
        exec->flags->verbose++; /* allow for ldap debuging */
    }
}


void display_version(msktutil_exec *exec)
{
    if (exec) {
        exec->show_version = 1;
    }
}


void display_help(msktutil_exec *exec)
{
    if (exec) {
        exec->show_help = 1;
    }
}


void create_default(msktutil_exec *exec)
{
    int i = 0;

    if (exec && exec->flags) {
        if (exec->flags->hostname) {
            free(exec->flags->hostname);
            exec->flags->hostname = NULL;
        }
        if (exec->flags->keytab_file) {
            free(exec->flags->keytab_file);
            exec->flags->keytab_file = NULL;
        }
        if (exec->principals) {
            while (exec->principals[i]) {
                free(exec->principals[i++]);
            }
            free(exec->principals);
            exec->principals = NULL;
        }
        if (exec->flags->userPrincipalName) {
            free(exec->flags->userPrincipalName);
            exec->flags->userPrincipalName = NULL;
        }

        exec->show_help = 0;
        exec->flush = 0;
        exec->update = 1;
        exec->show_version = 0;
        exec->flags->hostname = get_default_hostname();
        if (get_default_keytab(exec->flags)) {
            fprintf(stderr, "Error: get_default_keytab failed\n");
            cleanup_exec(exec);
            exit(-1);
        }
        if (get_default_ou(exec->flags)) {
            fprintf(stderr, "Error: get_default_ou failed\n");
            cleanup_exec(exec);
            exit(-1);
        }
        exec->principals = NULL;
    }
}


msktutil_exec *init_exec()
{
    msktutil_exec *exec;


    exec = (msktutil_exec *) malloc(sizeof(msktutil_exec));
    if (!exec) {
        fprintf(stderr, "Error: Out of memory\n");
        exit(ENOMEM);
    }
    exec->flags = (msktutil_flags *) malloc(sizeof(msktutil_flags));
    if (!exec->flags) {
        fprintf(stderr, "Error: Out of memory\n");
        free(exec);
        exit(ENOMEM);
    }
    exec->show_help = 0;
    exec->show_version = 0;
    exec->flush = 0;
    exec->update = 0;
    exec->flags->verbose = 0;
    exec->flags->des_bit = VALUE_IGNORE;
    exec->flags->delegate = VALUE_IGNORE;
    exec->flags->no_pac = VALUE_IGNORE;
    exec->flags->hostname = NULL;
    exec->flags->keytab_file = NULL;
    exec->flags->ldap_ou = NULL;
    exec->flags->description = NULL;
    exec->flags->server = NULL;
    exec->principals = NULL;
    exec->flags->context = NULL;
    exec->flags->ldap = NULL;
    exec->flags->base_dn = NULL;
    exec->flags->short_hostname = NULL;
    exec->flags->realm_name = NULL;
    exec->flags->lower_realm_name = NULL;
    exec->flags->samAccountName = NULL;
    exec->flags->samAccountName_nodollar = NULL;
    exec->flags->userPrincipalName = NULL;
    exec->flags->ad_enctypes = VALUE_IGNORE;
    exec->flags->enctypes = VALUE_IGNORE;
    exec->flags->supportedEncryptionTypes = MS_KERB_ENCTYPE_DES_CBC_CRC|MS_KERB_ENCTYPE_DES_CBC_MD5|MS_KERB_ENCTYPE_RC4_HMAC_MD5; /* default values for w2000, w2003 */

    if (get_krb5_context(exec->flags)) {
        fprintf(stderr, "Error: get_krb5_context failed\n");
        cleanup_exec(exec);
        exit(-1);
    }

    /* Check for environment variables as well.  These variables will be overriden
     * By command line arguments. */
    if (getenv("MSKTUTIL_DESCRIPTION")) {
        set_description(exec, getenv("MSKTUTIL_DESCRIPTION"));
    }
    if (getenv("MSKTUTIL_KEYTAB")) {
        set_keytab_file(exec, getenv("MSKTUTIL_KEYTAB"));
    }
    if (getenv("MSKTUTIL_DES_ONLY")) {
        set_desbit(exec, VALUE_ON);
    }
    if (getenv("MSKTUTIL_NO_PAC")) {
        set_no_pac(exec, VALUE_ON);
    }
    if (getenv("MSKTUTIL_DELEGATION")) {
        set_delegate(exec, VALUE_ON);
    }
    if (getenv("MSKTUTIL_LDAP_BASE")) {
        set_ldap_ou(exec, getenv("MSKTUTIL_LDAP_BASE"));
    }
    if (getenv("MSKTUTIL_HOSTNAME")) {
        set_hostname(exec, getenv("MSKTUTIL_HOSTNAME"));
    }
    if (getenv("MSKTUTIL_SERVER")) {
        set_server(exec, getenv("MSKTUTIL_SERVER"));
    }
    if (getenv("MSKTUTIL_SAM_NAME")) {
        set_samAccountName(exec, getenv("MSKTUTIL_SAM_NAME"));
    }
    if (getenv("MSKTUTIL_UPN")) {
        set_userPrincipalName(exec, getenv("MSKTUTIL_UPN"));
    }

    return exec;
}


int finalize_exec(msktutil_exec *exec)
{
    char *temp_hostname;
    char *temp_upn;
    char *temp_principal;
    char *short_upn;
    int i;
    int j;
    int no_hostname;
    msktutil_flags *flags;


    if (exec && exec->flags) {
        flags = exec->flags;

        init_password(flags);
        if (krb5_get_default_realm(flags->context, &(flags->realm_name))) {
            fprintf(stderr, "Error: krb5_get_default_realm failed\n");
            cleanup_exec(exec);
            exit(-1);
        }
        flags->lower_realm_name = (char *) malloc(strlen(flags->realm_name) + 1);
        if (!(flags->lower_realm_name)) {
            fprintf(stderr, "Error: malloc failed\n");
            cleanup_exec(exec);
            exit(ENOMEM);
        }
        memset(flags->lower_realm_name, 0, strlen(flags->realm_name) + 1);
        for (i = 0; *(flags->realm_name + i); i++) {
            *(flags->lower_realm_name + i) = tolower(*(flags->realm_name + i));
        }

        if (get_dc(flags)) {
            fprintf(stderr, "Error: get_dc failed\n");
            cleanup_exec(exec);
            exit(-1);
        }
        if (get_default_keytab(flags)) {
            fprintf(stderr, "Error: get_default_keytab failed\n");
            cleanup_exec(exec);
            exit(-1);
        }

        /* Determine the userPrincipalName, if not set */
        VERBOSE("Determining user principal name");
        if (!(flags->userPrincipalName)) {
            flags->userPrincipalName = (char *) malloc(strlen(flags->hostname) + strlen(flags->realm_name) + 7);
            if (!(flags->userPrincipalName)) {
                fprintf(stderr, "Error: malloc failed\n");
                cleanup_exec(exec);
                exit(ENOMEM);
            }
            memset(flags->userPrincipalName, 0, strlen(flags->hostname) + strlen(flags->realm_name) + 7);
            sprintf(flags->userPrincipalName, "host/%s@%s", flags->hostname, flags->realm_name);
        } else {
            temp_upn = (char*)malloc(strlen(flags->userPrincipalName) + strlen(flags->realm_name) + 2);
            if (!temp_upn) {
                fprintf(stderr, "Error: malloc failed\n");
                cleanup_exec(exec);
                exit(ENOMEM);
            }
            memset(temp_upn, 0, strlen(flags->userPrincipalName) + strlen(flags->realm_name) + 2);
            sprintf(temp_upn, "%s@%s", flags->userPrincipalName, flags->realm_name);
            free(flags->userPrincipalName);
            flags->userPrincipalName = temp_upn;
        }
        VERBOSE("User Principal Name is: %s", flags->userPrincipalName);

        signal(SIGINT, catch_int);
        if (create_fake_krb5_conf(flags)) {
            fprintf(stderr, "Error: create_fake_krb5_conf failed\n");
            cleanup_exec(exec);
            exit(-1);
        }
        if (try_machine_keytab(flags)) {
            untry_machine_keytab();
        }

        if (ldap_connect(flags)) {
            fprintf(stderr, "Error: ldap_connect failed\n");
            cleanup_exec(exec);
            exit(-1);
        }
        if (ldap_get_base_dn(flags)) {
            fprintf(stderr, "Error: get_ldap_base_dn failed\n");
            cleanup_exec(exec);
            exit(-1);
        }
        if (get_default_ou(flags)) {
            fprintf(stderr, "Error: get_default_ou failed\n");
            cleanup_exec(exec);
            exit(-1);
        }

        /* Canonicalize the hostname if need be */
        temp_hostname = complete_hostname(flags->hostname);
        if (!temp_hostname) {
            fprintf(stderr, "Error: complete_hostname failed\n");
            return -1;
        }
        set_hostname(exec, temp_hostname);

        flags->short_hostname = get_short_hostname(flags);
        if (!(flags->short_hostname)) {
            fprintf(stderr, "Error: get_short_hostname failed\n");
            return -1;
        }

        /* Determine the samAccountName, if not set */
        if (!(flags->samAccountName)) {
            set_samAccountName(exec, flags->short_hostname);
        }
        /* The samAccountName will cause win 9x, NT problems if longer than MAX_SAM_ACCOUNT_LEN characters */
        if (strlen(flags->samAccountName) > MAX_SAM_ACCOUNT_LEN) {
            fprintf(stderr, "Error: The SAM name (%s) for this host is longer than the maximum of MAX_SAM_ACCOUNT_LEN characters\n",
                flags->samAccountName);
            fprintf(stderr, "You can specify a shorter name using --computer-name\n");
            cleanup_exec(exec);
            exit(-1);
        }
        VERBOSE("SAM Account Name is: %s", flags->samAccountName);
    }

    /* Qualify all remaining entries in the principals list */
    i  = 0;
    if (exec->principals) {
        while (exec->principals[i]) {
            no_hostname = 1;
            for (j = 0; *(exec->principals[i] + j); j++) {
                if (*(exec->principals[i] + j) == '/') {
                    no_hostname = 0;
                }
            }
            if (no_hostname) {
                temp_principal = (char *) malloc(strlen(exec->principals[i]) + strlen(flags->hostname) + 2);
                if (!temp_principal) {
                    fprintf(stderr, "Error: malloc failed\n");
                    cleanup_exec(exec);
                    exit(ENOMEM);
                }
                memset(temp_principal, 0, strlen(exec->principals[i]) + strlen(flags->hostname) + 2);
                sprintf(temp_principal, "%s/%s", exec->principals[i], flags->hostname);
                free(exec->principals[i]);
                exec->principals[i] = temp_principal;
            }
            i++;
        }
    }

    /* Add the UPN to the list of principals as well, but do this after we qualify the list of
     * service principals.  We don't want something like afs@REALM getting converted into
     * afs/hostname@REALM */
    short_upn = (char *) malloc(strlen(flags->userPrincipalName) + 1);
    if (!short_upn) {
        fprintf(stderr, "Error: malloc failed\n");
        cleanup_exec(exec);
        exit(ENOMEM);
    }
    memset(short_upn, 0, strlen(flags->userPrincipalName) + 1);
    for (i = 0; *(flags->userPrincipalName + i) && *(flags->userPrincipalName + i) != '@'; i++) {
        *(short_upn + i) = *(flags->userPrincipalName + i);
    }
    add_spn(exec, short_upn);
    free(short_upn);

    return 0;
}


int execute(msktutil_exec *exec)
{
    int i;
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

            cleanup_exec(exec);
            return 0;
        }

        if (exec->show_version) {
            fprintf(stdout, "%s version %s\n", PACKAGE_NAME, PACKAGE_VERSION);
            cleanup_exec(exec);
            return 0;
        }

        if (exec->flush || exec->update || exec->principals || flags->userPrincipalName) {
            if (!flags->hostname) {
                fprintf(stderr, "Error: No hostname specified.\n");
                fprintf(stderr, "       Please specify a hostname using '-h'.\n");
                cleanup_exec(exec);
                return -2;
            }
            ret = finalize_exec(exec);
            if (ret) {
                fprintf(stderr, "Error: finalize_exec failed\n");
                cleanup_exec(exec);
                exit(ret);
            }
        }

        if (exec->flush) {
            fprintf(stdout, "Flushing all entries for %s from the keytab %s\n", flags->hostname,
                flags->keytab_file);
            ret = flush_keytab(flags);
            cleanup_exec(exec);
            return ret;
        }

        if (exec->update) {
            fprintf(stdout, "Updating all entries for %s in the keytab %s\n", flags->hostname,
                flags->keytab_file);
            ret = update_keytab(flags);
            cleanup_exec(exec);
            return ret;
        }

        if (exec->principals) {
            if (!exec->update) {
                /* Adding a principal will cause the machine account password to be reset - we don't
                 * store the current password anywhere - so we need to update any other principals
                 * the machine has before adding new ones. */
                ret = update_keytab(flags);
                if (ret) {
                    VERBOSE("update_keytab failed, trying using user credentials");
                    untry_machine_keytab();
                    ret = update_keytab(flags);
                    if (ret) {
                        fprintf(stderr, "Error: update_keytab failed\n");
                        cleanup_exec(exec);
                        return ret;
                    }
                }
            }

            i = 0;
            while (exec->principals[i]) {
                fprintf(stdout, "Adding principal %s to the keytab %s\n", exec->principals[i], flags->keytab_file);
                ret |= add_principal(exec->principals[i], flags);
                i++;
            }
            cleanup_exec(exec);
            return ret;
        }

        /* Default, no options present */
        fprintf(stderr, "Error: No command given\n");
        fprintf(stderr, "\nFor help, try running %s --help\n\n", PACKAGE_NAME);

        cleanup_exec(exec);
        return 0;
    }
    cleanup_exec(exec);
    return -1;
}


int main(int argc, char *argv [])
{
    int i;
    msktutil_exec *exec;

    exec = init_exec();

    for (i = 1; i < argc; i++) {

        /* Service Principal Name */
        if (!strcmp(argv[i], "--service") || !strcmp(argv[i], "-s")) {
            if (++i < argc) {
                add_spn(exec, argv[i]);
            } else {
                fprintf(stderr, "Error: No service principal given after '%s'\n", argv[i - 1]);
                goto error;
            }
            continue;
        }

        /* Host name */
        if (!strcmp(argv[i], "--host") || !strcmp(argv[i], "--hostname") || !strcmp(argv[i], "-h")) {
            if (++i < argc) {
                set_hostname(exec, argv[i]);
            } else {
                fprintf(stderr, "Error: No name given after '%s'\n", argv[i - 1]);
                goto error;
            }
            continue;
        }

        /* W2008 msDs-supportedEncryptionTypes */
        if (!strcmp(argv[i], "--enctypes")) {
            if (++i < argc) {
                set_supportedEncryptionTypes(exec, argv[i]);
            } else {
                fprintf(stderr, "Error: No enctype after '%s'\n", argv[i - 1]);
                goto error;
            }
            continue;
        }

        /* DES-Only Bit enabled ? */
        if (!strcmp(argv[i], "--des-only") || !strcmp(argv[i], "-d")) {
            set_desbit(exec, VALUE_ON);
            continue;
        }
        if (!strcmp(argv[i], "--disable-des-only")) {
            set_desbit(exec, VALUE_OFF);
            continue;
        }

        /* Disable the PAC ? */
        if (!strcmp(argv[i], "--no-pac")) {
            set_no_pac(exec, VALUE_ON);
            continue;
        }
        if (!strcmp(argv[i], "--disable-no-pac")) {
            set_no_pac(exec, VALUE_OFF);
            continue;
        }

        /* Trust for delegation ? */
        if (!strcmp(argv[i], "--delegation")) {
            set_delegate(exec, VALUE_ON);
            continue;
        }
        if (!strcmp(argv[i], "--disable-delegation")) {
            set_delegate(exec, VALUE_OFF);
            continue;
        }

        /* Flush the keytab */
        if (!strcmp(argv[i], "--flush") || !strcmp(argv[i], "-f")) {
            flush_all(exec);
            continue;
        }

        /* Use a certain sam account name */
        if (!strcmp(argv[i], "--computer-name")) {
            if (++i < argc) {
                set_samAccountName(exec, argv[i]);
            } else {
                fprintf(stderr, "Error: No name given after '%s'\n", argv[i - 1]);
                goto error;
            }
            continue;
        }

        /* Use a certain user principal name */
        if (!strcmp(argv[i], "--upn")) {
            if (++i < argc) {
                set_userPrincipalName(exec, argv[i]);
            } else {
                fprintf(stderr, "Error: No principal given after '%s'\n", argv[i - 1]);
                goto error;
            }
            continue;
        }

        /* Use certain keytab file */
        if (!strcmp(argv[i], "--keytab") || !strcmp(argv[i], "-k")) {
            if (++i < argc) {
                set_keytab_file(exec, argv[i]);
            } else {
                fprintf(stderr, "Error: No file given after '%s'\n", argv[i - 1]);
                goto error;
            }
            continue;
        }

        /* Use a certain LDAP base OU ? */
        if (!strcmp(argv[i], "--base") || !strcmp(argv[i], "-b")) {
            if (++i < argc) {
                set_ldap_ou(exec, argv[i]);
            } else {
                fprintf(stderr, "Error: No base given after '%s'\n", argv[i - 1]);
                goto error;
            }
            continue;
        }

        /* Set the description on the computer account */
        if (!strcmp(argv[i], "--description")) {
            if (++i < argc) {
                set_description(exec, argv[i]);
            } else {
                fprintf(stderr, "Error: No description given after '%s'\n", argv[i - 1]);
                goto error;
            }
            continue;
        }

        /* Use a certain LDAP server */
        if (!strcmp(argv[i], "--server")) {
            if (++i < argc) {
                set_server(exec, argv[i]);
            } else {
                fprintf(stderr, "Error: No server given after '%s'\n", argv[i - 1]);
                goto error;
            }
            continue;
        }

        /* Update All Principals */
        if (!strcmp(argv[i], "--update") || !strcmp(argv[i], "-u")) {
            update_all(exec);
            continue;
        }

        /* Create 'Default' Keytab */
        if (!strcmp(argv[i], "--create") || !strcmp(argv[i], "--createdefault") ||
            !strcmp(argv[i], "-c")) {
            create_default(exec);
            continue;
        }

        /* Display Version Message */
        if (!strcmp(argv[i], "-v") || !strcmp(argv[i], "--version")) {
            display_version(exec);
            continue;
        }

        /* Display Verbose Messages */
        if (!strcmp(argv[i], "--verbose")) {
            do_verbose(exec);
            continue;
        }

        /* Display Help Messages */
        if (!strcmp(argv[i], "--help") || !strcmp(argv[i], "--?") ||
            !strcmp(argv[i], "-?") || !strcmp(argv[i], "--usage")) {
            display_help(exec);
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

    return execute(exec);

error:
    fprintf(stderr, "\nFor help, try running %s --help\n\n", PACKAGE_NAME);
    cleanup_exec(exec);
    return -1;
}
