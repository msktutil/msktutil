/*
 *----------------------------------------------------------------------------
 *
 * msktpass.c
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


void init_password(msktutil_flags *flags)
{
    VERBOSE("Wiping the computer password structure");
    std::fill(flags->password.begin(), flags->password.end(), '\0');
}


int generate_new_password(msktutil_flags *flags)
{
    int i;
    char curr;
    int have_lower = 0;
    int have_upper = 0;
    int have_symbol = 0;
    int have_number = 0;
    int fd;
    int chars_used = 0;


    init_password(flags);
    flags->password.resize(PASSWORD_LEN);

    fd = open("/dev/urandom",O_RDONLY);
    if (fd < 0) {
        fprintf(stderr,"ERROR: failed to open /dev/urandom\n");
        return -1;
    }

    VERBOSE("Generating a new, random password for the computer account");
    while (!(have_symbol && have_number && have_lower && have_upper)) {
        have_symbol = 0;
        have_number = 0;
        have_upper = 0;
        have_lower = 0;
        for (i = 0; i < PASSWORD_LEN; i++) {
            curr = 0;
            while (curr < (char) 33 || curr > (char) 126) {
                read(fd, &curr, 1);
                curr &= 0x7f;
                chars_used++;
            }
            have_symbol |= (curr >= (char) 33 && curr <= (char) 47);
            have_symbol |= (curr >= (char) 91 && curr <= (char) 96);
            have_symbol |= (curr >= (char) 123 && curr <= (char) 126);
            have_symbol |= (curr >= (char) 58 && curr <= (char) 64);
            have_number |= (curr >= (char) 48 && curr <= (char) 57);
            have_upper |= (curr >= (char) 65 && curr <= (char) 90);
            have_lower |= (curr >= (char) 97 && curr <= (char) 122);
            flags->password[i] = curr;
        }
    }
    close(fd);
    VERBOSE(" Characters read from /dev/udandom = %d",chars_used);
    return 0;
}


int try_set_password(msktutil_flags *flags, int time, int try_keytab)
{
    int ret;
    krb5_ccache ccache;
    krb5_keytab keytab;
    krb5_creds creds;
    krb5_principal principal;
    krb5_data resp_code_string;
    krb5_data resp_string;
    int response = 0;
    char *old_pwdLastSet;
    char *current_pwdLastSet;
    int i;


    VERBOSE("Attempting to reset computer's password");
    ret = ldap_check_account(flags);
    if (ret) {
        fprintf(stderr, "Error: ldap_check_account failed (%s)\n", error_message(ret));
        return ret;
    }
    ret = generate_new_password(flags);
    if (ret) {
        fprintf(stderr, "Error: generate_new_password failed\n");
        return ret;
    }

    if (try_keytab) {   /* Try and use the keytab */
        VERBOSE("Try using keytab to change password\n");

        ret = krb5_kt_resolve(g_context.get(), flags->keytab_file.c_str(), &keytab);
        if (ret) {
            VERBOSE("krb5_kt_resolve failed (%s)", error_message(ret));
            untry_machine_keytab();
            return try_set_password(flags, time, 0);
        }
        ret = krb5_parse_name(g_context.get(), flags->userPrincipalName.c_str(), &principal);
        if (ret) {
            VERBOSE("krb5_parse_name failed (%s)", error_message(ret));
            krb5_kt_close(g_context.get(), keytab);
            untry_machine_keytab();
            return try_set_password(flags, time, 0);
        }
        ret = krb5_get_init_creds_keytab(g_context.get(), &creds, principal, keytab, 0, NULL, NULL);
        krb5_free_principal(g_context.get(), principal);
        krb5_kt_close(g_context.get(), keytab);
        if (ret) {
            VERBOSE("krb5_get_init_creds_keytab failed (%s)", error_message(ret));
            untry_machine_keytab();
            return try_set_password(flags, time, 0);
        }
        old_pwdLastSet = ldap_get_pwdLastSet(flags);
        ret = krb5_change_password(g_context.get(), &creds, const_cast<char*>(flags->password.c_str()),
                                   &response, &resp_code_string, &resp_string);
        krb5_free_data_contents(g_context.get(), &resp_string);
        krb5_free_cred_contents(g_context.get(), &creds);
        if (response) {
            VERBOSE("krb5_change_password failed using keytab: (%d) %s", response, (char *) resp_code_string.data);
            krb5_free_data_contents(g_context.get(), &resp_code_string);
            untry_machine_keytab();
            return try_set_password(flags, time, 0);
        }
        krb5_free_data_contents(g_context.get(), &resp_code_string);
        if (ret) {
            fprintf(stderr, "Error: krb5_change_password failed (%s)\n", error_message(ret));
            untry_machine_keytab();
            return try_set_password(flags, time, 0);
        }

    } else {        /* Use the default ticket cache */

        VERBOSE("Try change password using ticket cache\n");
        ret = krb5_cc_default(g_context.get(), &ccache);
        if (ret) {
            fprintf(stderr, "Error: krb5_cc_default failed (%s)\n", error_message(ret));
            fprintf(stderr, "Do you have a valid kerberos ticket?\n");
            return ret;
        }

#if 1
    /*
     * W2008 is using the userPrincipalName for smartcards,
     * but will also check the samAccountName (nodollar) or the cn
     * So we construct a alternative name
     * This is a bug in W2008, fixed by hotfix KB 951191
     * W2003 did not do this, and the old code would fail with a
     * response = 3, Authentication error
     */
        ret = krb5_parse_name(g_context.get(), flags->samAccountName_nodollar.c_str(), &principal);
#else
        ret = krb5_parse_name(g_context.get(), flags->userPrincipalName.c_str(), &principal);
#endif
        if (ret) {
            fprintf(stderr, "Error: krb5_parse_name failed (%s)\n", error_message(ret));
            krb5_cc_close(g_context.get(), ccache);
            return ret;
        }

        old_pwdLastSet = ldap_get_pwdLastSet(flags);
        ret = krb5_set_password_using_ccache(g_context.get(), ccache,
                                             const_cast<char*>(flags->password.c_str()),
                                             principal, &response, &resp_code_string, &resp_string);
        krb5_free_data_contents(g_context.get(), &resp_string);
        krb5_cc_close(g_context.get(), ccache);
        krb5_free_principal(g_context.get(), principal);
        if (!ret && response) {
            fprintf(stderr, "Error: Unable to set machine password for %s: (%d) %s\n",
                    flags->short_hostname.c_str(), response, (char *) resp_code_string.data);
            krb5_free_data_contents(g_context.get(), &resp_code_string);
            return response;
        }
        krb5_free_data_contents(g_context.get(), &resp_code_string);
        if (ret) {
            fprintf(stderr, "Error: krb5_set_password_using_ccache failed (%s)\n", error_message(ret));
            return ret;
        }
    }

    /* Loop and wait for the account and password set to replicate */
    for (i = time; ; i += 5) {
        current_pwdLastSet = ldap_get_pwdLastSet(flags);
        if (i >= 30 + time) {
            fprintf(stdout, "Re-attempting password reset for %s\n", flags->hostname.c_str());
            init_password(flags);
            if (current_pwdLastSet) { free(current_pwdLastSet); }
            if (old_pwdLastSet) { free(old_pwdLastSet); }
            return try_set_password(flags, i, try_keytab);
        }
        if (!current_pwdLastSet) {
            /* Account hasn't replicated yet */
            fprintf(stdout, "Waiting for account replication (%d seconds past)\n", i);
                        sleep(5);
        } else {
            /* The account exists, the domain supports kvno's and we're waiting for
             * the kvno to increment, indicating the password set worked */
            if (!old_pwdLastSet || strcmp(current_pwdLastSet,old_pwdLastSet)) {
                /* Password set has replicated successfully */
                VERBOSE("Successfully reset computer's password");
                if (current_pwdLastSet) { free(current_pwdLastSet); }
                if (old_pwdLastSet) { free(old_pwdLastSet); }
                return 0;
            }
            fprintf(stdout, "Waiting for password replication (%d seconds past)\n", i);
            sleep(5);
        }
        if (current_pwdLastSet) { free(current_pwdLastSet); }
    }
}


int set_password(msktutil_flags *flags)
{
    /* Only reset the password once... */
    if (flags->password[0] != '\0') {
        return 0;
    }
    return try_set_password(flags, 0, 1);
}
