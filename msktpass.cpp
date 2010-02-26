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


int set_password(msktutil_flags *flags, int time)
{
    int ret;
    krb5_data resp_code_string;
    krb5_data resp_string;
    int response = 0;
    std::string old_pwdLastSet;
    std::string current_pwdLastSet;


    // Zero out these data structures, because we attempt to free them below, and sometimes, upon
    // error conditions, the called API hasn't set them itself.
    resp_string.data = NULL;
    resp_string.length = 0;
    resp_code_string.data = NULL;
    resp_code_string.length = 0;


    VERBOSE("Attempting to reset computer's password");
    if (flags->auth_type == AUTH_FROM_USER_CREDS) {
        VERBOSE("Try change password using user's ticket cache\n");

        KRB5CCache ccache(KRB5CCache::defaultName());
        KRB5Principal principal(flags->samAccountName);

        old_pwdLastSet = ldap_get_pwdLastSet(flags);
        ret = krb5_set_password_using_ccache(g_context.get(), ccache.get(),
                                             const_cast<char*>(flags->password.c_str()),
                                             principal.get(), &response, &resp_code_string, &resp_string);
        krb5_free_data_contents(g_context.get(), &resp_string);

        if (!ret && response) {
            fprintf(stderr, "Error: Unable to set machine password for %s: (%d) %s\n",
                    flags->samAccountName.c_str(), response, (char *) resp_code_string.data);
            krb5_free_data_contents(g_context.get(), &resp_code_string);
            return response;
        }
        krb5_free_data_contents(g_context.get(), &resp_code_string);
        if (ret) {
            fprintf(stderr, "Error: krb5_set_password_using_ccache failed (%s)\n", error_message(ret));
            return ret;
        }
    } else {
        KRB5Creds creds;
        /* Use the machine's credentials */
        if (flags->auth_type == AUTH_FROM_SAM_KEYTAB ||
            flags->auth_type == AUTH_FROM_HOSTNAME_KEYTAB) {
            std::string princ_name;
            if (flags->auth_type == AUTH_FROM_SAM_KEYTAB)
                princ_name = "host/" + flags->hostname;
            else
                princ_name = flags->samAccountName;
            VERBOSE("Try using keytab for %s to change password\n", princ_name.c_str());

            KRB5Keytab keytab(flags->keytab_readname);
            KRB5Principal principal(flags->samAccountName);
            KRB5Creds local_creds(principal, keytab, "kadmin/changepw");
            creds.move_from(local_creds);
        } else if (flags->auth_type == AUTH_FROM_PASSWORD) {
            VERBOSE("Try using default password for %s to change password\n", flags->samAccountName.c_str());

            KRB5Principal principal(flags->samAccountName);
            KRB5Creds local_creds(principal, flags->samAccountName_nodollar, "kadmin/changepw");
            creds.move_from(local_creds);
        } else // shouldn't happen
            throw Exception("Error: unknown auth_type.");


        old_pwdLastSet = ldap_get_pwdLastSet(flags);
        ret = krb5_change_password(g_context.get(), creds.get(), const_cast<char*>(flags->password.c_str()),
                                   &response, &resp_code_string, &resp_string);
        krb5_free_data_contents(g_context.get(), &resp_string);

        if (response) {
            VERBOSE("krb5_change_password failed using keytab: (%d) %s", response, (char *) resp_code_string.data);
            krb5_free_data_contents(g_context.get(), &resp_code_string);
            return ret;
        }
        krb5_free_data_contents(g_context.get(), &resp_code_string);
        if (ret) {
            fprintf(stderr, "Error: krb5_change_password failed (%s)\n", error_message(ret));
            return ret;
        }

    }

    VERBOSE("Successfully set password, waiting for it to be reflected in LDAP.");

    /* Loop and wait for the account and password set to replicate */
    for (int this_time = 0; ; this_time += 5) {
        current_pwdLastSet = ldap_get_pwdLastSet(flags);
        if (time + this_time >= 60) {
            fprintf(stdout, "Password reset failed.\n");
            return 1;
        }
        if (this_time >= 30) {
            fprintf(stdout, "Re-attempting password reset for %s\n", flags->samAccountName.c_str());
            return set_password(flags);
        }
        if (current_pwdLastSet.empty()) {
            /* Account hasn't replicated yet */
            fprintf(stdout, "Waiting for account replication (%d seconds past)\n", time + this_time);
            sleep(5);
        } else {
            /* The account exists: we're waiting for the value to
             * change, indicating the password set worked */
            if (current_pwdLastSet != old_pwdLastSet) {
                /* Password set has replicated successfully */
                VERBOSE("Successfully reset computer's password");
                return 0;
            }
            fprintf(stdout, "Waiting for password replication (%d seconds past)\n", time + this_time);
            sleep(5);
        }
    }
}
