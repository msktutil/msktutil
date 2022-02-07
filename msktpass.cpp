/*
 *----------------------------------------------------------------------------
 *
 * msktpass.cpp
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


void init_password(msktutil_flags *flags)
{
    if (flags->use_service_account) {
        VERBOSE("Wiping the password structure");
    } else {
        VERBOSE("Wiping the computer password structure");
    }
    std::fill(flags->password.begin(), flags->password.end(), '\0');
}


int generate_new_password(msktutil_flags *flags)
{
    int i;
    int curr;
    int have_lower = 0;
    int have_upper = 0;
    int have_symbol = 0;
    int have_number = 0;
    int chars_used = 0;
    FILE *fp;


    init_password(flags);
    flags->password.resize(PASSWORD_LEN);

    fp = fopen("/dev/urandom", "r");
    if (!fp) {
        error_exit( "failed to open /dev/urandom");
    }

    if (flags->use_service_account) {
        VERBOSE("Generating a new, random password for the service account");
    } else {
        VERBOSE("Generating a new, random password for the computer account");
    }
    while (!(have_symbol && have_number && have_lower && have_upper)) {
        have_symbol = 0;
        have_number = 0;
        have_upper = 0;
        have_lower = 0;
        for (i = 0; i < PASSWORD_LEN; i++) {
            curr = 0;
            while (curr < 33 || curr > 126) {
                if ((curr = getc(fp)) == EOF) {
                    error_exit("Failed to read from /dev/urandom");
                }
                curr &= 0x7f;
                chars_used++;
            }
            have_symbol |= (curr >= 33 && curr <= 47);
            have_symbol |= (curr >= 91 && curr <= 96);
            have_symbol |= (curr >= 123 && curr <= 126);
            have_symbol |= (curr >= 58 && curr <= 64);
            have_number |= (curr >= 48 && curr <= 57);
            have_upper |= (curr >= 65 && curr <= 90);
            have_lower |= (curr >= 97 && curr <= 122);
            flags->password[i] = (char) curr;
        }
    }
    fclose(fp);
    VERBOSE("Characters read from /dev/urandom: %d", chars_used);
    return 0;
}


/* Try to set the the new Samba secret to <flags->password>. */
static int set_samba_secret(msktutil_flags *flags)
{
    VERBOSE("Setting samba machine trust account password using command: %s",
            flags->samba_cmd.c_str());

    FILE *pipe;
    pipe = popen(flags->samba_cmd.c_str(), "w");

    if (pipe == NULL) {
        fprintf(stdout,
                "Could not execute command: %s\n",
                flags->samba_cmd.c_str()
            );
        return 1;
    }

    size_t len = flags->password.length();
    if (fwrite(flags->password.c_str(), sizeof(char), len, pipe) != len) {
        fprintf(stdout,
                "Write error passing password to command: %s\n",
                flags->samba_cmd.c_str()
            );
        return 1;
    }

    int rc = pclose(pipe);
    if (rc != 0) {
        fprintf(stderr,
                "WARNING: Setting samba secret failed with error code %d\n",
                rc
            );
        return 1;
    }

    VERBOSE("Successfully set samba machine trust account password");

    return 0;
}


int set_password(msktutil_flags *flags)
{
    int ret;
    krb5_data resp_code_string;
    krb5_data resp_string;
    int response = 0;

    /* Zero out these data structures, because we attempt to free them
     * below, and sometimes, upon error conditions, the called API
     * hasn't set them itself. */
    resp_string.data = NULL;
    resp_string.length = 0;
    resp_code_string.data = NULL;
    resp_code_string.length = 0;

    if (flags->use_service_account) {
        VERBOSE("Attempting to reset service account's password");
    } else {
        VERBOSE("Attempting to reset computer's password");
    }
    if (flags->auth_type == AUTH_FROM_USER_CREDS) {
        VERBOSE("Try change password using user's ticket cache");

        KRB5CCache ccache(KRB5CCache::defaultName());
        KRB5Principal principal(flags->sAMAccountName);

        ret = krb5_set_password_using_ccache(g_context,
                                             ccache.get(),
                                             const_cast<char*>(flags->password.c_str()),
                                             principal.get(),
                                             &response,
                                             &resp_code_string,
                                             &resp_string);
        krb5_free_data_contents(g_context, &resp_string);

        if (!ret && response) {
            fprintf(stderr,
                    "Error: Unable to set machine password for %s: (%d) %s\n",
                    flags->sAMAccountName.c_str(),
                    response,
                    (char *) resp_code_string.data);
            krb5_free_data_contents(g_context, &resp_code_string);
            return response;
        }
        krb5_free_data_contents(g_context, &resp_code_string);
        if (ret) {
            if (!response && ret == KRB5KRB_AP_ERR_BADADDR) {
                VERBOSE("krb5_set_password_using_ccache: password changed "
                        "successfully, but sender IP in KRB-PRIV failed "
                        "validation");
                if (!flags->server_behind_nat) {
                    fprintf(stderr,
                            "Error: krb5_set_password_using_ccache "
                            "failed: %s\n",
                            error_message(ret)
                        );
                    return ret;
                }
            } else {
                fprintf(stderr,
                        "Error: krb5_set_password_using_ccache failed: %s\n",
                        error_message(ret)
                    );
                return ret;
            }
        }
    } else {
        KRB5Creds creds;
        /* Use the machine's credentials */
        if (flags->auth_type == AUTH_FROM_SAM_KEYTAB ||
            flags->auth_type == AUTH_FROM_SAM_UPPERCASE_KEYTAB ||
            flags->auth_type == AUTH_FROM_EXPLICIT_KEYTAB ||
            flags->auth_type == AUTH_FROM_HOSTNAME_KEYTAB) {
            std::string princ_name;
            if (flags->auth_type == AUTH_FROM_SAM_KEYTAB) {
                princ_name = flags->sAMAccountName;
            } else if (flags->auth_type == AUTH_FROM_SAM_UPPERCASE_KEYTAB) {
                princ_name = flags->sAMAccountName_uppercase;
            } else if (flags->auth_type == AUTH_FROM_EXPLICIT_KEYTAB) {
                princ_name = flags->keytab_auth_princ;
            } else {
                princ_name = "host/" + flags->hostname;
            }
            VERBOSE("Trying to use keytab for %s to change password",
                    princ_name.c_str());

            KRB5Keytab keytab(flags->keytab_readname);
            KRB5Principal principal(princ_name);
            KRB5Creds local_creds(principal, keytab, "kadmin/changepw");
            creds.move_from(local_creds);
        } else if (flags->auth_type == AUTH_FROM_PASSWORD) {
            VERBOSE("Trying to use default password for %s to change password",
                    flags->sAMAccountName.c_str());

            KRB5Principal principal(flags->sAMAccountName);
            KRB5Creds local_creds(principal,
                                  create_default_machine_password(
                                      flags->sAMAccountName),
                                  "kadmin/changepw");
            creds.move_from(local_creds);
        } else if ((flags->auth_type == AUTH_FROM_SUPPLIED_PASSWORD) ||
                   (flags->auth_type == AUTH_FROM_SUPPLIED_EXPIRED_PASSWORD)) {
            VERBOSE("Trying to use supplied password for %s to change password",
                    flags->sAMAccountName.c_str());
            KRB5Principal principal(flags->sAMAccountName);
            KRB5Creds local_creds(principal,
                                  flags->old_account_password,
                                  "kadmin/changepw");
            creds.move_from(local_creds);
        } else /* shouldn't happen */
            throw Exception("Error: unknown auth_type");

        ret = krb5_change_password(g_context,
                                   creds.get(),
                                   const_cast<char*>(flags->password.c_str()),
                                   &response,
                                   &resp_code_string,
                                   &resp_string);
        krb5_free_data_contents(g_context, &resp_string);

        if (response) {
            VERBOSE("krb5_change_password failed using keytab: (%d) %s",
                    response,
                    (char *) resp_code_string.data);
            krb5_free_data_contents(g_context, &resp_code_string);
            return response;
        }
        krb5_free_data_contents(g_context, &resp_code_string);
        if (ret) {
            if (!response && ret == KRB5KRB_AP_ERR_BADADDR) {
                VERBOSE("krb5_change_password: password changed "
                        "successfully, but sender IP in KRB-PRIV "
                        "failed validation");
                if (!flags->server_behind_nat) {
                    fprintf(stderr,
                            "Error: krb5_change_password failed: %s\n",
                            error_message(ret)
                        );
                    return ret;
                }
            } else {
                fprintf(stderr,
                        "Error: krb5_change_password failed: %s\n",
                        error_message(ret)
                    );
                return ret;
            }
        }
    }

    VERBOSE("Successfully set password");

    if (flags->set_samba_secret) {
        /* At this point, we've already set the new password in AD, and there's
         * no way to roll back for us because we don't know the old password.
         * Therefore, even if we fail to propagate the new password to Samba,
         * we still need to carry on, and write out the new keys to the keytab.
         * Failing here is not an option, so ignore the return value from
         * set_samba_secret(), and proceed normally. (The function has already
         * notified on stderr if a failure had occurred.)
         */
        (void) set_samba_secret(flags);
    }

    return 0;
}
