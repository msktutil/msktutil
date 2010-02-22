/*
 *----------------------------------------------------------------------------
 *
 * msktkrb5.c
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


#ifdef HEIMDAL
krb5_error_code krb5_free_unparsed_name(krb5_context context, void *buffer)
{
    if (buffer) {
        free(buffer);
    }
    return 0;
}


krb5_error_code krb5_free_keytab_entry_contents(krb5_context context, krb5_keytab_entry *entry)
{
    if (entry) {
        krb5_free_principal(context, entry->principal);
        if (entry->keyblock.keyvalue.data) {
            memset(entry->keyblock.keyvalue.data, 0, entry->keyblock.keyvalue.length);
            free(entry->keyblock.keyvalue.data);
        }
        return 0;
    }
    return -1;
}
#endif


int get_krb5_context(msktutil_flags *flags)
{
    int ret;


    VERBOSE("Creating Kerberos Context");
    ret = krb5_init_context(&(flags->context));
    if (ret) {
        fprintf(stderr, "Error: krb5_init_context failed (%s)\n", error_message(ret));
    }
    return ret;
}


void krb5_cleanup(msktutil_flags *flags)
{
    VERBOSE("Destroying Kerberos Context");
    if (flags->context) {
        krb5_free_context(flags->context);
        flags->context = NULL;
    }
}


char *get_user_principal(msktutil_flags *flags)
{
    int ret;
    char *user = NULL;
    char *principal_string;
    krb5_ccache ccache;
    krb5_principal principal;


    VERBOSE("Obtaining Principal for the executing user");
    ret = krb5_cc_default(flags->context, &ccache);
    if (ret) {
        VERBOSE("krb5_cc_default failed (%s)", error_message(ret));
        return NULL;
    }
    ret = krb5_cc_get_principal(flags->context, ccache, &principal);
    krb5_cc_close(flags->context, ccache);
    if (ret) {
        VERBOSE("krb5_cc_get_principal failed (%s)", error_message(ret));
        return NULL;
    }
    ret = krb5_unparse_name(flags->context, principal, &principal_string);
    krb5_free_principal(flags->context, principal);
    if (ret) {
        fprintf(stderr, "Error: krb5_unparse_name failed (%s)\n", error_message(ret));
        return NULL;
    }
    user = (char *) malloc(strlen(principal_string) + 1);
    if (!user) {
        fprintf(stderr, "Error: malloc failed\n");
        krb5_free_unparsed_name(flags->context, principal_string);
        return NULL;
    }
    memset(user, 0, strlen(principal_string) + 1);
    sprintf(user, "%s", principal_string);
    krb5_free_unparsed_name(flags->context, principal_string);

    return user;
}


int get_default_keytab(msktutil_flags *flags)
{
    char keytab_name[MAX_KEYTAB_NAME_LEN];
    int ret;


    if (!flags->keytab_file) {
        /* Only set the field to a default if it's empty */
        ret = krb5_kt_default_name(flags->context, (char *) &keytab_name, MAX_KEYTAB_NAME_LEN);
        if (ret) {
            fprintf(stderr, "Error: krb5_kt_default_name failed (%s)\n", error_message(ret));
            free(keytab_name);
            return ret;
        }
        flags->keytab_file = (char *) malloc(MAX_KEYTAB_NAME_LEN + 1);
        if (!(flags->keytab_file)) {
            fprintf(stderr, "Error: malloc failed\n");
            free(keytab_name);
            return ENOMEM;
        }
        memset(flags->keytab_file, 0, MAX_KEYTAB_NAME_LEN + 1);

        if (!strncmp(keytab_name, "FILE:", 5)) {
            /* Ignore the opening FILE: part */
            strcpy(flags->keytab_file, keytab_name + 5);
        } else {
            if (!strncmp(keytab_name, "WRFILE:", 7)) {
                /* Ignore the opening WRFILE: part */
                strcpy(flags->keytab_file, keytab_name + 7);
            } else {
                /* No prefix to the keytab path */
                strcpy(flags->keytab_file, keytab_name);
            }
        }
        VERBOSE("Obtaining the default keytab name: %s", flags->keytab_file);
    }
    return 0;
}


int flush_keytab(msktutil_flags *flags)
{
    int ret;
    char *keytab_name;
    krb5_keytab keytab;
    krb5_kt_cursor cursor;
    krb5_keytab_entry entry;
    char *principal;
    int i;
    int j;


    VERBOSE("Flushing the keytab");
    keytab_name = (char *) malloc(strlen(flags->keytab_file) + 8);
    if (!keytab_name) {
        fprintf(stderr, "Error: malloc failed\n");
        return ENOMEM;
    }
    memset(keytab_name, 0, strlen(flags->keytab_file) + 8);
    sprintf(keytab_name, "WRFILE:%s", flags->keytab_file);
    ret = krb5_kt_resolve(flags->context, keytab_name, &keytab);
    free(keytab_name);
    if (ret) {
        fprintf(stderr, "Error: krb5_kt_resolve failed (%s)\n", error_message(ret));
        return ret;
    }

    ret = krb5_kt_start_seq_get(flags->context, keytab, &cursor);
    if (!ret) {
        while (!krb5_kt_next_entry(flags->context, keytab, &entry, &cursor)) {
        ret = krb5_unparse_name(flags->context, entry.principal, &principal);
        if (ret) {
            fprintf(stderr, "Error: krb5_unparse_name failed (%s)\n", error_message(ret));
            krb5_free_keytab_entry_contents(flags->context, &entry);
            krb5_kt_close(flags->context, keytab);
            return ret;
            }
            for (i = 0; *(principal + i); i++) {
                if (*(principal + i) == '/') {
                    i++;    /* We want to start at the next character */
                    break;
                }
            }
            for (j = i; *(principal + j); j++) {
                if (*(principal + j) =='@') {
                    *(principal + j) = '\0';
                    break;
                }
            }
            if (strcmp(principal + i, flags->hostname)) {
                krb5_free_keytab_entry_contents(flags->context, &entry);
                krb5_free_unparsed_name(flags->context, principal);
                continue;
            }
            krb5_free_unparsed_name(flags->context, principal);

            ret = krb5_kt_end_seq_get(flags->context, keytab, &cursor);
            if (ret) {
                fprintf(stderr, "Error: krb5_kt_end_seq_get failed (%s)\n", error_message(ret));
                krb5_free_keytab_entry_contents(flags->context, &entry);
                krb5_kt_close(flags->context, keytab);
                return ret;
            }
            ret = krb5_kt_remove_entry(flags->context, keytab, &entry);
            krb5_free_keytab_entry_contents(flags->context, &entry);
            if (ret) {
                fprintf(stderr, "Error: krb5_kt_remove_entry failed (%s)\n", error_message(ret));
                krb5_kt_close(flags->context, keytab);
                return ret;
            }
            ret = krb5_kt_start_seq_get(flags->context, keytab, &cursor);
            if (ret) {
                fprintf(stderr, "Error: krb5_kt_remove_entry failed (%s)\n", error_message(ret));
                krb5_kt_close(flags->context, keytab);
                return ret;
            }
        }
        ret = krb5_kt_end_seq_get(flags->context, keytab, &cursor);
        if (ret) {
            fprintf(stderr, "Error: krb5_kt_end_seq_get failed (%s)\n", error_message(ret));
            krb5_kt_close(flags->context, keytab);
            return ret;
        }
    }

    krb5_kt_close(flags->context, keytab);

    return ldap_flush_principals(flags);
}


int update_keytab(msktutil_flags *flags)
{
    char **principals;
    int i;
    int ret = 0;


    /* Need to call set_password first, as this will check and create the computer account if needed */
    ret = set_password(flags);
    if (ret) {
        fprintf(stderr, "Error: set_password failed\n");
        return ret;
    }

    VERBOSE("Updating all entires for %s", flags->short_hostname);
    principals = ldap_list_principals(flags);
    if (principals) {
        for (i = 0; principals[i]; i++) {
            ret = add_principal(principals[i], flags);
            if (ret) {
                fprintf(stderr, "Error: add_principal failed\n");
                goto error;
            }
        }
error:
        for (i = 0; principals[i]; i++) {
            free(principals[i]);
        }
        free(principals);
    }

    return ret;
}


int add_principal(char *principal, msktutil_flags *flags)
{
    int ret;
    char *keytab_name;
    krb5_keytab keytab;
    char *principal_string;
    char *curr_principal;
    krb5_principal princ;
    krb5_kt_cursor cursor;
    krb5_keytab_entry entry;
    krb5_kvno kvno;
    krb5_enctype *enc_types;
    int i;
    krb5_keyblock key;
    krb5_data pass;
#ifndef HEIMDAL     /* MIT */
    krb5_encrypt_block eblock;
    krb5_data salt;
#else           /* HEIMDAL */
    krb5_enctype eblock;
    krb5_salt salt;
#endif


    ret = ldap_add_principal(principal, flags);
    if (ret) {
        fprintf(stderr, "Error: ldap_add_principal failed\n");
        return ret;
    }

    VERBOSE("Adding principal to keytab: %s", principal);
    keytab_name = (char *) malloc(strlen(flags->keytab_file) + 8);
    if (!keytab_name) {
        fprintf(stderr, "Error: malloc failed\n");
        return ENOMEM;
    }
    memset(keytab_name, 0, strlen(flags->keytab_file) + 8);
    sprintf(keytab_name, "WRFILE:%s", flags->keytab_file);
    ret = krb5_kt_resolve(flags->context, keytab_name, &keytab);
    free(keytab_name);
    if (ret) {
        fprintf(stderr, "Error: krb5_kt_resolve failed (%s)\n", error_message(ret));
        return ret;
    }

    principal_string = (char *) malloc(strlen(principal) + strlen(flags->realm_name) + 2);
    if (!principal_string) {
        fprintf(stderr, "Error: malloc failed\n");
        krb5_kt_close(flags->context, keytab);
        return ENOMEM;
    }
    memset(principal_string, 0, strlen(principal) + strlen(flags->realm_name) + 2);
    sprintf(principal_string, "%s@%s", principal, flags->realm_name);
    ret = krb5_parse_name(flags->context, principal_string, &princ);

    /* Need to call set_password first, as that produces a 'stable' kvno */
    ret = set_password(flags);
    if (ret) {
        fprintf(stderr, "Error: set_password failed\n");
        free(principal_string);
        krb5_free_principal(flags->context, princ);
        krb5_kt_close(flags->context, keytab);
        return ret;
    }
    kvno = ldap_get_kvno(flags);

    ret = krb5_kt_start_seq_get(flags->context, keytab, &cursor);
    if (!ret) {
        while (!krb5_kt_next_entry(flags->context, keytab, &entry, &cursor)) {
            ret = krb5_unparse_name(flags->context, entry.principal, &curr_principal);
            if (ret) {
                fprintf(stderr, "Error: krb5_unparse_name failed (%s)\n", error_message(ret));
                krb5_kt_start_seq_get(flags->context, keytab, &cursor);
                krb5_kt_close(flags->context, keytab);
                return ret;
            }
            if (strcmp(curr_principal, principal_string) ||
                entry.vno == kvno - 1) {
                krb5_free_keytab_entry_contents(flags->context, &entry);
                krb5_free_unparsed_name(flags->context, curr_principal);
                continue;
            }
                krb5_free_unparsed_name(flags->context, curr_principal);

            ret = krb5_kt_end_seq_get(flags->context, keytab, &cursor);
            if (ret) {
                fprintf(stderr, "Error: krb5_kt_end_seq_get failed (%s)\n", error_message(ret));
                krb5_free_keytab_entry_contents(flags->context, &entry);
                free(principal_string);
                krb5_kt_close(flags->context, keytab);
                return ret;
            }
            ret = krb5_kt_remove_entry(flags->context, keytab, &entry);
            krb5_free_keytab_entry_contents(flags->context, &entry);
            if (ret) {
                fprintf(stderr, "Error: krb5_kt_remove_entry failed (%s)\n", error_message(ret));
                free(principal_string);
                krb5_kt_close(flags->context, keytab);
                return ret;
            }
            ret = krb5_kt_start_seq_get(flags->context, keytab, &cursor);
            if (ret) {
                fprintf(stderr, "Error: krb5_kt_start_seq_get failed (%s)\n", error_message(ret));
                free(principal_string);
                krb5_kt_close(flags->context, keytab);
                return ret;
            }
        }
        free(principal_string);
        ret = krb5_kt_end_seq_get(flags->context, keytab, &cursor);
        if (ret) {
            fprintf(stderr, "Error: krb5_kt_end_seq_get failed (%s)\n", error_message(ret));
            krb5_kt_close(flags->context, keytab);
            return ret;
        }
    }

    enc_types = (krb5_enctype*)malloc(33 * sizeof(krb5_enctype));
    if (!enc_types) {
        fprintf(stderr, "Error: malloc failed\n");
        krb5_free_principal(flags->context, princ);
        krb5_kt_close(flags->context, keytab);
        return ENOMEM;
    }
    i=0;
    if (flags->ad_supportedEncryptionTypes & MS_KERB_ENCTYPE_DES_CBC_CRC)
        enc_types[i++] = ENCTYPE_DES_CBC_CRC;
    if (flags->ad_supportedEncryptionTypes & MS_KERB_ENCTYPE_DES_CBC_MD5)
        enc_types[i++] = ENCTYPE_DES_CBC_MD5;
    if (flags->ad_supportedEncryptionTypes & MS_KERB_ENCTYPE_RC4_HMAC_MD5)
        enc_types[i++] = ENCTYPE_ARCFOUR_HMAC;
#ifdef ENCTYPE_AES128_CTS_HMAC_SHA1_96
    if (flags->ad_supportedEncryptionTypes & MS_KERB_ENCTYPE_AES128_CTC_HMAC_SHA1_96)
        enc_types[i++] = ENCTYPE_AES128_CTS_HMAC_SHA1_96;
#endif
#ifdef ENCTYPE_AES256_CTS_HMAC_SHA1_96
    if (flags->ad_supportedEncryptionTypes & MS_KERB_ENCTYPE_AES256_CTS_HMAC_SHA1_96)
        enc_types[i++] = ENCTYPE_AES256_CTS_HMAC_SHA1_96;
#endif

    enc_types[i] = (krb5_enctype) 0;

    ret = set_password(flags);
    if (ret) {
        fprintf(stderr, "Error: set_password failed\n");
        krb5_free_principal(flags->context, princ);
        krb5_kt_close(flags->context, keytab);
        return ret;
    }

#ifndef HEIMDAL     /* MIT */

    salt.data = NULL;
    salt.length = 0;
    for (i = 0; enc_types[i]; i++) {
         ret = krb5_use_enctype(flags->context, &eblock, enc_types[i]);
         if (ret) {
            fprintf(stderr, "Error: krb5_use_enctype failed i=%d enc_types[i]=0x%x (%s)\n",
                i, enc_types[i],error_message(ret));
         }

        /*
         * Windows uses the realm_name+host+samAccountNumber_nodollar+.lower_realm_name
         * For DES and AES i.e. all accept RC4.
         */
        if (kvno != KVNO_WIN_2000 && enc_types[i] != ENCTYPE_ARCFOUR_HMAC) {
            salt.data = (char*)malloc((strlen(flags->realm_name) * 2) + strlen(flags->samAccountName_nodollar) + 6);
            if (!salt.data) {
                fprintf(stderr, "Error: malloc failed\n");
                ret = ENOMEM;
                goto error;
            }
            memset(salt.data, 0, (strlen(flags->realm_name) * 2) + strlen(flags->samAccountName_nodollar) + 6);
            sprintf(salt.data, "%shost%s.%s", flags->realm_name, flags->samAccountName_nodollar, flags->lower_realm_name);
            salt.length = strlen(salt.data);
        } else {
            ret = krb5_principal2salt(flags->context, princ, &salt);
            if (ret) {
                fprintf(stderr, "Error: krb5_principal2salt failed (%s)\n", error_message(ret));
                goto error;
            }
        }

        VERBOSE("    Using salt of %s", (char *) salt.data);
        pass.data = flags->password;
        pass.length = PASSWORD_LEN;
        ret = krb5_string_to_key(flags->context, &eblock, &key, &pass, &salt);
        if (ret) {
            fprintf(stderr, "Error: krb5_string_to_key failed (%s)\n", error_message(ret));
            krb5_free_data_contents(flags->context, &salt);
            goto error;
        }
        entry.principal = princ;
        entry.vno = kvno;
        entry.key = key;
        ret = krb5_kt_add_entry(flags->context, keytab, &entry);
        VERBOSE("  Adding entry of enctype 0x%x", enc_types[i]);
        krb5_free_data_contents(flags->context, &salt);
        krb5_free_keyblock_contents(flags->context, &key);
        if (ret) {
            fprintf(stderr, "Error: krb5_kt_add_entry failed (%s)\n", error_message(ret));
            goto error;
        }
        if (salt.data) {
            free(salt.data);
            salt.data = NULL;
        }
        salt.length = 0;
    }
error:
    if (salt.data)
            free(salt.data);
    free(enc_types);
    memset(&key, 0, sizeof(krb5_keyblock));
    krb5_free_principal(flags->context, princ);
    krb5_kt_close(flags->context, keytab);

    return ret;

#else /* HEIMDAL */

    salt.saltvalue.data = NULL;
    salt.saltvalue.length = 0;
    for (i = 0; enc_types[i]; i++) {
        eblock = enc_types[i];

        /*
         * Windows uses the realm_name+host+samAccountNumber_nodollar+.lower_realm_name
         * For DES and AES i.e. all accept RC4.
         */
        if (kvno != KVNO_WIN_2000 && enc_types[i] != ENCTYPE_ARCFOUR_HMAC) {
            salt.salttype = KRB5_PW_SALT;
            salt.saltvalue.data = malloc((strlen(flags->realm_name) * 2) + strlen(flags->samAccountName_nodollar) + 6);
            if (!salt.saltvalue.data) {
                fprintf(stderr, "Error: malloc failed\n");
                ret = ENOMEM;
                goto error;
            }

            memset(salt.saltvalue.data, 0, (strlen(flags->realm_name) * 2) + strlen(flags->samAccountName_nodollar) + 6);
            sprintf(salt.saltvalue.data, "%shost%s.%s", flags->realm_name, flags->samAccountName_nodollar, flags->lower_realm_name);
            salt.saltvalue.length = strlen(salt.saltvalue.data);
        } else {
            ret = krb5_get_pw_salt(flags->context, princ, &salt);
            if (ret) {
                fprintf(stderr, "Error: krb5_get_pw_salt failed (%s)\n", error_message(ret));
                goto error;
            }
        }

        VERBOSE("    Using salt of %s", (char *) salt.saltvalue.data);
        pass.data = &(flags->password[0]);
        pass.length = PASSWORD_LEN;
        ret = krb5_string_to_key_data_salt(flags->context, eblock, pass, salt, &key);
        if (ret) {
            fprintf(stderr, "Error: krb5_string_to_key_data_salt failed (%s)\n", error_message(ret));
            krb5_free_data_contents(flags->context, &salt.saltvalue);
            goto error;
        }
        entry.principal = princ;
        entry.vno = kvno;
        entry.keyblock = key;
        ret = krb5_kt_add_entry(flags->context, keytab, &entry);
        VERBOSE("  Adding entry of enctype 0x%x", enc_types[i]);
        krb5_free_data_contents(flags->context, &salt.saltvalue);
        krb5_free_keyblock_contents(flags->context, &key);
        if (ret) {
            fprintf(stderr, "Error: krb5_kt_add_entry failed (%s)\n", error_message(ret));
            goto error;
        }
        if (salt.saltvalue.data) {
            free(salt.saltvalue.data);
            salt.saltvalue.data = NULL;
        }
    }
error:
    if (salt.saltvalue.data)
        free(salt.saltvalue.data);
    free(enc_types);
    memset(&key, 0, sizeof(krb5_keyblock));
    krb5_free_principal(flags->context, princ);
    krb5_kt_close(flags->context, keytab);

    return ret;

#endif
}
