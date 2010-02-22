/*
 *----------------------------------------------------------------------------
 *
 * msktutil.h
 *
 * (C) 2004-2006 Dan Perry (dperry@pppl.gov)
 *
 *
 * THIS CODE AND INFORMATION IS PROVIDED "AS IS" WITHOUT WARRANTY OF
 * ANY KIND, EITHER EXPRESSED OR IMPLIED, INCLUDING BUT NOT LIMITED
 * TO THE IMPLIED WARRANTIES OF MERCHANTABILITY AND/OR FITNESS FOR A
 * PARTICULAR PURPOSE.
 *
 *-----------------------------------------------------------------------------
 */

#ifndef __msktutil_h__
#define __msktutil_h__


#include "config.h"

#include <stdio.h>
#include <fcntl.h>
#include <string.h>
#include <unistd.h>
#include <signal.h>
#include <ctype.h>
#include <malloc.h>
#include <stdlib.h>
#include <errno.h>
#include <time.h>
#include <netdb.h>
#include <sys/socket.h>
#include <sys/utsname.h>
#include <ldap.h>

#ifdef HAVE_COM_ERR_H
# ifdef COM_ERR_NEEDS_EXTERN_C
  extern "C" {
# endif
#include <com_err.h>
# ifdef COM_ERR_NEEDS_EXTERN_C
 }
# endif
#endif
#include <krb5.h>
#ifdef HAVE_SASL_H
#include <sasl.h>
#else
#include <sasl/sasl.h>
#endif


#ifndef PACKAGE_NAME
#define PACKAGE_NAME "msktutil"
#endif
#define PASSWORD_LEN                    63
#define MAX_HOSTNAME_LEN                255
#define MAX_TRIES                       10
#define MAX_SAM_ACCOUNT_LEN             19

#ifndef TMP_DIR
#define TMP_DIR                         "/tmp"
#endif


/* In case it's not in krb5.h */
#ifndef MAX_KEYTAB_NAME_LEN
#define  MAX_KEYTAB_NAME_LEN            1100
#endif

/* From SAM.H */
#define UF_WORKSTATION_TRUST_ACCOUNT    0x00001000
#define UF_DONT_EXPIRE_PASSWORD         0x00010000
#define UF_TRUSTED_FOR_DELEGATION       0x00080000
#define UF_USE_DES_KEY_ONLY             0x00200000
#define UF_NO_AUTH_DATA_REQUIRED        0x02000000

/* for msDs-supportedEncryptionTypes  bit defines */
#define MS_KERB_ENCTYPE_DES_CBC_CRC             0x01
#define MS_KERB_ENCTYPE_DES_CBC_MD5             0x02
#define MS_KERB_ENCTYPE_RC4_HMAC_MD5            0x04
#define MS_KERB_ENCTYPE_AES128_CTC_HMAC_SHA1_96 0x08
#define MS_KERB_ENCTYPE_AES256_CTS_HMAC_SHA1_96 0x10

/* Some KVNO Constansts */
#define KVNO_FAILURE                    -1
#define KVNO_WIN_2000                   0

/* LDAP Binding Attempts */
#define ATTEMPT_SASL_PARAMS_TLS         0x0
#define ATTEMPT_SASL_NO_PARAMS_TLS      0x1
#define ATTEMPT_SASL_NO_TLS             0x2

typedef enum {
    VALUE_OFF = 0,
    VALUE_ON = 1,
    VALUE_IGNORE = 2
} msktutil_val;

typedef struct {
    char *keytab_file;
    char *ldap_ou;
    char *hostname;
    char *description;
    char *server;
    char *short_hostname;
    char *realm_name;
    char *lower_realm_name;
    char *base_dn;
    char *userPrincipalName;
    char *samAccountName;
    char *samAccountName_nodollar;
    char password[PASSWORD_LEN + 1];
    krb5_context context;
    LDAP *ldap;
    msktutil_val des_bit;
    msktutil_val no_pac;
    msktutil_val delegate;
    int verbose;
    unsigned int ad_userAccountControl; /* value AD has now */
    int ad_enctypes;    /* if msDs-supportedEncryptionTypes in AD */
    unsigned int ad_supportedEncryptionTypes; /* value AD has now */
    int enctypes;       /* if --enctypes parameter was set */
    unsigned int supportedEncryptionTypes;
} msktutil_flags;

typedef struct {
    int show_help;
    int show_version;
    int update;
    int flush;
    char **principals;
    msktutil_flags *flags;
} msktutil_exec;


/* Prototypes */
extern void krb5_cleanup(msktutil_flags *);
extern void ldap_cleanup(msktutil_flags *);
extern void init_password(msktutil_flags *);
extern char *get_default_hostname();
extern int get_default_keytab(msktutil_flags *);
extern int get_default_ou(msktutil_flags *);
extern int get_krb5_context(msktutil_flags *);
extern int ldap_connect(msktutil_flags *);
extern int ldap_get_base_dn(msktutil_flags *);
extern char *complete_hostname(char *);
extern char *get_short_hostname(msktutil_flags *);
extern int flush_keytab(msktutil_flags *);
extern int update_keytab(msktutil_flags *);
extern int add_principal(char *, msktutil_flags *);
extern int ldap_flush_principals(msktutil_flags *);
extern int set_password(msktutil_flags *);
extern krb5_kvno ldap_get_kvno(msktutil_flags *);
extern int ldap_get_des_bit(msktutil_flags *);
extern char *ldap_get_pwdLastSet(msktutil_flags *);
extern char **ldap_list_principals(msktutil_flags *);
extern int ldap_add_principal(char *, msktutil_flags *);
extern int get_dc(msktutil_flags *);
extern char *get_user_principal(msktutil_flags *flags);
extern char *get_host_os();
extern int ldap_check_account(msktutil_flags *);
extern int create_fake_krb5_conf(msktutil_flags *);
extern int remove_fake_krb5_conf();
extern int try_machine_keytab(msktutil_flags *);
extern int untry_machine_keytab();


/* Verbose messages */
#define VERBOSE(text...) if (flags->verbose) { fprintf(stdout, " -- %s: ", __FUNCTION__); fprintf(stdout, ## text); fprintf(stdout, "\n"); }


#define VERBOSEldap(text...) if (flags->verbose > 1) { fprintf(stderr, " ###### %s: ", __FUNCTION__); fprintf(stderr, ## text); fprintf(stderr, "\n"); }
#endif


#ifdef __GNUC__
#define ATTRUNUSED __attribute__((unused))
#else
#define ATTRUNUSED 
#endif
