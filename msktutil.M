.TH REPLACE_PROGNAME 1 REPLACE_VERSION
.SH NAME
REPLACE_PROGNAME \- fetches and manages kerberos keytabs in an Active Directory environment
.SH SYNOPSIS
.B REPLACE_PROGNAME
[mode] [parameter 1] [parameter 2] ...
.SH DESCRIPTION
REPLACE_PROGNAME is a Unix/Linux keytab utility for Microsoft Active Directory environments.  This program is
capable of creating accounts in Active Directory, adding service principals to those accounts, and
creating local keytab files so that kerberizied services can utilize Active Directory as a Kerberos infrastructure.
REPLACE_PROGNAME will create and manage machine accounts by default.  The --use-service-account option
lets REPLACE_PROGNAME operate on service accounts.  REPLACE_PROGNAME requires that the Kerberos client
libraries are properly installed and configured to use Active Directory as a realm.
.PP
Whenever a principal is added or a keytab is updated, the secret password for the corresponding
account is changed.  By default, the password is not stored, so it needs to be reset each time
REPLACE_PROGNAME is executed.  All entries in the keytab will be automatically updated whenever the
password is reset.  The previous entries will be left in the keytab, so sessions using the older key
versions will not break.  This behavior is similar to the way Windows hosts handle machine password
changes.
.SH CREDENTIALS
.PP
There are two common methods of using this program.  The first is to "kinit" with Administrator-like
credentials which have permission to create computer objects in your Active Directory server.  If you
invoke the program with such credentials, you can create a new computer account or service account
from scratch.
.PP
The second is to pre-create the accounts with such credentials, and then invoke REPLACE_PROGNAME on
a machine without any special permissions.  When the computer account or service account exists already,
REPLACE_PROGNAME will attempt to authenticate as that account using either the existing keytab, or
if that fails, a default password.  When that default password is not specified with the option
--old-account-password, REPLACE_PROGNAME will use the default machine password.  It will then change
the password and update the keytab appropriately.  This is usually the more convenient option when joining
many computers to the domain.
.PP
To pre-create a computer account, you may use the Active Directory Users and Computers GUI, select
"new computer" from the right click menu, and type the short DNS name, then right click on the newly
created object and select "Reset account" to set the password to the default value.  Another
alternative is to run REPLACE_PROGNAME in the pre-create mode.  Both methods accomplish the
same thing.
.PP
To pre-create a service account, you may use the Active Directory Users and Computers GUI, select
"new user" from the right click menu, fill in all required data, set the password to a specific
value and use setspn.exe to set the desired servicePrincipalName(s).  You may also select "must change
password at next logon".
.SH MODES
.TP
.B create
Creates a keytab for the current host or a given service account.  Equivalent to update --service host.
.TP
.B update
Forces a password change and updates all related service principal entries from the
servicePrincipalName and userPrincipalName attributes.  Updates dNSHostName for machine accounts and
always updates msDS-supportedEncryptionTypes attributes with current values, and applies other changes
as specified.
.TP
.B auto-update
Checks if the password is at least 30 days old (from pwdLastSet attribute), and that the account
does not have password expiry disabled.  If those conditions are met, acts just like REPLACE_PROGNAME
update. Will also update if the keytab failed to authenticate but the default password did work (e.g.
after resetting the account in AD).  Otherwise, exits without doing anything (even if attribute modifying
options are given).  This option is intended for use from a daily crontab to ensure that the password
is rotated regularly.
.TP
.B pre-create
Pre-create (or update) an account for the given host with default password.  Does not use or update
local keytab.  Requires -h or --computer-name argument.  Implies --user-creds-only.  Generally
requires administrator credentials.
.TP
.B flush
Flushes out principals for the current accountname from the keytab, and makes corresponding changes
to the machine or service account.
.TP
.B cleanup
Deletes entries from the keytab that are no longer needed.
.B delete
Deletes the host or service account from Active Directory.
.SH OPTIONS
.SS COMMON OPTIONS
.TP
-v, --version
Displays version information
.TP
--help
Displays a help message
.TP
--verbose
Enables verbose status messages.  May be specified more then once to get LDAP debugging.
.SS CONNECTION/SETUP OPTIONS
.TP
-b, --base <base ou>
Specifies an LDAP base OU when creating a new account.  Unless the given string ends with the
domain's base DN, it is assume to be a relative path: For example, specifying '-b OU=Unix'
for a computer named SERVER in an Active Directory domain example.com would create a computer
account in the LDAP path: CN=SERVER,OU=Unix,DC=EXAMPLE,DC=COM.  This option can also
be specified by setting the MSKTUTIL_LDAP_BASE environment variable to the desired value.

If not specified, the default value is read from AD (and the default there, unless modified by an
admin, is CN=Computers for machine accounts and CN=Users for service accounts).
.TP
--computer-name <name>
Specifies that the new account should use <name> for the computer account name and the SAM Account
Name.  Note that a '$' will be automatically appended to the SAM Account Name.  Defaults to the
machine's hostname, excluding the realm, with dots replaced with dashes.

That is: if the realm is EXAMPLE.COM, and the hostname is FOO.EXAMPLE.COM, the default computer name
is FOO.  If the hostname is FOO.BAR.EXAMPLE.COM, the default computer name is FOO-BAR.
.TP
--account-name <name>
An alias for --computer-name that can be used when operating on service accounts.  Note that a '$' 
will not be automatically appended to the SAM Account Name when using service accounts.
.TP
--old-account-password <password>
Use supplied account password for authentication.  This is useful if the keytab does not yet exist 
but the password of the computer account is known.  This password will be changed by REPLACE_PROGNAME in order 
to create or update the keytab
.TP
--password <new_password>
Specify the new account password instead of generating a random one. Consider the password policy settings
when defining the string.
.TP
--dont-change-password
Do not create a new password. Try to use existing keys when performing keytab updates or the old password
when creating a new keytab. This is useful for adding new SPNs to a machine or service account. This option
is only available in update or create mode. In create mode the old password needs to be specified
with --old-account-password
.TP
-h, --hostname <name>
Overrides the current hostname to be used to be <name>.  If this is not specified, the local host
name will be used.  Note that the local name lookup service will be to qualify and resolve names
into fully-qualified names, including a domain extension.  This affects the default hostname for
other arguments, and the default computer-name.  The hostname is also used to set the dNSHostName
attribute.
.TP
-k, --keytab <file>
Specifies to use <file> for the keytab.  This option can also be specified by setting the
MSKTUTIL_KEYTAB environment variable to the name of the desired keytab file.  This keytab is both
read from, in order to authenticate as the given account, and written to, after updating the
account password.  Default: /etc/krb5.keytab
.TP
--keytab-auth-as <name>
Specifies which principal name we should try to use, when we authenticate from a keytab. Normally,
REPLACE_PROGNAME will try to use the account name or the host principal for the current host. If
this option is specified, instead REPLACE_PROGNAME will try to use the given principal name first,
and only fall back to the default behavior if we fail to authenticate with the given name. This
option can be useful if you do not know the current password for the relevant account, do not have
a keytab with the account principal, but you do have a keytab with a service principal associated
with that account.
.TP
--server <server>
Specifies to use <server> as the domain controller.  This affects both kerberos and ldap operations.
The server can also be specified by setting the MSKTUTIL_SERVER environment variable.  Default:
looked up in DNS from the realm name.
.TP
--server-behind-nat
When the server is behind a firewall that performs Network Address Translation, KRB-PRIV messages
fail validation.  This is because the IP address in the encrypted part of the message cannot be
rewritten in the NAT process.  This option ignores the resulting error for the password change
process, allowing systems outside the NAT firewall to join the domain managed by servers inside
the NAT firewall.
.TP
--realm <realm>
Specifies to use <realm> as kerberos realm.  Default: use the default_realm from [libdefaults] 
section of krb5.conf.
.TP
--site <site>
Find and use domain controller in specific AD site. This option is ignored if option --server is used.
.TP
-N, --no-reverse-lookups
Do not attempt to canonicalize the name of the domain controller via DNS reverse lookups.  You may
need to do this if your client cannot resolve the PTR records for a domain controller or your DNS
servers store incorrect PTR records.  Default: Use DNS reverse lookups to canonicalize DC names.
.TP
-n, --no-canonical-name
Do not attempt to canonicalize the hostname while creating names of kerberos principals.
Instead use supplied hostname. This may be needed for systems where forward and reverse
DNS lookups do not return the same (an dynamic dns system for example where lookup for
myhost.mydomain returns IP X.Y.Z.W , but lookup for IP X.Y.Z.W returns a name different
than myhost.mydomain).
.TP
--user-creds-only
Don't attempt to authenticate with a keytab: only use user's credentials (from
e.g. kinit).  You may need to do this to modify certain attributes that require Administrator
credentials (description, userAccountControl, userPrincipalName, in a default AD setup).
.TP
--auto-update-interval <days>
Number of <days> when REPLACE_PROGNAME auto-update will change the account password. Defaults to 30 days.
.TP
-m, --sasl-mechanisms <mechanisms list>
A space-separated list of candidate SASL mechanisms to use when performing the LDAP bind.  The first mechanism in
the list that is supported by both the client (the host running REPLACE_PROGNAME) and the server (Active Directory)
will be used. If providing more than one candidate mechanism, make sure to quote the list to protect the whitespace
from the shell.  Default: "GSS-SPNEGO GSSAPI".
.SS OBJECT TYPE/ATTRIBUTE-SETTING OPTIONS
.TP
--use-service-account
Create and maintain service accounts instead of machine accounts.
.TP
--delegation
Enables the account to be trusted for delegation.  This option can also be enabled by
setting the MSKTUTIL_DELEGATION environment variable.  This modifies the userAccountControl
attribute.  Generally requires administrator credentials.
.TP
--description <text>
Sets the account's description attribute to the given text (or removes if text
is '').  Generally requires administrator credentials.
.TP
--disable-delegation
Disables the account from being trusted for delegation.  This modifies the
userAccountControl attribute.  Generally requires administrator credentials.
.TP
--disable-no-pac
Unsets the flag that disables the KDC's including of a PAC in the machine's service tickets.  This
modifies the userAccountControl attribute.  Generally requires administrator credentials.
.TP
--dont-expire-password
Sets the DONT_EXPIRE_PASSSWORD bit in the userAccountControl attribute, which disables password
expiry for this account.  If you don't run a cron job to periodically rotate the keytab, you will
want to set this flag.  Generally requires administrator credentials.
.TP
--do-expire-password
Unsets the DONT_EXPIRE_PASSWORD flag in the userAccountControl attribute.  Generally requires
administrator credentials.
.TP
--dont-update-dnshostname 
Do not update dnsHostName attribute. In some AD installations modification of this attribute
is not allowed (unless using administrator credentials), using this option will avoid constraint 
violation warning.
.TP
--enable 
Unsets the UF_ACCOUNT_DISABLE flag in the userAccountControl attribute.  When a computer leaves the domain
this flag is normally set.  Generally requires administrator credentials.
.TP
--enctypes <integer>
Sets the supported encryption types in the msDs-supportedEncryptionTypes field.

You may OR together the following values:
  0x1=des-cbc-crc
  0x2=des-cbc-md5
  0x4=rc4-hmac-md5
  0x8=aes128-cts-hmac-sha1
  0x10=aes256-cts-hmac-sha1

This value is used to determine which encryption types AD will offer to use, and which encryption
types to put in the keytab.

If the value is set to 0x3 (that is: only the two DES types), it also attempts to set the DES-only
flag in userAccountControl.

Note: Windows 2008R2 refuses to use DES by default; you thus cannot use DES-only keys unless
you have enabled DES encryption for your domain first.  Recent versions of MIT kerberos clients
similarly refuse to use DES by default.

Default: sets the value to 0x1C: that is, use anything but DES.
.TP
--allow-weak-crypto
Enables the usage of DES keys for authentication. This is equivalent to MIT's krb5.conf parameter allow_weak_crypto.
.TP
--no-pac
Specifies that service tickets for this account should not contain a PAC.  This modifies
the userAccountControl attribute.  See Microsoft Knowledge Base article #832575 for details.  This
option can also be specified by setting the MSKTUTIL_NO_PAC environment variable.  Generally requires
administrator credentials.
.TP
-s, --service <principal>
Specifies a service principal to add to the account (and thus keytab, if appropriate).  The service is of
the form <service>/<hostname>.  If the hostname is omitted, assumes current hostname.  May be specified
multiple times.
.TP
--remove-service <principal>
Specifies a service principal to remove from the account (and keytab if appropriate).
.TP
--upn <principal>
Sets the userPrincipalName attribute of the computer account or service account to be <principal>.

The userPrincipalName can be used in addition to the sAMAccountName (e.g. computername$ for computer accounts) for kinit.

<principal> can be provided in short form (e.g. host/hostname.example.com) or in long form
(e.g. host/hostname.example.com@EXAMPLE.COM). In short form the default realm will automatically
be appended.

This operation requires administrator privileges.
.TP
--set-samba-secret
Use Samba's net changesecretpw command to locally set the machine account password in Samba's secrets.tdb.
$PATH need to include Samba's net command.  Samba needs to be configured appropriately.
.TP
--use-samba-cmd <command>
Use supplied command instead of Samba's net changesecretpw command. command will be supplied machine account
password on standard input and shall return 0 exit code on success. 
.TP
--check-replication
Wait until the password change is reflected in LDAP.  By default, msktutil exits once a password update is
successful and the new keytab is written.  However, due to replication delays, LDAP queries might still
return an older key version number.  If --check-replication is given, msktutil waits until the key version
number is updated on the queried LDAP server as well.  Note that this is just a sanity check: The new
password is supposed to be accepted on all domain controllers once the update succeeds, even if LDAP is
not yet in sync.  Turning on this option might substantially increase the runtime of msktutil in some
environments due to replication delays (eg. 15 to 30 minutes for common AD configurations).  The default
is not to check LDAP replication.
.SS CLEANUP OPTIONS
.TP
--remove-old <number>
Removes entries from the keytab that are older than <number> days. The newest keytab entries will be kept
to prevent a total cleanup. I.e. it is not possible to produce an empty keytab with the --remove-old option.
.TP
--remove-enctype <int>
Removes entries from the keytab with given encryption type. (See --enctypes for supported encryption types.)
Warning: it is possible to produce empty keytabs with the --remove-empty option by successively removing
all encryption types. Supported enctype strings are: des-cbc-crc,des-cbc-md5, arcfour, aes128 and aes256.
.SH NOTES
.SS PASSWORD EXPIRY
.PP
Be aware that Windows machines will, by default, automatically change their account password every
30 days, and thus many domains have a 90-day password expiry window, after which your keytab will
stop working.  There are two ways to deal with this:
.PP
a) (Preferred): Make sure you're running a daily cron job to run REPLACE_PROGNAME auto-update, which
will change the password automatically 30 days after it was last changed and update the keytab.
.PP
b) (Not preferred): disable password expiry for the account via the --dont-expire-password option (or
otherwise setting DONT_EXPIRE_PASSWORD flag in userAccountControl in AD).
.SS PASSWORD POLICY ISSUES
.PP
This section only applies to REPLACE_PROGNAME --use-service-account.
.PP
While machine account passwords may be changed at any time, service accounts are user accounts and
your Active Directory domain may have special password policies for those user accounts.  E.g.,
"minimum password age" is typically set to 1 day, which means that you will have to wait for that
time to pass until you may invoke REPLACE_PROGNAME update --use-service-account.
.SS OTHER NOTES
.PP
Unlike other kerberos implementations, Active Directory has only a single key for all of the
principals associated with an account.  So, if you create a HTTP/hostname service principal, it will
share the same key as the host/hostname principal.  If you want to isolate (security-wise) different
service principals, you may want to create a dedicated service account for them (with --use-service-account)
and a separate keytab file (with --keytab).
.PP
Also note: kinit -k 'host/computername' *will not work*, by default, even when that is a valid
service principal existing in your keytab.  Active Directory does not allow you to authenticate as a
service principal, so do not use that as a test of whether the service principal is working.  If you
actually want to authenticate as the computer account user, kinit -k 'computername$' instead.
.PP
If you really need to be able to authenticate as 'host/computername', you can also use the --upn
argument to set the userPrincipalName attribute (generally requires administrator credentials, not
computer account credentials).  Both 'computername$' and the value of userPrincipalName are treated
as valid account names to kinit as.
.PP
REPLACE_PROGNAME will use kerberized LDAP operations to talk to domain controllers.  To obtain a LDAP service
ticket, the DNS service will be used to construct the domain controllers LDAP principal name.  If DNS is
misconfigured, this construction may fail.  To work around this issue,  you may specify the fully
qualified DNS name of your domain controller with the --server option and additionally use the
--no-reverse-lookups option.
.PP
Samba (www.samba.org) provides the net command that can be used to manage kerberos keytabs as
well.  Using REPLACE_PROGNAME and commands like "net ads join" or "net ads keytab" together can lead to
trouble.  With the --set-samba-secret option, REPLACE_PROGNAME can be used as a replacement for net.
.PP
Active Directory includes authorization data (e.g. information about group memberships) in Kerberos tickets.
This information is called PAC and may lead to very large ticket sizes.  Especially HTTP services are
known to produce failures if that size exceeds the HTTP header size.  If your service does not make use
of that PAC information (which is true for most Unix/Linux-services) you may just disable it with
the --no-pac option.
.SH EXAMPLES
For unprivileged users the most common invocations are:
.PP
.nf
REPLACE_PROGNAME create
.fi
.PP
This will create a computer account in Active Directory with a new password and write out a new keytab.
.PP
.nf
REPLACE_PROGNAME update --service host --service HTTP
.fi
.PP
This will update a computer account in Active Directory with a new password, write out a new keytab,
and ensure that it has both "host" and "HTTP" service principals are on it for the hostname.
.PP
.nf
REPLACE_PROGNAME update  --dont-change-password --service host --service HTTP
.fi
.PP
This will do the same as the last example but without changing the password.
.PP
.nf
REPLACE_PROGNAME auto-update
.fi
.PP
This is useful in a daily cron job to check and rotate the password automatically when it's 30 days
old.
.PP
.nf
For users with admin privileges in AD, some common uses:
.PP
.nf
REPLACE_PROGNAME create --service host --service HTTP
.fi
.PP
This will create a computer account in Active Directory with a new password, write out a new keytab,
and ensure that it has both "host" and "HTTP" service principals are on it for the hostname.
.PP
.nf
REPLACE_PROGNAME pre-create --host computer1.example.com
.fi
.PP
This will pre-create an account for computer1 with the default password using your credentials.  This
can be done on a central host, e.g. to script the addition of many hosts.  You can then use
REPLACE_PROGNAME create on the hosts themselves (without special credentials) to join them to the
domain.
.PP
.nf
REPLACE_PROGNAME create --host afs --service afs --enctypes 0x03
.fi
.PP
This will create an afs/cell.name@REALM principal, and associate that principal with a computer
account called 'afs'.  The principal will be marked as DES-only, which is required for AFS.
.PP
.nf
REPLACE_PROGNAME create --use-service-account --service HTTP/hostname.example.com --keytab /etc/apache/krb5.keytab --account-name srv-http --no-pac
.fi
.PP
This will create an HTTP/hostname.example.com@REALM principal, and associate that principal with a service
account called 'srv-http'.  Corresponding Kerberos keys will be written to the keytab file /etc/apache/krb5.keytab.
The size of Kerberos tickets for that service will stay small because no PAC information will be included.
.PP
.nf
REPLACE_PROGNAME create --keytab /etc/krb5/user/10123/client.keytab --use-service-account --account-name johndoe --dont-change-password --old-account-password <John Doe's Password>
.fi
.PP
This will create a keytab for johndoe without changing John Doe's password
.PP
.nf
REPLACE_PROGNAME create --service host/hostname --service host/hostname.example.com --set-samba-secret --enctypes 0x4
.fi
.PP
This will create a computer account in Active Directory that is compatible with Samba.  The command creates
a new password, write out a new keytab, and ensure that it includes both "host/hostname" and "host/hostname.example.com"
as service principals (which is equivalent to what setspn.exe -R would do on windows).  The new computer
password will be stored in Samba's secrets.tdb database to provide interoperability with Samba.
As Samba (version 3) only supports arcfour encrypted Kerberos tickets the --enctypes option must be used
to select only that encryption type.
.PP
.nf
REPLACE_PROGNAME cleanup --remove-old 10
.fi
.PP
Deletes all entries older than 10 days, keeping at least the last entry.
.SH ENVIRONMENT
.TP
MSKTUTIL_LDAP_BASE
Specifies a relative LDAP base when creating a new account (see --base),
.TP
MSKTUTIL_KEYTAB
  Specifies the keytab. Default: /etc/krb5.keytab (see --keytab),
.TP
MSKTUTIL_SERVER
Specifies the domain controller (see --server).
.TP
MSKTUTIL_DELEGATION
Enables the account to be trusted for delegation (see --delegation).
.TP
MSKTUTIL_NO_PAC
Specifies that service tickets for this account should not contain a PAC (see --no-pac).
.TP
MSKTUTIL_SAMBA_CMD
Specifies the command to be used to locally set the machine account password in Samba's  secrets.tdb.
.SH AUTHORS
(C) 2004-2006 Dan Perry <dperry at pppl.gov>
.PP
(C) 2006 Brian Elliott Finley (finley at anl.gov)
.PP
(C) 2009-2010 Doug Engert (deengert at anl.gov)
.PP
(C) 2010 James Knight <foom at fuhm.net>
.PP
(C) 2010-2013 Ken Dreyer <ktdreyer at ktdreyer.com>
.PP
(C) 2012-2017 Mark Proehl <mark at mproehl.net>
.PP
(C) 2012-2017 Olaf Flebbe <of at oflebbe.de>
.PP
(C) 2013-2017 Daniel Kobras <d.kobras at science-computing.de>
