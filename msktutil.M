.TH REPLACE_PROGNAME 1 REPLACE_VERSION
.SH NAME
REPLACE_PROGNAME \- fetches and manages kerberos keytabs in an Active Directory environment
.SH SYNOPSIS
.B REPLACE_PROGNAME
[command 1] [command 2] [command 3] ...
.SH DESCRIPTION
REPLACE_PROGNAME is a Unix/Linux keytab client for Microsoft Active Directory environments.  This program is
capable of creating accounts in Active Directory, adding service principals to those accounts, and
creating local keytab files so that kerberizied services can utilize Active directory as a Kerberos realm.
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
alternative is to invoke REPLACE_PROGNAME with the --precreate argument.  Both methods accomplish the
same thing.
.PP
To pre-create a service account, you may use the Active Directory Users and Computers GUI, select
"new user" from the right click menu, fill in all required data, set the password to a specific
value and use setspn.exe to set the desired servicePrincipalName(s).  You may also select "must change
password at next logon".
.SH PASSWORD EXPIRY
.PP
Be aware that Windows machines will, by default, automatically change their account password every
30 days, and thus many domains have a 90-day password expiry window, after which your keytab will
stop working.  There are two ways to deal with this:
.PP
a) (Preferred): Make sure you're running a daily cron job to run REPLACE_PROGNAME --auto-update, which
will change the password automatically 30 days after it was last changed and update the keytab.
.PP
b) (Not preferred): disable password expiry for the account via the --dont-expire-password option (or
otherwise setting DONT_EXPIRE_PASSWORD flag in userAccountControl in AD).
.SH PASSWORD POLICY ISSUES
.PP
This section only applies to REPLACE_PROGNAME --use-service-account.
.PP
While machine account passwords may be changed at any time, service accounts are user accounts and
your Active Directory domain may have special password policies for those user accounts.  E.g.,
"minimum password age" is typically set to 1 day, which means that you will have to wait for that
time to pass until you may invoke REPLACE_PROGNAME --update --use-service-account.
.SH OTHER NOTES
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
msktutil will use kerberized LDAP operations to talk to domain controllers.  To obtain a LDAP service
ticket, the DNS service will be used to construct the domain controllers LDAP principal name.  If DNS is
mis-configured, this construction may fail.  To work around this issue,  you may specify the fully
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
.SH MODES
.TP
-v, --version
Displays version information
.TP
--help
Displays a help message
.TP
-c, --create
Creates a keytab for the current host or a given service account.  Equivalent to --update --service host.
.TP
-f, --flush
Flushes out all principals for the current accountname from the keytab, and makes corresponding changes
to the machine or service account.
.TP
-u, --update
Forces a password change and updates all related service principal entries from the
servicePrincipalName and userPrincipalName attributes.  Updates dNSDomainName for machine accounts and
always updates msDS-supportedEncryptionTypes attributes with current values, and applies other changes
as specified.
.TP
--auto-update
Checks if the password is at least 30 days old (from pwdLastSet attribute), and that the account
does not have password expiry disabled.  If those conditions are met, acts just like --update.  Will
also update if the keytab failed to authenticate but the default password did work (e.g. after
resetting the account in AD).  Otherwise, exits without doing anything (even if attribute modifying
options are given).  This option is intended for use from a daily crontab to ensure that the password
is rotated regularly.
.TP
--precreate
Pre-create (or update) an account for the given host with default password.  Does not use or update
local keytab.  Requires -h or --computer-name argument.  Implies --user-creds-only.  Generally
requires administrator credentials.
.SH CONNECTION/SETUP OPTIONS
.TP
-b, --base <base>
Specifies a relative LDAP base when creating a new account.  For example, specifying '-b OU=Unix'
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
but the password of the computer account is known.  This password will be changed by msktutil in order 
to create or update the keytab
.TP
-h, --hostname <name>
Overrides the current hostname to be used to be <name>.  If this is not specified, the local host
name will be used.  Note that the local name lookup service will be to qualify and resolve names
into fully-qualified names, including a domain extension.  This affects the default hostname for
other arguments, and the default computer-name.  The hostname is also used to set the dNSDomainName
attribute.
.TP
-k, --keytab <file>
Specifies to use <file> for the keytab.  This option can also be specified by setting the
MSKTUTIL_KEYTAB environment variable to the name of the desired keytab file.  This keytab is both
read from, in order to authenticate as the given account, and written to, after updating the
account password.  Default: /etc/krb5.keytab
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
fail validation.  This is because the IP adddress in the encrypted part of the message cannot be
rewritten in the NAT process.  This option ignores the resulting error for the password change
process, allowing systems outside the NAT firewall to join the domain managed by servers inside
the NAT firewall.
.TP
--realm <realm>
Specifies to use <realm> as kerberos realm.  Default: use the default_realm from [libdefaults] 
section of krb5.conf.
.TP
-N, --no-reverse-lookup
Do not attempt to canonicalize the name of the domain controller via DNS reverse lookups.  You may
need to do this if your client cannot resolve the PTR records for a domain controller or your DNS
servers store incorrect PTR records.  Default: Use DNS reverse lookups to canonicalize DC names.
.TP
--user-creds-only
Don't attempt to authenticate with a keytab: only use user's credentials (from
e.g. kinit).  You may need to do this to modify certain attributes that require Administrator
credentials (description, userAccountControl, userPrincipalName, in a default AD setup).
.TP
--verbose
Enables verbose status messages.  May be specified more then once to get LDAP debugging.

.SH OBJECT TYPE/ATTRIBUTE-SETTING OPTIONS
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
--enctypes <integer>
Sets the supported encryption types in the msDs-supportedEncryptionTypes field.

You may OR together the following values:
  0x1=des-cbc-crc
  0x2=des-cbc-md5
  0x4=rc4-hmac-md5
  0x8=aes128-ctc-hmac-sha1
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
Sets the userPrincipalName on the computer account or service account to be <principal>.  Note that
the realm will automatically be appended to the value given.  The userPrincipalName is an additional
name which can be used to kinit.  This is generally unnecessary, since you can
always authenticate as the name given by --accountname (i.e. computername$ for computer accounts) whether
or not userPrincipalName is set.  Generally requires administrator credentials.
.TP
--set-samba-secret
Use Samba's net changesecretpw command to locally set the machine account password in Samba's secrets.tdb.
$PATH need to include Samba's net command.  Samba needs to be configured appropriately.
.SH EXAMPLES
For unprivileged users the most common invocations are:
.PP
.nf
REPLACE_PROGNAME --update --service host --service HTTP
.fi
.PP
This will update a computer account in Active Directory with a new password, write out a new keytab,
and ensure that it has both "host" and "HTTP" service principals are on it for the hostname.
.PP
.nf
REPLACE_PROGNAME --auto-update
.fi
.PP
This is useful in a daily cron job to check and rotate the password automatically when it's 30 days
old.


For users with admin privileges in AD, some common uses:
.PP
.nf
REPLACE_PROGNAME --create --service host --service HTTP
.fi
.PP
This will create a computer account in Active Directory with a new password, write out a new keytab,
and ensure that it has both "host" and "HTTP" service principals are on it for the hostname.
.PP
.nf
REPLACE_PROGNAME --precreate --host computer1.example.com
.fi
.PP
This will pre-create an account for computer1 with the default password using your credentials.  This
can be done on a central host, e.g. to script the addition of many hosts.  You can then use
REPLACE_PROGNAME --create on the hosts themselves (without special credentials) to join them to the
domain.
.PP
.nf
REPLACE_PROGNAME --host afs --service afs --enctypes 0x03
.fi
.PP
This will create an afs/cell.name@REALM principal, and associate that principal with a computer
account called 'afs'.  The principal will be marked as DES-only, which is required for AFS.
.PP
.nf
REPLACE_PROGNAME --create --use-service-account --service HTTP/hostname.example.com --keytab /etc/apache/krb5.keytab --accountname srv-http --no-pac
.fi
.PP
This will create an HTTP/hostname.example.com@REALM principal, and associate that principal with a service
account called 'srv-http'.  Corresponding Kerberos keys will be written to the keytab file /etc/apache/krb5.keytab.
The size of Kerberos tickets for that service will stay small because no PAC information will be included.
.PP
.nf
REPLACE_PROGNAME --create --service host/hostname --service host/hostname.example.com --set-samba-secret --enctypes 0x4
.fi
.PP
This will create a computer account in Active Directory that is compatible with Samba.  The command creates
a new password, write out a new keytab, and ensure that it includes both "host/hostname" and "host/hostname.example.com"
as service principals (which is equivalent to what setspn.exe -R would do on windows).  The new computer
password will be stored in Samba's secrets.tdb database to provide interoperability with Samba.
As Samba (version 3) only supports arcfour-encrypted Kerberos tickets the --enctypes option must be used
to select only that encryption type.
.SH AUTHOR
REPLACE_AUTHOR
