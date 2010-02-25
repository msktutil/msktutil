.TH REPLACE_PROGNAME 1 REPLACE_VERSION
.SH NAME
REPLACE_PROGNAME \- fetches and manages kerberos keytabs in an Active Directory environment
.SH SYNOPSIS
.B REPLACE_PROGNAME
[command 1] [command 2] [command 3] ...
.SH DESCRIPTION
REPLACE_PROGNAME is a keytab client for a Microsoft Active Directory environment.  This program is
capable of creating an account for this computer in Active Directory, adding service principals to that account,
and creating a local keytab file so that kerberizied services can utilize Active directory as a Kerberos realm.
This utility requires that the Kerberos client libraries are properly installed and configured to use Active
Directory as a realm.
.PP
Whenever a principal is added or the keytab is updated, the secret password for the computer's machine
account is reset.   This password is not stored, so it needs to be reset each time REPLACE_PROGNAME is
executed.  All entries in the keytab will be automatically updated whenever the machine password is
reset.   The previous entries will be left in the keytab, so sessions using the older key versions
will not break.   This behavior is similar to the way Windows hosts handle machine password changes.
.SH CREDENTIALS
.PP
There are two common methods of using this program.  The first is to "kinit" with Administrator-like
credentials which have permission to create computer objects in your Active Directory server. If you
invoke the program with such credentials, you can create a new computer account from scratch.
.PP
The second is to pre-create the computer accounts with such credentials, and then invoke this
program on a machine without any special permissions. When the computer account exists already,
REPLACE_PROGNAME will attempt to authenticate as that account using either the existing keytab, or
if that fails, the default computer password. It will then change the password and update the keytab
appropriately. This is usually the more convenient option when joining many computers to the domain.
.PP
To pre-create the computer account, you may use the Active Directory Users and Computers GUI, select
"new computer" from the right click menu, and type the short DNS name, then right click on the newly
created object and select "Reset account" to set the password to the default value. Another
alternative is to invoke REPLACE_PROGNAME with the --precreate argument. Both methods accomplish the
same thing.
.SH PASSWORD EXPIRY
.PP
Be aware that Windows machines will, by default, automatically change their account password every
30 days, and thus many domains have a 90-day password expiry window, after which your keytab will
stop working. There are two ways to deal with this:

a) (Preferred): Make sure you're running a daily cron job to run REPLACE_PROGNAME --auto-update, which
will change the password automatically 30 days after it was last changed and update the keytab.

b) (Not preferred): disable password expiry for the account via the --dont-expire-password option (or
otherwise setting DONT_EXPIRE_PASSWORD flag in userAccountControl in AD).
.SH OTHER NOTES
.PP
Note: Unlike other kerberos implementations, Active Directory has only a single key for all of the
principals associated with the account. So, if you create a HTTP/hostname service principal, it will
share the same key as the host/hostname principal. If you want to isolate (security-wise) different
service principals, you may want to make a dedicate account for them.
.PP
Also note: kinit -k 'host/computername' *will not work*, by default, even when that is a valid
service principal existing in your keytab. Active Directory does not allow you to authenticate as a
service principal, so do not use that as a test of whether the service principal is working.  If you
actually want to authenticate as the computer account user, kinit -k 'computername$' instead. 

If you really need to be able to authenticate as 'host/computername', you can also use the --upn
argument to set the userPrincipalName attribute (generally requires administrator credentials, not
computer account credentials). Both 'computername$' and the value of userPrincipalName are treated
as valid account names to kinit as.
.SH MODES
.TP
-v, --version
Displays version information
.TP
--help
Displays a help message
.TP
-c, --create
Creates a default keytab. Equivalent to --update --service host.
.TP
-f, --flush
Flushes out all principals for the current hostname from the keytab, and makes corresponding changes to the machine
account.
.TP
-u, --update
Forces a change of the machine password, and updates all related service principal entries from the
servicePrincipalName and userPrincipalName attributes. Always updates dNSDomainName and
supportedEncryptionTypes attributes with current values, and applies other changes as specified.
.TP
--auto-update
Checks if the password is at least 30 days old (from pwdLastSet attribute), and that the account
does not have password expiry disabled. If those conditions are met, acts just like --update. Will
also update if the keytab failed to authenticate but the default password did work. (e.g. after
resetting the account in AD). Otherwise, exits without doing anything (even if attribute modifying
options are given). This option is intended for use from a daily crontab to ensure that the password
is rotated regularly.
.TP
--precreate
Pre-create (or update) an account for the given host with default password. Does not use or update
local keytab.  Requires -h or --computer-name argument.  Implies --user-creds-only. Generally
requires administrator credentials.

.SH CONNECTION/SETUP OPTIONS
.TP
-b, --base <base>
Specifies a relative LDAP base when creating a new machine account. For example, specifying '-b
OU=Unix' for a computer named SERVER in an Active Directory domain example.com would create a
computer account in the LDAP path: CN=SERVER,OU=Unix,DC=EXAMPLE,DC=COM.  This option can also
be specified by setting the MSKTUTIL_LDAP_BASE environment variable to the desired value.

If not specified, the default value is read from AD (and the default there, unless modified by an
admin, is CN=Computers).
.TP
--computer-name <name>
Specifies that the new account should use <name> for the computer account name and the SAM Account
Name.  Note that a '$' will be automatically appended to the SAM Account Name.  Defaults to the
machine's hostname, excluding the realm, with dots replaced with dashes.

That is: if the realm is EXAMPLE.COM, and the hostname is FOO.EXAMPLE.COM, the default computer name
is FOO. If the hostname is FOO.BAR.EXAMPLE.COM, the default computer name is FOO-BAR.
.TP
-h, --hostname <name>
Overrides the current hostname to be used to be <name>.  If this is not specified, the local host
name will be used.  Note that the local name lookup service will be to qualify and resolve names
into fully-qualified names, including a domain extension.  This affects the default hostname for
other arguments, and the default computer-name. The hostname is also used to set the dNSDomainName
attribute.
.TP
-k, --keytab <file>
Specifies to use <file> for the keytab.  This option can also be specified by setting the
MSKTUTIL_KEYTAB environment variable to the name of the desired keytab file. This keytab is both
read from, in order to authenticate as the computer account, and written to, after updating the
account password. Default: /etc/krb5.keytab
.TP
--server <server>
Specifies to use <server> as the domain controller. This affects both kerberos and ldap operations.
The server can also be specified by setting the MSKTUTIL_SERVER environment variable. Default:
looked up in DNS from the realm name.
.TP
--user-creds-only
Don't attempt to authenticate with machine keytab: only use user's credentials (from
e.g. kinit). You may need to do this to modify certain attributes that require Administrator
credentials (description, userAccountControl, userPrincipalName, in a default AD setup).
.TP
--verbose
Enables verbose status messages

.SH ATTRIBUTE SETTING OPTIONS
.TP
--delegation
Enables the computer account to be trusted for delegation.  This option can also be enabled by
setting the MSKTUTIL_DELEGATION environment variable. This modifies the userAccountControl
attribute. Generally requires administrator credentials.
.TP
--description <text>
Sets the machine account's description attribute to the given text (or removes if text
is ''). Generally requires administrator credentials.
.TP
--disable-delegation
Disables the computers account from being trusted for delegation.  This modifies the
userAccountControl attribute. Generally requires administrator credentials.
.TP
--disable-no-pac
Unsets the flag that disables the KDC's including of a PAC in the machine's service tickets.  This
modifies the userAccountControl attribute. Generally requires administrator credentials.
.TP
--dont-expire-password
Sets the DONT_EXPIRE_PASSSWORD bit in the userAccountControl attribute, which disables password
expiry for this account.  If you don't run a cron job to periodically rotate the keytab, you will
want to set this flag. Generally requires administrator credentials.
.TP
--do-expire-password
Unsets the DONT_EXPIRE_PASSWORD flag in the userAccountControl attribute. Generally requires
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
Specifies that service tickets for this computer account should not contain a PAC.  This modifies
the userAccountControl attribute. See Microsoft Knowledge Base article #832575 for details.  This
option can also be specified by setting the MSKTUTIL_NO_PAC environment variable. Generally requires
administrator credentials.
.TP
-s, --service <principal>
Specifies a service principal to add to the account (and thus keytab, if appropriate). The service is of
the form <service>/<hostname>.  If the hostname is omitted, assumes current hostname.
.TP
--remove-service <principal>
Specifies a service principal to remove from the account (and keytab if appropriate).
.TP
--upn <principal>
Sets the userPrincipalName on the computer account to be <principal>.  Note that the realm will
automatically be appended to the value given. The userPrincipalName is an additional name which can
be used to kinit. This is generally unnecessary, since you can always authenticate as COMPUTERNAME$
whether or not userPrincipalName is set. Generally requires administrator credentials.

.SH EXAMPLES
For unprivileged users the most common invocations are:
.PP
.nf
REPLACE_PROGNAME -u -s host -s HTTP
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
REPLACE_PROGNAME --precreate --host computer1.example.com
.fi
.PP
This will pre-create an account for computer1 with the default password using your credentials. This
can be done on a central host, e.g. to script the addition of many hosts. You can then use
REPLACE_PROGNAME --create on the hosts themselves (without special credentials) to join them to the
domain.
.PP
.nf
REPLACE_PROGNAME --host afs --service afs --enctypes 0x03
.fi
.PP
This will create an afs/cell.name@REALM principal, and associate that principal with a computer
account called 'afs'.  The principal will be marked as DES-only, which at least was required for
AFS in the past (is this really *still* true in 2010?).
.SH AUTHOR
REPLACE_AUTHOR
