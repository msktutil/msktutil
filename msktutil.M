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
.PP
There are two common methods of using this program.  The first is to "kinit" with credentials which
have permission to create computer objects in your Active Directory server. If you invoke the
program with such credentials, you can create a new computer account from scratch.
.PP
The second is to pre-create the computer accounts, and then invoke this program on a machine without
any special permissions. When the computer account exists already, REPLACE_PROGNAME will attempt to
authenticate as that account using either the existing keytab, or if that fails, the default
password. It will then change the password and update the keytab appropriately. This is usually the
more convenient option when joining a large number of computers to the domain.
.PP
To pre-create the computer account, you may use the Active Directory Users and Computers GUI, select
"new computer" from the right click menu, and type the short DNS name, then right click on the newly
created object and select "Reset account" to set the password to the default value. Another
alternative is to invoke REPLACE_PROGNAME with the --precreate argument. They both accomplish the
same thing.
.PP
Note: Unlike other kerberos implementations, Active Directory has only a single key for all of the
principals associated with the account. So, if you create a HTTP/hostname service principal, it will
share the same key as the host/hostname principal. If you want to isolate (security-wise) different
service principals, you may want to make extra computer accounts for each of them.
.PP
Also note: kinit -k "host/computername" will not work, by default, even when that is a valid service
principal. Active Directory does not allow you to authenticate as a service principal, so that is
not a valid test of whether your service principal is working. Use kinit -k "computername$" (which
key is also in the keytab) if you need to authenticate as the computer account. You may also use the
--upn argument to set userPrincipalName (requires administrator permissions, not computer account
permissions) to a single additional principal name you'd like to be able to kinit as.
.SH MODES
.TP
-v, --version
Displays version information
.TP
--help
Displays a help message
.TP
-c, --create
Creates a default keytab.  A default keytab contains entries for the local machine's HOST principals.
.TP
-f, --flush
Flushes out all kerberos keytabs from the keytab, and makes corresponding changes to the machine account.
.TP
-u, --update
Forces a change of the machine password, and updates all related service principal entries
.TP
--precreate
Pre-create an account for the given host with default password but do not update local keytab.
Requires -h or --computer-name argument.  Implies --user-creds-only.

.SH OPTIONS
.TP
-b, --base <base>
Specifies a relative LDAP base to use when creating a new machine account.  For example, specifying '-b OU=Unix'
for a computer named SERVER in an Active Directory domain example.com would create a computer account in the LDAP path:
CN=SERVER,OU=Unix,DC=EXAMPLE,DC=COM.  This option can also be specified by setting the MSKTUTIL_LDAP_BASE to the desired
base organizational unit.
.TP
--computer-name <name>

Specifies that the new account should use <name> for the computer account name and the SAM Account
Name.  This option can also be specified by setting the MSKTUTIL_SAM_NAME to the desired SAM Account
Name.  Note that a '$' will be automatically appended to the SAM Account Name.  Defaults to the
machine's hostname, excluding the realm.
.TP
--delegation
Enables the computer account to be trusted for delegation.   This option can also be enabled by setting the 
MSKTUTIL_DELEGATION environment variable.
.TP
--description <text>
Sets the machine account's description field.  This option can also by specified by setting the MSKTUTIL_DESCRIPTION to
the desired text.
.TP
--disable-delegation
Disables the computers account from being trusted for delegation.
.TP
--disable-no-pac
Unsets the flag that disables the KDC's including of a PAC in the machine's service tickets.
.TP
-h, --hostname <name>

Sets the current hostname to be used to be <name>.  If this is not specified, the local host name
will be used.  Note that the local name lookup service will be to qualify and resolve names into
fully-qualified names, including a domain extension.  This option can also be specified by setting
the MSKTUTIL_HOSTNAME environment variable to the desired host name.
.TP
-k, --keytab <file>
Specifies to use <file> for the keytab.  This option can also be specified by setting the MSKTUTIL_INSTANCE environment 
variable to the name of the desired keytab file.
.TP
--no-pac
Specifies that service tickets for this computer account should not contain a PAC.  See Microsoft Knowledge Base
article #832575 for details.   This option can also be specified by setting the MSKTUTIL_NO_PAC environment variable.
.TP
-s, --service <principal>
Specifies a service principal to add to the keytab.
.TP
--server <server>
Specifies to use <server> as the domain controller. This affects both kerberos and ldap operations.
The server can also be specified by setting the MSKTUTIL_SERVER environment variable to the desired
server name.
.TP
--upn <principal>
Sets the User Principal Name on the computer account to be <principal>.  This option can also be specified by setting the
MSKTUTIL_UPN  to the desired User Principal Name.   Note that the realm will automatically be appended to the value given.
.TP
--user-creds-only
Don't attempt to authenticate with machine keytab: only use user's credentials (from e.g. kinit)
.TP
--verbose
Enables verbose status messages
.SH EXAMPLES
The most commonly used option is:
.PP
.nf 
REPLACE_PROGNAME --create
.fi
.PP
This will create/update a computer account in Active Directory, and will create a new keytab file
with a 'host' principal.
.PP
.nf
REPLACE_PROGNAME --precreate --host computer1.example.com
.fi
.PP
This will pre-create an account for computer1 with the default password using the logged in user's
credentials. You can then use REPLACE_PROGNAME --create on the host itself to join the domain.
.PP
.nf
REPLACE_PROGNAME --host afs --service afs --enctypes 0x03
.fi
.PP
This will create an afs/cell.name@REALM principal, and associate that principal with a computer
account called 'afs'.  The principal will be marked as DES-only, which is generally required for
AFS. (Note: Windows 2008R2 has DES disabled by default; you cannot use DES-only keys unless you
have enabled DES encryption for your domain first.)
.SH AUTHOR
REPLACE_AUTHOR
