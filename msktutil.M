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
This utility requires thatthe Kerberos client libraries are properly installed and configured to use Active 
Directory as a realm.
.PP 
Whenever a principal is added or the keytab is updated, the secret password for the computer's machine
account is reset.   This password is not stored, so it needs to be reset each time REPLACE_PROGNAME is
executed.  All entries in the keytab will be automatically updated whenever the machine password is
reset.   The previous entries will be left in the keytab, so sessions using the older key versions
will not break.   This behavior is similar to the way Windows hosts handle machine password changes.
.SH OPTIONS
.TP
-b <base>
Specifies a relative LDAP base to use when creating a new machine account.  For example, specifying '-b OU=Unix'
for a computer named SERVER in an Active Directory domain example.com would create a computer account in the LDAP path:
CN=SERVER,OU=Unix,DC=EXAMPLE,DC=COM.  This option can also be specified by setting the MSKTUTIL_LDAP_BASE to the desired
base organizational unit.
.TP
--base <base>
Same as -b <base>
.TP
-c
Creates a default keytab.  A default keytab contains entries for the local machine's HOST principals.
.TP
--create
Same as -c
.TP
--computer-name <name>
Specifies that the new account should use <name> for thecomputer account name and the SAM Account Name.  This option can also be 
specified by setting the MSKTUTIL_SAM_NAME to the desired SAM Account Name.  Note that a '$' will be automatically appended to the 
SAM Account Name.
.TP
-d
Specifies the machine's account should be flagged as DES-only.  This forces all keys to only be generated using DES
encryption.  This option can also be enabled by setting the MSKTUTIL_DES_ONLY environment variable.
.TP
--delegation
Enables the computer account to be trusted for delegation.   This option can also be enabled by setting the 
MSKTUTIL_DELEGATION environment variable.
.TP
--des-only
Same as -d
.TP
--description <text>
Sets the machine account's description field.  This option can also by specified by setting the MSKTUTIL_DESCRIPTION to
the desired text.
.TP
--disable-delegation
Disables the computers account from being trusted for delegation.
.TP
--disable-des-only
Sets the machine's account not to be  flagged as DES-only.
.TP
--disable-no-pac
Unsets the flag that disables the KDC's including of a PAC in the machine's service tickets.
.TP
-f
Flushes out all kerberos keytabs from the keytab, and makes corresponding changes to the machine account.
.TP
--flush
Same as -f
.TP
-h <name>
Sets the current hostname to be used to be <name>.   If this is not specified, the local host name will be used.  Note that 
the local name lookup service will be to qualify and resolve names into fully-qualified names, including a domain extension.
This option MUST be specified in all cases except when using '--create' or a similiar command.   This option can also be specified
by setting the MSKTUTIL_HOSTNAME environment variable to the desired host name.
.TP
--help
Same as -?
.TP
--host <name>
Same as -h <name>
.TP
--hostname
Same as -h <name>
.TP
-k <file>
Specifies to use <file> for the keytab.  This option can also be specified by setting the MSKTUTIL_INSTANCE environment 
variable to the name of the desired keytab file.
.TP
--keytab <file>
Same as -k <file>
.TP
--no-pac
Specifies that service tickets for this computer account should not contain a PAC.  See Microsoft Knowledge Base
article #832575 for details.   This option can also be specified by setting the MSKTUTIL_NO_PAC environment variable.
.TP
-s <principal>
Specifies a service principal to add to the keytab.
.TP
--server <server>
Specifies to use <server> for the ldap operations.  To control which server is used for the kerberos operations, 
you will need to manually adjust krb5.conf.  The server can also be specified by setting the MSKTUTIL_SERVER 
environment variable to the desired server name.
.TP
--service <principal>
Same as -s <principal>
-u
Forces a change of the machine password, and updates all related service principal entries
.TP
--update
Same as -u
.TP
--upn <principal>
Sets the User Principal Name on the computer account to be <principal>.  This option can also be specified by setting the
MSKTUTIL_UPN  to the desired User Principal Name.   Note that the realm will automatically be appended to the value given.
.TP
--usage
Same as -?
.TP
-v
Displays version information
.TP
--verbose
Enables verbose status messages
.TP
--version
Same as -v
.TP
-?
Displays a help message
.TP
--?
Same as -?
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
REPLACE_PROGNAME --host afs --upn afs/cell.name --des-only
.fi
.PP
This will create an afs/cell.name@REALM principal, and associate that principal with a computer 
account called 'afs'.  The principal will be marked as DES-only, which is generally required for 
AFS.
.SH AUTHOR
REPLACE_AUTHOR
