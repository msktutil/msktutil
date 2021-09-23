#!/bin/bash
#
# Workaround for https://github.com/msktutil/msktutil/issues/124 
#
# for Samba 4.7 (RHEL/CentOS 7)
#
# 22.09.2018 jaroslaw.polok@gmail.com
#
# Usage:
#
#   msktutil --set-samba-secret --use-samba-cmd /path/to/this/script
#
#   MSKTUTIL_SAMBA_CMD=/pat/tp/this/script msktutil --set-samba-secret
#

#
# Samba workgroup (UPPERCASE)
# WORKGROUP="MYWORKGROUP"
#

WORKGROUP=""

#
# Active Directory Domain Controller to query for Domain SID
# DCHOST="mydc.my.domain"
#

DCHOST=""

#
# Samba utilities used.
# (RHEL/CentOS 7: tdb-tools and samba-common-tools rpms)
#

TDBTOOL="/usr/bin/tdbtool"
NET="/usr/bin/net"
TESTPARM="/usr/bin/testparm"

err_exit() {
    echo "$0: Error in line $1: $ERR_MSG" >&2
}

SAMBA_MSG="Invalid Samba configuration
   Adjust your SAMBA configuration first in /etc/samba/smb.conf
   [global] section must contain at least following directives:
   security  = ADS
   workgroup = $WORKGROUP"

trap 'err_exit $LINENO' EXIT

set -e

ERR_MSG="must be run as root."
[ "$UID" -eq 0 ]

ERR_MSG="WORKGROUP not set"
[ "x$WORKGROUP" != "x" ]

ERR_MSG="DCHOST not set"
[ "x$DCHOST" != "x" ]

ERR_MSG="tdbtool and net SAMBA utilities are not installed."
[ -x "$TDBTOOL" ] && [ -x "$NET" ]

ERR_MSG="$SAMBA_MSG"
"$TESTPARM" -l -s --parameter-name workgroup 2>/dev/null | /usr/bin/grep -q -x "$WORKGROUP"
"$TESTPARM" -l -s --parameter-name security 2>/dev/null | /usr/bin/grep -q -x "ADS"

ERR_MSG="$NET getsid failed"
"$NET" -k -P rpc getsid -S "$DCHOST"

ERR_MSG="$TDBTOOL failed"
"$TDBTOOL" /var/lib/samba/private/secrets.tdb store SECRETS/MACHINE_LAST_CHANGE_TIME/"$WORKGROUP" 0000 2>/dev/null 1>/dev/null
"$TDBTOOL" /var/lib/samba/private/secrets.tdb store SECRETS/MACHINE_PASSWORD.PREV/"$WORKGROUP" none 2>/dev/null 1>/dev/null
"$TDBTOOL" /var/lib/samba/private/secrets.tdb store SECRETS/MACHINE_PASSWORD/"$WORKGROUP" none 2>/dev/null 1>/dev/null

ERR_MSG="$NET changesecretpw failed"
exec "$NET" changesecretpw -f -i

