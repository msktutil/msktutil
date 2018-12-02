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

samba_msg() {
echo "$0: Error: "
echo "       Adjust your SAMBA configuration first in /etc/samba/smb.conf"
echo "       [global] section must contain at least following directives:"
echo "       security  = ADS"
echo "       workgroup = $WORKGROUP" 
}

[ "$UID" -ne 0 ] && echo "$0 must be run as root." && exit 1

[ "x$WORKGROUP" == "x" ] && echo "$0: Error WORKGROUP not set" && exit 1

[ "x$DCHOST" == "x" ] && echo "$0: Error DCHOST not set" && exit 1

if [ ! -x $TDBTOOL ] || [ ! -x $NET ]; then
   echo "Error: tdbtool and net SAMBA utilities are not installed."
   exit 1
fi

$TESTPARM -l -s --parameter-name workgroup 2>/dev/null | /usr/bin/grep -q -x "$WORKGROUP"

[ $? -ne 0 ] && samba_msg && exit 1

$TESTPARM -l -s --parameter-name security 2>/dev/null | /usr/bin/grep -q -x "ADS"

[ $? -ne 0 ] && samba_msg && exit 1

$NET -k -P rpc getsid -S $DCHOST

[ $? -ne 0 ] && echo "$0: Error running $NET getsid" && exit 1

$TDBTOOL /var/lib/samba/private/secrets.tdb store SECRETS/MACHINE_LAST_CHANGE_TIME/"$WORKGROUP" 0000 2>/dev/null 1>/dev/null

[ $? -ne 0 ] && echo "$0: Error running $TDBTOOL (1)" && exit 1

$TDBTOOL /var/lib/samba/private/secrets.tdb store SECRETS/MACHINE_PASSWORD.PREV/"$WORKGROUP" none 2>/dev/null 1>/dev/null

[ $? -ne 0 ] && echo "$0: Error running $TDBTOOL (2)" && exit 1

$TDBTOOL /var/lib/samba/private/secrets.tdb store SECRETS/MACHINE_PASSWORD/"$WORKGROUP" none 2>/dev/null 1>/dev/null

[ $? -ne 0 ] && echo "$0: Error running $TDBTOOL (3)" && exit 1

exec $NET changesecretpw -f -i




