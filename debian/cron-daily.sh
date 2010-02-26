#!/bin/sh

test -x /usr/sbin/msktutil || exit 0

# These options are overridden in /etc/default/msktutil.
# Edit there, not here.
AUTOUPDATE_ENABLED="false"
AUTOUPDATE_OPTIONS=""

[ -r /etc/default/msktutil ] && . /etc/default/msktutil

[ "$AUTOUPDATE_ENABLED" = "true" ] || exit 0
exec /usr/sbin/msktutil --auto-update $AUTOUPDATE_OPTIONS
