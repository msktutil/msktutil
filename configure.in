# Process this file with autoconf to produce a configure script.

AC_PREREQ(2.53)
AC_INIT(msktutil, 1.1)
AC_CONFIG_HEADER([config.h])

PACKAGE_DATE="June 25, 2018"
PACKAGE_AUTHOR="Mark Pröhl, Olaf Flebbe, Daniel Kobras, Michael Osipov"
AC_SUBST(PACKAGE_DATE)
AC_SUBST(PACKAGE_AUTHOR)


# Checks for programs.
AC_PROG_CC
AC_PROG_CXX
AC_LANG(C++)
AC_PATH_PROGS(INSTALL, install)
AC_PATH_PROGS(CAT, cat)
AC_PATH_PROGS(RM, rm)
AC_PATH_PROGS(CP, cp)
AC_PATH_PROGS(ECHO, echo)
AC_PATH_PROGS(SED, sed)
AC_PATH_PROGS(MKDIR, mkdir)
AC_SUBST(WARNFLAGS)

AC_ARG_WITH(mandir,
[  --with-mandir=DIR       Where to put man pages ($mandir)],
[ mandir="$withval" ])

AC_ARG_WITH(krb5,
[  --with-krb5=<auto/mit/heimdal>
                          Which krb5 implementation to use (default: auto-detect)],
[ krb5="$withval" ], [ krb5="auto" ] )

AC_ARG_WITH(krb5dir,
[  --with-krb5dir=DIR      Where to find the Kerberos 5 includes and libraries],
[ krb5dir="$withval" ])

AC_ARG_WITH(krb5-config,
[  --with-krb5-config=DIR  Where to find the Kerberos 5 configuration script],
[ krb5config="$withval" ])

AC_ARG_WITH(ldapdir,
[  --with-ldapdir=DIR      Where to find the LDAP includes and libraries],
[ ldapdir="$withval" ])

AC_ARG_WITH(sasldir,
[  --with-sasldir=DIR      Where to find the SASL includes and libraries],
[ sasldir="$withval" ])

AC_ARG_WITH(tmpdir,
[  --with-tmpdir=DIR       What temporary directory to use],
[ tmpdir="$withval" ])

AC_ARG_WITH(udns,
[  --with-udns=<yes/no/DIR> Whether to use and where to find the udns includes and libraries (default: check)],
[ udns="$withval" ], [ udns=check ] )
AC_ARG_WITH(static-udns,
[  --with-static-udns      Whether to link udns statically (default: no)],
[ udnsstatic=yes ], [ udnsstatic=no ] )

# If krb5-config was not specified, try to find it ourselves.
AS_IF([test -z "$krb5config"],
	[AC_PATH_PROG([PATH_KRB5_CONFIG], [krb5-config] [],
		[${PATH}:/usr/kerberos/bin])
	[ krb5config="$PATH_KRB5_CONFIG"]
])

if test x$GCC = xyes ; then
  WARNFLAGS="-Wall -Wextra -Wno-write-strings"
fi

if test -x "$krb5config"; then
  KRB5_CPPFLAGS=`$krb5config --cflags 2>/dev/null`
  KRB5_LIBS=`$krb5config --libs 2>/dev/null`
  CPPFLAGS="$CPPFLAGS $KRB5_CPPFLAGS"
  LIBS="$LIBS $KRB5_LIBS"
else
  AC_MSG_WARN([Could not find a krb5-config program.])
fi

if test "$krb5dir" != ""; then
  if test -d "$krb5dir/include"; then
     CPPFLAGS="$CPPFLAGS -I$krb5dir/include"
  fi  
  if test -d "$krb5dir/lib"; then
     LDFLAGS="$LIBDIRS -L$krb5dir/lib"
  fi
fi
if test "$ldapdir" != ""; then
  if test "$ldapdir" != "$krb5dir"; then
    CPPFLAGS="-I$ldapdir/include $CPPFLAGS"
    LDFLAGS="-L$ldapdir/lib $LDFLAGS"
  fi
fi
if test "$sasldir" != ""; then
  if test "$sasldir" != "$krb5dir"; then
    if test "$sasldir" != "$ldapdir"; then
      CPPFLAGS="-I$sasldir/include $CPPFLAGS"
      LDFLAGS="-L$sasldir/lib $LDFLAGS"
    fi
  fi
fi
if test "$tmpdir" != ""; then
  CPPFLAGS="$CPPFLAGS -DTMP_DIR=\\\"$tmpdir\\\""
fi

case "$udns" in
  no|yes|check) ;;
  *)
    if test "$udns" != "$krb5dir" && test "$udns" != "$ldapdir" && test "$udns" != "$sasldir" ; then
      if test -d "$udns/include"; then
        CPPFLAGS="-I$udns/include $CPPFLAGS"
      else
        # udns source dir, put include path extension last since otherwise
        # udns's config.h will be found first and msktutil's build will fail
        CPPFLAGS="-I$udns $CPPFLAGS"
      fi
      if test -d "$udns/lib"; then
        LDFLAGS="-L$udns/lib $LDFLAGS"
      else
        LDFLAGS="-L$udns $LDFLAGS"
      fi
    fi
    ;;
esac

AC_CHECK_HEADERS([krb5.h com_err.h])
if test "$ac_cv_header_krb5_h" = "no"; then
  AC_MSG_ERROR([This program cannot be built without krb5.h])
fi

# Fedora, RHEL, Centos has com_err.h in /usr/include/et
AC_CHECK_HEADERS([et/com_err.h])
if test "$ac_cv_header_et_com_err_h" = "yes"; then
   CPPFLAGS="-I/usr/include/et $CPPFLAGS"
   AC_DEFINE(HAVE_COM_ERR_H, 1)
fi

# We only ever directly include krb5.h, so the only reason to check for
# Heimdal-specific heim_err.h is to distinguish which implementation we use.
# We can entirely skip this check if the krb5 implementation has bee given
# explicitly, ie. krb5 is set to anything but "auto".
case "$krb5" in
mit|heimdal) ;;
auto) krb5="mit"; AC_CHECK_HEADERS([heim_err.h heimdal/heim_err.h], [krb5="heimdal"; break]) ;;
*) AC_MSG_ERROR([invalid parameter for --with-krb5]) ;;
esac

AC_MSG_CHECKING([krb5 implementation])
AC_MSG_RESULT([$krb5])

if test "$krb5" = "heimdal"; then
    AC_DEFINE(HEIMDAL, 1, [defined if the kerberos is heimdal])
fi

AC_CHECK_HEADERS([sasl.h])
if test "$ac_cv_header_sasl_h" = "no"; then
  AC_CHECK_HEADERS([sasl/sasl.h])
  if test "$ac_cv_header_sasl_sasl_h" = "no"; then
    AC_MSG_ERROR([This program cannot be built without sasl.h])
  fi
fi

if test "$udns" != "no"; then
  AC_CHECK_HEADERS([udns.h])
  if test "$ac_cv_header_udns_h" = "no"; then
    if test "$udns" != "check"; then
      AC_MSG_ERROR([udns requested but udns.h not found])
    fi
    udns=no
  fi
fi

if test "$udns" != "no"; then
  if test "$udnsstatic" != "no"; then
    # FIXME: Only works with GNU ld :-(
    LIBS="$LIBS -Wl,-Bstatic -ludns -Wl,-Bdynamic"
    AC_MSG_CHECKING([for dns_new in statically linked -ludns])
    AC_LINK_IFELSE([AC_LANG_PROGRAM([[
#include <udns.h>
    ]],[[
      dns_new(0);
    ]])],
    [ AC_DEFINE(HAVE_LIBUDNS, 1)
    AC_MSG_RESULT([yes])], [
    if test "$udns" != "check"; then
      AC_MSG_ERROR([static link to udns requested but static libudns not found])
    fi
    udns=no])
  else
    AC_CHECK_LIB([udns], [dns_new], , [
      if test "$udns" != "check"; then
        AC_MSG_ERROR([udns requested but libudns not found])
      fi
      udns=no])
  fi
fi

if test "$udns" = "no"; then
# look for resolver functions
# see if ns_initparse is simply in libc or libresolv
AC_SEARCH_LIBS([ns_initparse], [resolv], AC_DEFINE(HAVE_NS_INITPARSE, 1, [defined if ns_initparse can be used]) , [
	# On Linux it actually is in libresolv but prefixed with __ when
	# linking dynamically. This is taken care of by actually including the
	# right headers and trying again.
	AC_MSG_CHECKING([for ns_initparse])
	AC_LINK_IFELSE([AC_LANG_PROGRAM([[
#include <netinet/in.h>
#include <arpa/nameser.h>
#include <resolv.h>
		]],[[
	ns_initparse(0, 0, 0);
		]])],
		AC_MSG_RESULT([yes]), [
		# now try libresolv again
		AC_MSG_RESULT([no])
		saved_LIBS="$LIBS"
		LIBS="$LIBS -lresolv"
		AC_MSG_CHECKING([for ns_initparse in -lresolv])
		AC_LINK_IFELSE([AC_LANG_PROGRAM([[
#include <netinet/in.h>
#include <arpa/nameser.h>
#include <resolv.h>
			]],[[
	ns_initparse(0, 0, 0);
			]])],
			[ AC_DEFINE(HAVE_NS_INITPARSE,1)
			AC_MSG_RESULT([yes])], [
			# glibc versions prior to 2.9 include ns_initparse in
			# libresolve but do not export it. Try to circumvent
			# this restriction by linking the missing bits statically.
			AC_MSG_RESULT([no])
			LIBS="$saved_LIBS -lresolv -Wl,-Bstatic -lresolv -Wl,-Bdynamic"
			AC_MSG_CHECKING([for ns_initparse in statically linked -lresolv])
			AC_LINK_IFELSE([AC_LANG_PROGRAM([[
#include <netinet/in.h>
#include <arpa/nameser.h>
#include <resolv.h>
				]],[[
	ns_initparse(0, 0, 0);
				]])],
				[AC_DEFINE(HAVE_NS_INITPARSE,1)
				AC_MSG_RESULT([yes])],
				[LIBS="$saved_LIBS"
				AC_MSG_RESULT([no])])])])])

# finally check if res_search is present as well just as a sanity check
AC_MSG_CHECKING([for res_search])
AC_LINK_IFELSE([AC_LANG_PROGRAM([[
#include <netinet/in.h>
#include <arpa/nameser.h>
#include <resolv.h>
	]],[[
	res_search(0, 0, 0, 0, 0);
	]])],
	[
	AC_DEFINE(HAVE_RES_SEARCH, 1, [defined if res_search can be used])
	AC_MSG_RESULT([yes])],
	AC_MSG_RESULT([no]))
fi

# Solaris support, http://stackoverflow.com/questions/1630225/what-is-the-canonical-way-to-make-autoconf-link-in-solaris-network-libraries
AC_SEARCH_LIBS([gethostbyname], [nsl])
AC_SEARCH_LIBS([socket], [socket], [], [
               AC_CHECK_LIB([socket], [socket], [LIBS="-lsocket -lnsl $LIBS"],
              [], [-lnsl])])
# Checks for libraries.
AC_CHECK_LIB([ldap], [ldap_search_ext_s], , [AC_MSG_ERROR([libldap not found])])
#
# OpenLDAP's LDAP_OPT_ON macro uses ber_pvt_opt_on. In newer OpenLDAP
# versions, we have to explicitly link with lber.
#
AC_CHECK_LIB([lber], [ber_pvt_opt_on], , [AC_MSG_ERROR([liblber not found])])
#AC_CHECK_LIB([com_err], [error_message], , [AC_MSG_ERROR([libcom_err not found])])
#
# LDAP_OPT_DIAGNOSTIC_MESSAGE is present from OpenLDAP 2.4 upwards, only.
AC_CHECK_DECLS([LDAP_OPT_DIAGNOSTIC_MESSAGE], [], [], [[#include <ldap.h>]])

if test "$ac_cv_header_com_err_h"; then
AC_MSG_CHECKING([whether com_err.h needs extern "C"]);

AC_LINK_IFELSE([AC_LANG_SOURCE([
#include <stdlib.h>
#include <com_err.h>

int main(void) {
    error_message(0);
}
])], [AC_MSG_RESULT(no); com_err_needs_extern_c=no], [

AC_LINK_IFELSE([AC_LANG_SOURCE([
#include <stdlib.h>
extern "C" {
#include <com_err.h>
}

int main(void) {
    error_message(0);
}
])], [AC_MSG_RESULT(yes); com_err_needs_extern_c=yes], [AC_MSG_ERROR([Couldn't get error_message to work.])])])

if test "$com_err_needs_extern_c=yes"; then
  AC_DEFINE(COM_ERR_NEEDS_EXTERN_C, 1, [Does com_err.h need extern "C" around it?])
fi
fi

# Check for functions
AC_CHECK_FUNCS(vasprintf vsnprintf setenv strtoll ldap_initialize)

# Check that the AES enctypes are found
AC_CHECK_DECLS([ENCTYPE_AES256_CTS_HMAC_SHA1_96, ENCTYPE_AES128_CTS_HMAC_SHA1_96], [], [], [[#include <krb5.h>]])

AC_CONFIG_FILES([Makefile])
AC_OUTPUT
