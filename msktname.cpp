/*
 *----------------------------------------------------------------------------
 *
 * msktname.c
 *
 * (C) 2004-2006 Dan Perry (dperry@pppl.gov)
 * (C) 2010 James Y Knight (foom@fuhm.net)
 *
    This program is free software; you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation; either version 2 of the License, or
    (at your option) any later version.

    This program is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.

    You should have received a copy of the GNU General Public License
    along with this program; if not, write to the Free Software
    Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA  02110-1301  USA
 *
 *-----------------------------------------------------------------------------
 */

#include "msktutil.h"


std::string complete_hostname(const std::string &hostname)
{
    // Ask the kerberos lib to canonicalize the hostname, and then pull it out of the principal.
    krb5_principal temp_princ_raw = NULL;
    krb5_error_code ret =
        krb5_sname_to_principal(g_context.get(), hostname.c_str(), "host",
                                KRB5_NT_SRV_HST, &temp_princ_raw);
    if (ret != 0) {
        fprintf(stderr, "Warning: hostname canonicalization for %s failed (%s)\n",
                hostname.c_str(), error_message(ret));
        return hostname;
    }

    KRB5Principal temp_princ(temp_princ_raw);

#ifdef HEIMDAL
    const char *comp = krb5_principal_get_comp_string(g_context.get(), temp_princ.get(), 1);
#else
    krb5_data *comp = krb5_princ_component(g_context.get(), temp_princ.get(), 1);
#endif
    if (comp == NULL) {
        std::string name(temp_princ.name());
        fprintf(stderr, "Warning: hostname canonicalization for %s failed: returned unexpected principal %s\n", hostname.c_str(), name.c_str());
        return hostname;
    }
#ifdef HEIMDAL
    return std::string(comp);
#else
    return std::string(comp->data, comp->length);
#endif
}


std::string get_default_hostname()
{
    // Ask the kerberos lib to canonicalize the hostname, and then pull it out of the principal.
    krb5_principal temp_princ_raw;
    krb5_error_code ret =
        krb5_sname_to_principal(g_context.get(), NULL, "host", KRB5_NT_SRV_HST, &temp_princ_raw);
    if (ret != 0)
        throw KRB5Exception("krb5_sname_to_principal (get_default_hostname)", ret);

    KRB5Principal temp_princ(temp_princ_raw);

#ifdef HEIMDAL
    const char *comp = krb5_principal_get_comp_string(g_context.get(), temp_princ.get(), 1);
#else
    krb5_data *comp = krb5_princ_component(g_context.get(), temp_princ.get(), 1);
#endif
    if (comp == NULL)
        throw Exception("Error: get_default_hostname: couldn't determine hostname, strange value from krb5_sname_to_principal.");

#ifdef HEIMDAL
    return std::string(comp);
#else
    return std::string(comp->data, comp->length);
#endif
}


std::string get_dc_host(const std::string &realm_name)
{
    std::string dc;
    struct hostent *host;
    struct sockaddr_in addr;
    struct hostent *hp;
    int sock;
    int i;


    VERBOSE("Attempting to find a Domain Controller to use");
    host = gethostbyname(realm_name.c_str());
    if (!host) {
        fprintf(stderr, "Error: gethostbyname failed \n");
        return "";
    }

    for (i = 0; host->h_addr_list[i]; i++) {
        memcpy(&(addr.sin_addr.s_addr), host->h_addr_list[i], sizeof(host->h_addr_list[i]));
        hp = gethostbyaddr((char *) &addr.sin_addr.s_addr, sizeof(addr.sin_addr.s_addr), AF_INET);
        if (!hp) {
            fprintf(stderr, "Error: gethostbyaddr failed \n");
            continue;
        }

        /* Now let's try and open and close a socket to see if the domain controller is up or not */
        addr.sin_family = AF_INET;
        addr.sin_port = htons(LDAP_PORT);
        sock = socket(AF_INET, SOCK_STREAM, 0);
        connect(sock, (struct sockaddr *) &addr, 2);
        if (sock) {
            close(sock);
            /* See if this is the 'lowest' domain controller name... the idea is to always try to
             * use the same domain controller.   Things may become inconsitent otherwise */
            if (dc.empty()) {
                dc = std::string(hp->h_name);
            } else {
                if (0 > dc.compare(hp->h_name)) {
                    dc = std::string(hp->h_name);
                }
            }
        }
    }
    endhostent();

    VERBOSE("Found Domain Controller: %s", dc.c_str());
    return dc;
}


std::string get_host_os()
{
    struct utsname info;
    int ret;


    ret = uname(&info);
    if (ret == -1) {
        fprintf(stderr, "Error: uname failed (%d)\n", ret);
        return NULL;
    }
    return std::string(info.sysname);
}


std::string get_short_hostname(msktutil_flags *flags)
{
    std::string long_hostname = flags->hostname;

    for(std::string::iterator it = long_hostname.begin();
        it != long_hostname.end(); ++it)
        *it = std::tolower(*it);

    std::string short_hostname = long_hostname;

    size_t dot = std::string::npos;
    while ((dot = long_hostname.find('.', dot + 1)) != std::string::npos) {
        if (long_hostname.compare(dot + 1, std::string::npos, flags->lower_realm_name) == 0) {
            short_hostname = long_hostname.substr(0, dot);
            break;
        }
    }

    /* Replace any remaining dots with dashes */
    for (size_t i = 0; i < short_hostname.length(); ++i) {
        if (short_hostname[i] == '.') {
            short_hostname[i] = '-';
        }
    }

    VERBOSE("Determined short hostname: %s", short_hostname.c_str());
    return short_hostname;
}
