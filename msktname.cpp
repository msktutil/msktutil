/*
 *----------------------------------------------------------------------------
 *
 * msktname.cpp
 *
 * (C) 2004-2006 Dan Perry (dperry@pppl.gov)
 * (C) 2006 Brian Elliott Finley (finley@anl.gov)
 * (C) 2009-2010 Doug Engert (deengert@anl.gov)
 * (C) 2010 James Y Knight (foom@fuhm.net)
 * (C) 2010-2013 Ken Dreyer <ktdreyer at ktdreyer.com>
 * (C) 2012-2016 Mark Proehl <mark at mproehl.net>
 * (C) 2012-2016 Olaf Flebbe <of at oflebbe.de>
 * (C) 2013-2016 Daniel Kobras <d.kobras at science-computing.de>
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

#if defined(HAVE_LIBUDNS)
#include <udns.h>
#elif defined(HAVE_NS_INITPARSE) && defined(HAVE_RES_SEARCH)
#include <arpa/inet.h>
#include <arpa/nameser.h>
#include <resolv.h>

#if !defined(NS_MAXMSG)
#define NS_MAXMSG 65535
#endif
#endif
#include <netinet/in.h>
#include <cctype>
std::string complete_hostname(const std::string &hostname, bool no_canonical_name)
{
    // Ask the kerberos lib to canonicalize the hostname, and then pull it out of the principal.
    int32_t type = KRB5_NT_SRV_HST;
    krb5_principal temp_princ_raw = NULL;

    // do not canonicalize, use supplied hostname
    if (no_canonical_name) { type = KRB5_NT_UNKNOWN; }

    krb5_error_code ret =
        krb5_sname_to_principal(g_context.get(), hostname.c_str(), "host",
                                type, &temp_princ_raw);
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


std::string get_default_hostname(bool no_canonical_name)
{
    // Ask the kerberos lib to canonicalize the hostname, and then pull it out of the principal.
    int32_t type = KRB5_NT_SRV_HST;
    krb5_principal temp_princ_raw;

    // do not canonicalize, use supplied hostname
    if (no_canonical_name) { type = KRB5_NT_UNKNOWN; }

    krb5_error_code ret =
        krb5_sname_to_principal(g_context.get(), NULL, "host", type, &temp_princ_raw);

    if (ret != 0) {
        throw KRB5Exception("krb5_sname_to_principal (get_default_hostname)", ret);
    }
    KRB5Principal temp_princ(temp_princ_raw);

#ifdef HEIMDAL
    const char *comp = krb5_principal_get_comp_string(g_context.get(), temp_princ.get(), 1);
#else
    krb5_data *comp = krb5_princ_component(g_context.get(), temp_princ.get(), 1);
#endif
    if (comp == NULL) {
        throw Exception("Error: get_default_hostname: couldn't determine hostname, strange value from krb5_sname_to_principal.");
    }
#ifdef HEIMDAL
    return std::string(comp);
#else
    return std::string(comp->data, comp->length);
#endif
}

#if defined(HAVE_NS_INITPARSE) && defined(HAVE_RES_SEARCH)
struct msktutil_dcdata {
    char srvname[NS_MAXDNAME];
    unsigned int priority;
    unsigned int weight;
    unsigned int port;
};

/* A quirk in glibc < 2.9 makes us pick up a symbol marked GLIBC_PRIVATE
 * if we use ns_get16 from libresolv, leading to a broken RPM
 * that can only be installed with --nodeps. As a workaround,
 * use a private version of ns_get16--it's simple enough.
 */
static unsigned int msktutil_ns_get16(const unsigned char *src)
{
    return (unsigned int) (((uint16_t)src[0] << 8) | ((uint16_t)src[1]));
}


static int compare_priority_weight(const void *a, const void *b)
{
    struct msktutil_dcdata *ia = (struct msktutil_dcdata *)a;
    struct msktutil_dcdata *ib = (struct msktutil_dcdata *)b;

    if (ia->priority > ib->priority) {
        return 1;
    }

    if (ia->priority < ib->priority) {
        return -1;
    }

    if (ia->weight > ib->weight) {
        return -1;
    }

    if (ia->weight < ib->weight) {
        return 1;
    }

    return 0;
}
#endif


static std::string get_dc_host_from_srv_rr(const std::string &domain, const std::string &protocol)
{
#if defined(HAVE_LIBUDNS)
    struct dns_ctx *nsctx = NULL;
    std::string dc; // default: empty == error

    dns_reset(NULL);
    if ((nsctx = dns_new(NULL)) != NULL) {
        if (dns_init(nsctx, 1) >= 0) {
            struct dns_rr_srv *srv;

            if ((srv = dns_resolve_srv(nsctx, domain.c_str(), "kerberos",
                                            protocol.c_str(), DNS_NOSRCH)) != NULL) {
                /* determine preferred dc in a really, really pedestrian
                 * fashion to avoid mucking about with separate dcdata
                 * structure, qsort and comparison function */
                struct dns_srv *bestdc = srv->dnssrv_srv;
                int i;

                for (i = 1; i < srv->dnssrv_nrr; i++) {
                    /* dc ist "better" if priority is lower or for equal
                     * priority if weight is higher */
                    if (srv->dnssrv_srv[i].priority < bestdc->priority ||
                        (srv->dnssrv_srv[i].priority == bestdc->priority &&
                         srv->dnssrv_srv[i].weight > bestdc->weight)) {
                        bestdc = &(srv->dnssrv_srv[i]);
                        continue;
                    }
                }

                dc = bestdc->name;
                free(srv);
            }
        }

        dns_close(nsctx);
        free(nsctx);
    }

    return dc;
#elif defined(HAVE_NS_INITPARSE) && defined(HAVE_RES_SEARCH)
    unsigned char response[NS_MAXMSG];
    int len;
    int i;
    int j=0; // my not so smart compiler warns me about: 'j' may be used uninitialized in this function ...
    ns_msg reshandle;
    ns_rr rr;
    struct msktutil_dcdata alldcs[MAX_DOMAIN_CONTROLLERS];
    const std::string krbdnsquery = "_kerberos._" + protocol + "." + domain;

    if ((len=res_search(krbdnsquery.c_str(), ns_c_in, ns_t_srv, response, sizeof(response))) > 0) {
        if (ns_initparse(response,len,&reshandle) >= 0) {
            if ((len=ns_msg_count(reshandle,ns_s_an)) > 0) {
                for (i=0,j=0;i<len && j<MAX_DOMAIN_CONTROLLERS; i++) {
                    if (ns_parserr(&reshandle,ns_s_an,i,&rr)) {
                        // Ignore records we cannot parse, this is non fatal.
                        continue;
                    }
                    if (ns_rr_class(rr) == ns_c_in && ns_rr_type(rr) == ns_t_srv) {
                        // Process DNS SRV RR
                        // TTL Class Type Priority Weight Port Target
                        // _kerberos._tcp.my.realm. 600 IN    SRV  0        10000  88   dcserverXX.my.realm.
                        alldcs[j].priority = msktutil_ns_get16(ns_rr_rdata(rr));
                        alldcs[j].weight   = msktutil_ns_get16(ns_rr_rdata(rr) +   NS_INT16SZ);
                        alldcs[j].port     = msktutil_ns_get16(ns_rr_rdata(rr) + 2*NS_INT16SZ); // we do not really need it...
                        dn_expand(ns_msg_base(reshandle),ns_msg_base(reshandle)+ns_msg_size(reshandle),
                                  ns_rr_rdata(rr) + 3*NS_INT16SZ,
                                  alldcs[j].srvname, sizeof(char)*NS_MAXDNAME);
                        j++;
                    }
                }
            }
        }
    }

    if (j) {
        // and get the 'top' one from the list.
        qsort(&alldcs,j,sizeof(struct msktutil_dcdata),compare_priority_weight);
        return std::string(alldcs[0].srvname,strlen(alldcs[0].srvname));
    }
#endif
    return std::string();
}


std::string get_dc_host(const std::string &realm_name, const std::string &site_name,
                        const bool no_reverse_lookups)
{
    std::string dc;
    struct hostent *host;
    struct sockaddr_in addr;
    struct hostent *hp;
    int sock;
    int i;
    std::string dcsrv;
    std::string protocols[] = { "tcp", "udp" };

    if (!site_name.empty()) {
        for (i = 0; i < (int)(sizeof(protocols) / sizeof(protocols[0])); i++) {
            VERBOSE("Attempting to find site-specific Domain Controller to use via "
                            "DNS SRV record in domain %s for site %s and procotol %s",
                            realm_name.c_str(), site_name.c_str(), protocols[i].c_str());
            dcsrv = get_dc_host_from_srv_rr(site_name + "._sites." + realm_name, protocols[i]);
            if (!dcsrv.empty()) {
                break;
            }
        }
    }

    if (dcsrv.empty()) {
        for (i = 0; i < (int)(sizeof(protocols) / sizeof(protocols[0])); i++) {
            VERBOSE("Attempting to find Domain Controller to use via "
                            "DNS SRV record in domain %s for procotol %s",
                            realm_name.c_str(), protocols[i].c_str());
            dcsrv = get_dc_host_from_srv_rr(realm_name, protocols[i]);
            if (!dcsrv.empty()) {
                break;
            }
        }
    }

    if (dcsrv.empty()) {
        VERBOSE("Attempting to find a Domain Controller to use (DNS domain)");
        dcsrv = realm_name;
    }

    host = gethostbyname(dcsrv.c_str());
    if (!host) {
        fprintf(stderr, "Error: gethostbyname failed \n");
        return "";
    }

    VERBOSE("Found DC: %s", dcsrv.c_str());
    if (no_reverse_lookups) {
        return dcsrv;
    }

    VERBOSE("Canonicalizing DC through forward/reverse lookup...");
    for (i = 0; host->h_addr_list[i]; i++) {
        memcpy(&(addr.sin_addr.s_addr), host->h_addr_list[i], host->h_length);
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
