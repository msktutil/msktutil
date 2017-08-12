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
 * (C) 2012-2017 Mark Proehl <mark at mproehl.net>
 * (C) 2012-2017 Olaf Flebbe <of at oflebbe.de>
 * (C) 2013-2017 Daniel Kobras <d.kobras at science-computing.de>
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

#include <algorithm>
#include <cctype>

std::string complete_hostname(const std::string &hostname,
                              bool no_canonical_name)
{
    /* Ask the kerberos lib to canonicalize the hostname, and then
     * pull it out of the principal. */
    int32_t type = KRB5_NT_SRV_HST;
    krb5_principal temp_princ_raw = NULL;

    /* do not canonicalize, use supplied hostname */
    if (no_canonical_name) {
        type = KRB5_NT_UNKNOWN;
    }

    krb5_error_code ret = krb5_sname_to_principal(g_context,
                                                  hostname.c_str(),
                                                  "host",
                                                  type,
                                                  &temp_princ_raw);
    if (ret != 0) {
        fprintf(stderr,
                "Warning: hostname canonicalization for %s failed (%s)\n",
                hostname.c_str(),
                error_message(ret)
            );
        return hostname;
    }

    KRB5Principal temp_princ(temp_princ_raw);

#ifdef HEIMDAL
    const char *comp = krb5_principal_get_comp_string(g_context,
                                                      temp_princ.get(),
                                                      1);
#else
    krb5_data *comp = krb5_princ_component(g_context,
                                           temp_princ.get(),
                                           1);
#endif
    if (comp == NULL) {
        std::string name(temp_princ.name());
        fprintf(stderr,
                "Warning: hostname canonicalization for %s failed: returned "
                "unexpected principal %s\n",
                hostname.c_str(),
                name.c_str()
            );
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
    /* Ask the kerberos lib to canonicalize the hostname, and then
     * pull it out of the principal. */
    int32_t type = KRB5_NT_SRV_HST;
    krb5_principal temp_princ_raw;

    /* do not canonicalize, use supplied hostname */
    if (no_canonical_name) { type = KRB5_NT_UNKNOWN; }

    krb5_error_code ret = krb5_sname_to_principal(g_context,
                                                  NULL,
                                                  "host",
                                                  type,
                                                  &temp_princ_raw);

    if (ret != 0) {
        throw KRB5Exception("krb5_sname_to_principal (get_default_hostname)",
                            ret);
    }
    KRB5Principal temp_princ(temp_princ_raw);

#ifdef HEIMDAL
    const char *comp = krb5_principal_get_comp_string(g_context,
                                                      temp_princ.get(),
                                                      1);
#else
    krb5_data *comp = krb5_princ_component(g_context,
                                           temp_princ.get(),
                                           1);
#endif
    if (comp == NULL) {
        error_exit("get_default_hostname: couldn't determine "
                        "hostname, strange value from "
                        "krb5_sname_to_principal.");
    }
#ifdef HEIMDAL
    return std::string(comp);
#else
    return std::string(comp->data, comp->length);
#endif
}

bool DnsSrvHost::validate(bool nocanon) {
    int sock = -1;
    struct hostent *host;

    if (!validated_name.empty()) {
        return true;
    }

    host = gethostbyname(srvname.c_str());

    if (!host) {
        VERBOSE("Error: gethostbyname failed for %s\n", srvname.c_str());
        return false;
    }

    VERBOSE("Found DC: %s. Checking availability...", srvname.c_str());

    for (int i = 0; host->h_addr_list[i]; i++) {
        struct sockaddr_in addr;
        struct hostent *hp;

        memcpy(&(addr.sin_addr.s_addr), host->h_addr_list[i], host->h_length);

        /* Now let's try and open and close a socket to see if the domain controller is up or not */
        addr.sin_family = AF_INET;
        addr.sin_port = htons(LDAP_PORT);
        if (sock != -1) {
            close(sock);
        }
        if ((sock = socket(AF_INET, SOCK_STREAM, 0)) == -1) {
            VERBOSE("Failed to open socket");
            continue;
        }
        if (connect(sock, (struct sockaddr *) &addr, sizeof(addr)) == -1) {
            VERBOSE("LDAP connection (%d) failed", i);
            continue;
        }

        /* See if this is the 'lowest' domain controller name... the idea is to always try to
         * use the same domain controller. Things may become inconsistent otherwise.
         * This optimization is only possible if we're told to canonify the hostname. Otherwise,
         * we're not allowed to touch it, but we can make sure that it resolves to at least
         * one working IP address. */
        if (nocanon) {
            validated_name = srvname;
            break;
        }
        hp = gethostbyaddr((char *) &addr.sin_addr.s_addr, sizeof(addr.sin_addr.s_addr), AF_INET);
        if (!hp) {
            VERBOSE("Error: gethostbyaddr failed for %s\n", srvname.c_str());
            continue;
        }
        if (!validated_name.empty() && std::string(hp->h_name) > validated_name) {
            VERBOSE("Connection to DC %s ok, but we already prefer %s", hp->h_name, validated_name.c_str());
            continue;
        }
        validated_name = std::string(hp->h_name);

    }
    if (sock != -1) {
        close(sock);
    }
    return ! validated_name.empty();
};

DnsSrvQuery::DnsSrvQuery(const std::string& domain, const std::string& service, const std::string& protocol)
{
#if defined(HAVE_LIBUDNS)
    struct dns_ctx *nsctx = NULL;

    dns_reset(NULL);
    if ((nsctx = dns_new(NULL)) != NULL) {
        if (dns_init(nsctx, 1) >= 0) {
            struct dns_rr_srv *srv;

            if ((srv = dns_resolve_srv(nsctx, domain.c_str(), service.c_str(),
                            protocol.c_str(), DNS_NOSRCH)) != NULL) {

                for (int i = 0; i < srv->dnssrv_nrr; i++) {
                    m_results.push_back(DnsSrvHost(srv->dnssrv_srv[i]));
                }
                free(srv);
            }
        }

        dns_close(nsctx);
        free(nsctx);
    }
#elif defined(HAVE_NS_INITPARSE) && defined(HAVE_RES_SEARCH)
    unsigned char response[NS_MAXMSG];
    int len;
    ns_msg reshandle;
    ns_rr rr;
    const std::string krbdnsquery = "_" + service + "._" + protocol + "." + domain;

    VERBOSE("Running DNS SRV query for %s", krbdnsquery.c_str());
    if ((len=res_search(krbdnsquery.c_str(), ns_c_in, ns_t_srv, response, sizeof(response))) > 0) {
        if (ns_initparse(response,len,&reshandle) >= 0) {
            if ((len=ns_msg_count(reshandle,ns_s_an)) > 0) {
                for (int i = 0; i<len; i++) {
                    if (ns_parserr(&reshandle,ns_s_an,i,&rr) ||
                        ns_rr_class(rr) != ns_c_in ||
                        ns_rr_type(rr) != ns_t_srv) {
                        // Ignore records we cannot parse, this is non fatal.
                        VERBOSE("Skipping invalid record %d", i);
                        continue;
                    }
                    m_results.push_back(DnsSrvHost(reshandle, rr));
                }
            }
        }
    }
#endif
    std::sort(m_results.begin(), m_results.end());
}

std::string get_dc_host(const std::string &realm_name, const std::string &site_name,
                        const bool no_reverse_lookups)
{
    std::string dc;
    int i;
    DnsSrvQuery dcsrvs;
    std::string bestdc;
    std::string protocols[] = { "tcp", "udp" };

    if (!site_name.empty()) {
        for (i = 0; i < (int)(sizeof(protocols) / sizeof(protocols[0])); i++) {
            VERBOSE("Attempting to find site-specific Domain Controller to use via "
                            "DNS SRV record in domain %s for site %s and procotol %s",
                            realm_name.c_str(), site_name.c_str(), protocols[i].c_str());
            dcsrvs = DnsSrvQuery(site_name + "._sites.dc._msdcs." + realm_name, "kerberos", protocols[i]);
            if (!dcsrvs.empty()) {
                break;
            }
        }
    }

    if (dcsrvs.empty()) {
        for (i = 0; i < (int)(sizeof(protocols) / sizeof(protocols[0])); i++) {
            VERBOSE("Attempting to find Domain Controller to use via "
                            "DNS SRV record in domain %s for procotol %s",
                            realm_name.c_str(), protocols[i].c_str());
            dcsrvs = DnsSrvQuery("dc._msdcs." + realm_name, "kerberos", protocols[i]);
            if (!dcsrvs.empty()) {
                break;
            }
        }
    }

    if (dcsrvs.empty()) {
        VERBOSE("Attempting to find a Domain Controller to use (DNS domain)");
        dcsrvs = DnsSrvQuery(DnsSrvHost(realm_name, 0, 0, 0));
    }

    for (std::vector<DnsSrvHost>::iterator it=dcsrvs.begin(); it != dcsrvs.end(); it++) {
        if (it->validate(no_reverse_lookups)) {
            bestdc = it->name();
            break;
	}
    }

    VERBOSE("Found preferred Domain Controller: %s", bestdc.c_str());

    return bestdc;
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

/* Return true if <str> ends with <suffix>, false otherwise */
static bool ends_with(std::string const &str, std::string const &suffix)
{
    if (suffix.size() > str.size())
        return false;

    return std::equal(suffix.rbegin(), suffix.rend(), str.rbegin());
}

/* Default sAMAccountName for current host:
   Use lowercase FQDN, strip realm if applicable, convert remaining dots to dashes.
   Eg. foo.example.com in realm EXAMPLE.COM -> foo
       foo.subdomain1.example.com in realm EXAMPLE.COM -> foo-subdomain1
       foo.subdomain1.example.com in realm OTHEREXAMPLE.COM -> foo-subdomain1-example-com
 */
std::string get_default_samaccountname(msktutil_flags *flags)
{
    std::string long_hostname = flags->hostname;

    std::transform(long_hostname.begin(), long_hostname.end(),
                   long_hostname.begin(), ::tolower);

    std::string samaccountname = long_hostname;

    if (ends_with(samaccountname, '.' + flags->lower_realm_name))
        samaccountname.resize(samaccountname.length() - flags->lower_realm_name.length() - 1);

    /* Replace any remaining dots with dashes */
    std::replace(samaccountname.begin(), samaccountname.end(), '.', '-');

    VERBOSE("Determined sAMAccountName: %s", samaccountname.c_str());
    return samaccountname;
}

/* Return first component of FQDN set in flags->hostname */
std::string get_short_hostname(msktutil_flags *flags)
{
    std::string long_hostname = flags->hostname;
    std::string short_hostname = long_hostname.substr(0, long_hostname.find('.'));
    std::transform(short_hostname.begin(), short_hostname.end(), short_hostname.begin(), ::tolower);

    VERBOSE("Determined short hostname: %s", short_hostname.c_str());
    return short_hostname;
}
