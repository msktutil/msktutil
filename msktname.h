/*
 *----------------------------------------------------------------------------
 *
 * msktname.h
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

#include "config.h"

#if defined(HAVE_LIBUDNS)
#include <udns.h>
#define inet_ntop dns_ntop
#elif defined(HAVE_NS_INITPARSE) && defined(HAVE_RES_SEARCH)
#include <arpa/inet.h>
#include <arpa/nameser.h>
#include <resolv.h>

#if !defined(NS_MAXMSG)
#define NS_MAXMSG 65535
#endif
#else
#include <arpa/inet.h>
#endif

#ifndef stringify
#define stringify(x) stringify_(x)
#define stringify_(x) #x
#endif

#include <algorithm>
#include <cctype>

#if defined(HAVE_NS_INITPARSE)
/* A quirk in glibc < 2.9 makes us pick up a symbol marked GLIBC_PRIVATE
 * if we use ns_get16 from libresolv, leading to a broken RPM
 * that can only be installed with --nodeps. As a workaround,
 * use a private version of ns_get16--it's simple enough.
 */
static unsigned int msktutil_ns_get16(const unsigned char *src)
{
    return (unsigned int) (((uint16_t)src[0] << 8) | ((uint16_t)src[1]));
}
#endif

class DnsSrvHost {
private:
    std::string srvname;
    std::string validated_name;
    unsigned int m_priority;
    unsigned int m_weight;
    unsigned int m_port;
public:
    DnsSrvHost(const std::string& name, unsigned int priority, unsigned int weight, unsigned int port)
        : srvname(name),
          validated_name(""),
          m_priority(priority),
          m_weight(weight),
          m_port(port)
        {};
#if defined(HAVE_LIBUDNS)
    DnsSrvHost(const struct dns_srv& dnssrv)
        : srvname(dnssrv.name),
          validated_name(""),
          m_priority(dnssrv.priority),
          m_weight(dnssrv.weight),
          m_port(dnssrv.port)
        {};
#endif
#if defined(HAVE_NS_INITPARSE)
    DnsSrvHost(ns_msg reshandle, ns_rr rr) : validated_name("")
    {
        if (ns_rr_class(rr) == ns_c_in && ns_rr_type(rr) == ns_t_srv) {
        char name[NS_MAXDNAME];
        m_priority = msktutil_ns_get16(ns_rr_rdata(rr));
        m_weight   = msktutil_ns_get16(ns_rr_rdata(rr) +   NS_INT16SZ);
        m_port     = msktutil_ns_get16(ns_rr_rdata(rr) + 2*NS_INT16SZ);
        dn_expand(ns_msg_base(reshandle),ns_msg_base(reshandle)+ns_msg_size(reshandle),
              ns_rr_rdata(rr) + 3*NS_INT16SZ,
              name, sizeof(char)*NS_MAXDNAME);
        srvname = std::string(name);
        }
    };
#endif
    std::string name() { return validated_name; };
    unsigned int priority() { return m_priority; };
    unsigned int weight() { return m_weight; };
    unsigned int port() { return m_port; };
    /* Allow to sort by prio where a lower prio number means stronger
     * preference, ie. the lowest sorting item is the most preferred. */
    bool operator<(const DnsSrvHost& other) const {
        /* for ultimate confusion, prio and weight go in opposite
         * directions, ie. we prefer lower prio, but higher weight. */
        if (m_priority == other.m_priority)
            return m_weight > other.m_weight;
        
        return m_priority < other.m_priority;
    };
    /* Check host availability by opening a TCP connection to the objects's
     * <port>. If <service> is non-empty, use its associated port instead. */
    bool validate(bool nocanon, std::string service = "");
};


class DnsSrvQuery {
private:
    std::vector<DnsSrvHost> m_results;
public:
    DnsSrvQuery() {};
    DnsSrvQuery(const DnsSrvHost& host) {
        m_results.push_back(host);
    };
    DnsSrvQuery(const std::string& domain, const std::string& service, const std::string& protocol);
    bool empty() { return m_results.empty(); };
    std::vector<DnsSrvHost>::iterator begin() { return m_results.begin(); };
    std::vector<DnsSrvHost>::iterator end() { return m_results.end(); };
};
