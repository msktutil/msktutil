/*
 *----------------------------------------------------------------------------
 *
 * ldapconnection.h
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

#ifndef LDAPCONNECTION_H
#define LDAPCONNECTION_H 1

#include <ldap.h>
#include <string>
#include <vector>
#ifdef HAVE_SASL_H
#include <sasl.h>
#else
#include <sasl/sasl.h>
#endif

class LDAP_mod {
    std::vector<LDAPMod *> attrs;
public:
    void add(const std::string& type);
    void add(const std::string& type, const std::string& val, bool ucs = false);
    void add(const std::string& type, const std::vector<std::string>& val);
    std::vector<LDAPMod *> get() const;
    ~LDAP_mod();
};


class LDAPConnection {
private:
    LDAP *m_ldap;

    int modify_ext(const std::string &dn, const std::string& type, char *vals[], int op, bool check);


public:
    LDAPConnection(const std::string &server, const std::string &sasl_mechanisms, bool no_reverse_lookups = false);
    void set_option(int option, const void *invalue);
    void get_option(int option, void *outvalue);

    bool is_connected() const { return m_ldap != NULL; };


    LDAPMessage *search(
                const std::string &base_dn, int scope, const std::string &filter, const std::string& attr);

    LDAPMessage *search(
                   const std::string &base_dn, int scope, const std::string &filter, const char *attr[]);

    LDAPMessage *search(
                       const std::string &base_dn, int scope, const std::string &filter, const std::vector<std::string>& attr);

    LDAPMessage *first_entry(LDAPMessage *mesg);

    int add_attr(const std::string &dn, const std::string &attrName, const std::string &val);
    int simple_set_attr(const std::string &dn, const std::string &attrName, const std::string &val);
    int remove_attr(const std::string &dn, const std::string& type, const std::string& name);
    int flush_attr_no_check(const std::string &dn, const std::string& type);

    int add(const std::string &dn, const LDAP_mod& mod);

    void print_diagnostics(const char *msg, int err);
    std::string get_one_val(LDAPMessage *msg, const std::string& name);
    int count_entries(LDAPMessage *msg);
    std::vector<std::string> get_all_vals(LDAPMessage *msg, const std::string& name);
    ~LDAPConnection();
};


#endif

