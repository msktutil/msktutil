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



class LDAPConnection {
public:
    LDAP *m_ldap;

    int modify_ext(const std::string &dn, const std::string& type, char *vals[], int op, bool check );


public:
    LDAPConnection(const std::string &server, bool no_reverse_lookups = false);
    void set_option(int option, const void *invalue);
    void get_option(int option, void *outvalue);


    LDAPMessage *search(
                const std::string &base_dn, int scope, const std::string &filter, const std::string& attr);

    LDAPMessage *search(
                   const std::string &base_dn, int scope, const std::string &filter, const char *attr[]);

    LDAPMessage *first_entry(LDAPMessage *mesg);

    int add_attr(const std::string &dn, const std::string &attrName, const std::string &val);
    int simple_set_attr(const std::string &dn, const std::string &attrName, const std::string &val);
    int remove_attr(const std::string &dn, const std::string& type, const std::string& name);
    int flush_attr_no_check(const std::string &dn, const std::string& type);


    void print_diagnostics(const char *msg, int err);
    std::string get_one_val(LDAPMessage *msg, const std::string& name);
    int count_entries(LDAPMessage *msg);
    std::vector<std::string> get_all_vals(LDAPMessage *msg, const std::string& name);
    ~LDAPConnection();
};


#endif

