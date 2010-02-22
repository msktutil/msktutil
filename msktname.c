/*
 *----------------------------------------------------------------------------
 *
 * msktname.c
 *
 * (C) 2004-2006 Dan Perry (dperry@pppl.gov)
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


char *complete_hostname(char *hostname)
{
    struct hostent *host;
    struct sockaddr_in addr;
    struct hostent *hp;
    char *name;


    if (!hostname) {
        /* Null in, NULL out */
        return hostname;
    }

    host = gethostbyname(hostname);
    if (!host) {
        fprintf(stderr, "Warning: No DNS entry found for %s\n", hostname);
        name = (char *) malloc(strlen(hostname) + 1);
        if (!name) {
            fprintf(stderr, "Error: malloc failed\n");
            return NULL;
        }
        memset(name, 0, strlen(hostname) + 1);
        sprintf(name, "%s", hostname);
        return name;
    }
    memcpy(&(addr.sin_addr.s_addr), host->h_addr_list[0], sizeof(host->h_addr_list[0]));
    hp = gethostbyaddr((char *) &addr.sin_addr.s_addr, sizeof(addr.sin_addr.s_addr), AF_INET);
    if (!hp) {
        fprintf(stderr, "Error: No reverse DNS entry found for %s\n", (char *) &addr.sin_addr.s_addr);
        endhostent();
        return NULL;
    }
    name = (char *) malloc(strlen((char *) hp->h_name) + 1);
    if (!name) {
        fprintf(stderr, "Error: malloc failed\n");
        endhostent();
        return NULL;
    }
    memset(name, 0, strlen((char *) hp->h_name) + 1);
    strcpy(name, (char *) hp->h_name);

    endhostent();
    return name;
}


char *get_default_hostname()
{
    int ret;
    char *hostname;
    char *name;


    hostname = (char *) malloc(MAX_HOSTNAME_LEN + 1);
    if (!hostname) {
        fprintf(stderr, "Error: malloc failed\n");
        return NULL;
    }
    memset(hostname, 0, MAX_HOSTNAME_LEN + 1);
    ret = gethostname(hostname, MAX_HOSTNAME_LEN);
        if (ret) {
            fprintf(stderr, "Error: gethostname failed\n");
            free(hostname);
        return NULL;
    }
    name = complete_hostname(hostname);
    free(hostname);

    return name;
}


int get_dc(msktutil_flags *flags)
{
    char *dc = NULL;
    struct hostent *host;
    struct sockaddr_in addr;
    struct hostent *hp;
    int sock;
    int i;


    if (flags->server) {
        /* The server has already been specified */
        return 0;
    }
    VERBOSE("Attempting to find a Domain Controller to use");
    host = gethostbyname(flags->realm_name);
    if (!host) {
        fprintf(stderr, "Error: gethostbyname failed \n");
        return -1;
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
            if (!dc) {
                dc = (char *) malloc(strlen(hp->h_name) + 1);
                if (!dc) {
                    fprintf(stderr, "Error: malloc failed\n");
                    endhostent();
                    continue;
                }
                memset(dc, 0, strlen(hp->h_name) + 1);
                strcpy(dc, hp->h_name);
            } else {
                if (0 > strcmp(dc, (char *) hp->h_name)) {
                    free(dc);
                    dc = (char *) malloc(strlen(hp->h_name) + 1);
                    if (!dc) {
                        fprintf(stderr, "Error: malloc failed\n");
                        endhostent();
                        continue;
                    }
                    memset(dc, 0, strlen(hp->h_name) + 1);
                    strcpy(dc, hp->h_name);
                }
            }
        }
    }
    endhostent();

    VERBOSE("Found Domain Controller: %s", dc);
    flags->server = dc;
    return 0;
}


char *get_host_os()
{
    char *name = NULL;
    struct utsname info;
    int ret;


    ret = uname(&info);
    if (ret == -1) {
        fprintf(stderr, "Error: uname failed (%d)\n", ret);
        return NULL;
    }
    name = (char *) malloc(strlen(info.sysname) + 1);
    if (!name) {
        fprintf(stderr, "Error: malloc failed\n");
        return NULL;
    }
    memset(name, 0, strlen(info.sysname) + 1);
    sprintf(name, "%s", info.sysname);

    return name;
}


char *get_short_hostname(msktutil_flags *flags)
{
    char *short_hostname = NULL;
    char *long_hostname;
    int i;


    long_hostname = (char *) malloc(strlen(flags->hostname) + 1);
    if (!long_hostname) {
        fprintf(stderr, "Error: malloc failed\n");
        return NULL;
    }
    memset(long_hostname, 0, strlen(flags->hostname) + 1);
    sprintf(long_hostname, "%s", flags->hostname);

    /* Make things lower case so that we can compare strings */
    for (i = 0; *(long_hostname + i); i++) {
        *(long_hostname + i) = tolower(*(long_hostname + i));
    }

    for (i = 0; *(long_hostname + i); i++) {
        if (*(long_hostname + i) == '.') {
            i++;
            if (*(long_hostname + i)) {
                if (!strcmp(long_hostname + i, flags->lower_realm_name)) {
                    i--;
                    break;
                }
            }
        }
    }
    free(long_hostname);

    short_hostname = (char *) malloc(i + 1);
    if (!short_hostname) {
        fprintf(stderr, "Error: malloc failed\n");
        return NULL;
    }
    memset(short_hostname, 0, i + 1);
    strncpy(short_hostname, flags->hostname, i);

    /* Replace any remaining dots with dashes */
    for (i = 0; *(short_hostname + i); i++) {
        if (*(short_hostname + i) == '.') {
            *(short_hostname + i) = '-';
        }
    }

    VERBOSE("Determined short hostname: %s", short_hostname);
    return short_hostname;
}
