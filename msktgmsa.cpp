/*
 *----------------------------------------------------------------------------
 *
 * msktgmsa.cpp
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
#include <string>

#define RET_ILSEQ      -1
#define RET_TOOFEW     -2
#define RET_ILUNI      -1

#define READ_U16LE(str, offset)  (str[offset] | str[offset+1] << 8)
#define READ_U32LE(str, offset)  (str[offset] | str[offset+1] << 8 | str[offset+2] << 16 | str[offset+3] << 24)

std::string transcode_utf16le_utf8 (const std::string &source);
int utf8_wctomb(uint32_t wc, std::string &out);
int utf16le_mbtowc(uint32_t *pwc, const unsigned char *s, size_t n);

/*
 * Parses a MSDS-MANAGEDPASSWORD_BLOB structure to retrieve
 * the current password in a format usable by GSSAPI.
*/
std::string get_managed_password(const std::string &blob)
{
    if (blob.length() < 32) {
        fprintf(stderr, "ERROR: MSDS-MANAGEDPASSWORD_BLOB structure received"
                "is invalid.\n");
        exit(1);
    }

    uint16_t version = READ_U16LE(blob, 0);
    if (version != 1) {
        fprintf(stderr, "ERROR: MSDS-MANAGEDPASSWORD_BLOB structure version "
                "is not 1 but %d.\n", version);
        exit(1);
    }

    uint32_t length = READ_U32LE(blob, 4);
    if (length != blob.length()) {
        fprintf(stderr, "ERROR: MSDS-MANAGEDPASSWORD_BLOB structure length "
                "is different than the number of received bytes from LDAP ("
                "received: %ld, expected: %d)\n", blob.length(),
                length);
        exit(1);
    }

    uint16_t current_password_offset = READ_U16LE(blob, 8);
    uint16_t previous_password_offset = READ_U16LE(blob, 10);
    uint16_t query_password_interval_offset = READ_U16LE(blob, 12);

    uint16_t end_current_password_offset = 0;
    if (previous_password_offset == 0) {
        end_current_password_offset = query_password_interval_offset;
    } else {
        end_current_password_offset = previous_password_offset;
    }

    // current_password contains the password of the GMSA account
    // encoded in UTF-16-LE. The two last zeros are ignored.
    std::string current_password = std::string(blob,
            (size_t) current_password_offset,
            (size_t) (end_current_password_offset - current_password_offset - 2));

    // To be used by GSSAPI, the password needs to be
    // transcoded in UTF-8.
    return transcode_utf16le_utf8(current_password);
}

std::string transcode_utf16le_utf8 (const std::string &source)
{
    std::string out = std::string();
    unsigned char* inptr = (unsigned char*) source.c_str();
    size_t inleft = source.length();
    int incount;
    int ret;
    while (inleft > 0) {
        uint32_t pwc = 0;
        incount = utf16le_mbtowc(&pwc, inptr, inleft);
        if (incount < 0) {
            // An error occurred. Use a replacement character.
            incount = 2;
            pwc = 0xfffd;
        }
        inleft -= incount;
        inptr += incount;

        ret = utf8_wctomb(pwc, out);
        if (ret < 0) {
            fprintf(stderr, "ERROR: Could not encode Unicode CP U+%x in UTF-8.\n",
                    pwc);
            exit(1);
        }
    }
    return out;
}

// This code is taken from libiconv
int utf16le_mbtowc(uint32_t *pwc, const unsigned char *s, size_t n)
{
    if (n >= 2)
    {
        uint32_t wc = s[0] + (s[1] << 8);
        if (wc >= 0xd800 && wc < 0xdc00)
        {
            if (n >= 4)
            {
                uint32_t wc2 = s[2] + (s[3] << 8);
                if (!(wc2 >= 0xdc00 && wc2 < 0xe000))
                    return RET_ILSEQ;
                *pwc = 0x10000 + ((wc - 0xd800) << 10) + (wc2 - 0xdc00);
                return 4;
            }
        }
        else if (wc >= 0xdc00 && wc < 0xe000)
        {
            return RET_ILSEQ;
        }
        else
        {
            *pwc = wc;
            return 2;
        }
    }
    return RET_TOOFEW;
}

// This code is taken from libiconv
int utf8_wctomb(uint32_t wc, std::string &out)
{
    int count;
    if (wc < 0x80)
        count = 1;
    else if (wc < 0x800)
        count = 2;
    else if (wc < 0x10000) {
        if (wc < 0xd800 || wc >= 0xe000)
            count = 3;
        else
            return RET_ILUNI;
    } else if (wc < 0x110000)
        count = 4;
    else
        return RET_ILUNI;
    char r[4] = {0};
    switch (count) { /* note: code falls through cases! */
        case 4: r[3] = 0x80 | (wc & 0x3f); wc = wc >> 6; wc |= 0x10000;
        case 3: r[2] = 0x80 | (wc & 0x3f); wc = wc >> 6; wc |= 0x800;
        case 2: r[1] = 0x80 | (wc & 0x3f); wc = wc >> 6; wc |= 0xc0;
        case 1: r[0] = wc;
    }
    out.append(r, count);
    return count;
}
