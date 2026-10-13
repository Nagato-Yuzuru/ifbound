/*
 * readers.c - a replica of the two macOS readers of /etc/hosts, for the
 * differential test of the line and field logic (readers_test.go). This
 * file is test data only. It is not part of any binary that the
 * repository builds. readers.py compiles it and runs it to make
 * readers.txt.
 *
 * It prints one record per entry:
 *
 *   MA <address> <name>       mDNSResponder: an address record
 *   MC <alias> <name>         mDNSResponder: a CNAME record
 *   LA <address> <name>       Libinfo: a name of a line with an address
 *
 * A name in an M record is its wire-form labels in hex, joined by "."; the
 * root name is ".". A name in an LA record is the field in hex.
 *
 * The file has two parts with different sources and licenses. See NOTICE
 * at the root of the repository, and the license texts in LICENSES/.
 *
 * Part 1, mDNSResponder (from "mDNSResponder part" to "Libinfo part"):
 * derived from mDNSResponder-2600.140.3 mDNSMacOSX.c (EtcHostsParseOneName,
 * mDNSMacOSXParseEtcHostsLine, mDNSMacOSXParseEtcHosts, lines 5724-5951)
 * and mDNSResponder mDNSCore/DNSCommon.c (AppendDNSNameString, line 1120).
 * The original notice of these files (mDNSMacOSX.c: 2002-2024,
 * DNSCommon.c: 2002-2026):
 *
 *   Copyright (c) 2002-2026 Apple Inc. All rights reserved.
 *
 *   Licensed under the Apache License, Version 2.0 (the "License");
 *   you may not use this file except in compliance with the License.
 *   You may obtain a copy of the License at
 *
 *       https://www.apache.org/licenses/LICENSE-2.0
 *
 *   Unless required by applicable law or agreed to in writing, software
 *   distributed under the License is distributed on an "AS IS" BASIS,
 *   WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *   See the License for the specific language governing permissions and
 *   limitations under the License.
 *
 * Part 2, Libinfo (from "Libinfo part" to "Driver"): derived from
 * Libinfo-600 lookup.subproj/file_module.c (_fsi_append_string,
 * _fsi_tokenize, _fsi_get_line, and the address and name logic of
 * _fsi_parse_host and _fsi_get_host, lines 137-253 and 1296-1450). The
 * original notice of this file:
 *
 *   Copyright (c) 2008-2015 Apple Inc.  All rights reserved.
 *
 *   @APPLE_LICENSE_HEADER_START@
 *
 *   This file contains Original Code and/or Modifications of Original Code
 *   as defined in and that are subject to the Apple Public Source License
 *   Version 2.0 (the 'License'). You may not use this file except in
 *   compliance with the License. Please obtain a copy of the License at
 *   http://www.opensource.apple.com/apsl/ and read it before using this
 *   file.
 *
 *   The Original Code and all software distributed under the License are
 *   distributed on an 'AS IS' basis, WITHOUT WARRANTY OF ANY KIND, EITHER
 *   EXPRESS OR IMPLIED, AND APPLE HEREBY DISCLAIMS ALL SUCH WARRANTIES,
 *   INCLUDING WITHOUT LIMITATION, ANY WARRANTIES OF MERCHANTABILITY,
 *   FITNESS FOR A PARTICULAR PURPOSE, QUIET ENJOYMENT OR NON-INFRINGEMENT.
 *   Please see the License for the specific language governing rights and
 *   limitations under the License.
 *
 *   @APPLE_LICENSE_HEADER_END@
 *
 * Part 3, the driver (from "Driver" to the end), is not derived from Apple
 * code and is under the license of the repository.
 *
 * Modifications. This file was changed from the Apple originals on
 * 2026-10-12 and 2026-10-13. Each changed place has a comment that starts
 * with "CHANGED:". In summary:
 *
 *   - The code is reformatted, the mDNS types and macros (mDNSlocal,
 *     mDNSexport, mDNSu8, mDNSBool) are replaced by plain C types, and the
 *     log calls are removed.
 *   - The resource record creation of mDNSResponder prints a record
 *     instead. SameDomainName is a short replacement.
 *   - mDNSMacOSXParseEtcHosts reads a file at a given path, not
 *     /etc/hosts through a watched descriptor.
 *   - The Libinfo host lookup prints every name of a line instead of
 *     matching a requested name or address, and uses strdup for its copy.
 */
#include <arpa/inet.h>
#include <net/if.h>
#include <netdb.h>
#include <netinet/in.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <sys/socket.h>
#include <ctype.h>

/* ---- mDNSResponder part (Apache License 2.0) ---- */

/* CHANGED: plain C types and macros replace those of mDNSEmbeddedAPI.h. */
typedef unsigned char u8;
typedef struct { u8 c[256]; } domainname;
#define MAX_DOMAIN_NAME 256
#define MAX_DOMAIN_LABEL 63
#define mDNSIsDigit(X) ((X) >= '0' && (X) <= '9')

/* CHANGED: reformatted; appends to an empty name only (no DomainNameLength). */
static u8 *AppendDNSNameString(domainname *const name, const char *cstring) {
  const char *cstr = cstring;
  u8 *ptr = name->c; /* empty name: DomainNameLength 1, minus 1 */
  const u8 *const lim = name->c + MAX_DOMAIN_NAME - 1;
  if (cstr[0] == '.' && cstr[1] == '\0') cstr++;
  while (*cstr && ptr < lim) {
    u8 *lengthbyte = ptr++;
    if (*cstr == '.') return NULL;
    while (*cstr && *cstr != '.' && ptr < lim) {
      u8 c = (u8)*cstr++;
      if (c == '\\') {
        if (*cstr == '\0') break;
        c = (u8)*cstr++;
        if (mDNSIsDigit(cstr[-1]) && mDNSIsDigit(cstr[0]) && mDNSIsDigit(cstr[1])) {
          int v0 = cstr[-1] - '0', v1 = cstr[0] - '0', v2 = cstr[1] - '0';
          int val = v0 * 100 + v1 * 10 + v2;
          if (val <= 255) { c = (u8)val; cstr += 2; }
        }
      }
      *ptr++ = c;
    }
    if (*cstr == '.') cstr++;
    if (ptr - lengthbyte - 1 > MAX_DOMAIN_LABEL) return NULL;
    *lengthbyte = (u8)(ptr - lengthbyte - 1);
  }
  *ptr++ = 0;
  if (*cstr) return NULL;
  return ptr;
}
static u8 *MakeDomainNameFromDNSNameString(domainname *name, const char *cstr) { name->c[0] = 0; return AppendDNSNameString(name, cstr); }

/* CHANGED: new helpers that print a record (printwire, printaddr). */
static void printwire(const domainname *d) { /* labels as hex, '.'-joined; root = "." */
  const u8 *p = d->c; int first = 1;
  if (!*p) { printf("."); return; }
  while (*p) { if (!first) printf("."); first = 0; for (int i = 1; i <= *p; i++) printf("%02x", p[i]); p += 1 + *p; }
}
static void printaddr(const struct sockaddr *sa) {
  char b[64];
  if (sa->sa_family == AF_INET) inet_ntop(AF_INET, &((const struct sockaddr_in*)sa)->sin_addr, b, sizeof b);
  else inet_ntop(AF_INET6, &((const struct sockaddr_in6*)sa)->sin6_addr, b, sizeof b);
  printf("%s", b);
}
typedef int mDNSBool;
/* CHANGED: replaces mDNSMacOSXCreateEtcHostsEntry; prints the record. */
static mDNSBool CreateEntry(const domainname *domain, const struct sockaddr *sa, const domainname *cname, char *ifname) {
  if (ifname && !if_nametoindex(ifname)) return 0;
  if (sa) { printf("MA "); printaddr(sa); printf(" "); printwire(domain); printf("\n"); }
  else { printf("MC "); printwire(domain); printf(" "); printwire(cname); printf("\n"); }
  return 1;
}
/* CHANGED: a short replacement of SameDomainName (ASCII case folded). */
static int SameDomainName(const domainname *a, const domainname *b) {
  const u8 *p = a->c, *q = b->c;
  for (;;) { if (*p != *q) return 0; if (!*p) return 1;
    for (int i = 1; i <= *p; i++) if (tolower(p[i]) != tolower(q[i])) return 0;
    p += 1 + *p; q += 1 + *q; }
}

static int EtcHostsParseOneName(int start, int length, char *buffer, char **name) {
  int i; *name = NULL;
  for (i = start; i < length; i++) {
    if (buffer[i] == '#') return -1;
    if (buffer[i] != ' ' && buffer[i] != ',' && buffer[i] != '\t') {
      *name = &buffer[i];
      for (i++; i < length; i++) {
        if (buffer[i] == ' ' || buffer[i] == ',' || buffer[i] == '\t') { buffer[i] = 0; break; }
      }
      return i;
    }
  }
  return -1;
}

/* CHANGED: mDNSMacOSXParseEtcHostsLine without logs and the AuthHash argument. */
static void ParseEtcHostsLine(char *buffer, int length) {
  int i, ifStart = 0; char *ifname = NULL; domainname name1d, name2d; char *name1, *name2; int aliasIndex;
  while (*buffer == ' ' || *buffer == '\t') { buffer++; length--; }
  for (i = 0; i < length; i++) {
    if (buffer[i] == ' ' || buffer[i] == ',' || buffer[i] == '\t' || buffer[i] == '%') {
      if (buffer[i] == '%') ifStart = i + 1;
      buffer[i] = 0; break;
    }
  }
  struct addrinfo hints; bzero(&hints, sizeof(hints)); hints.ai_flags = AI_NUMERICHOST;
  struct addrinfo *gairesults = NULL;
  if (getaddrinfo(buffer, NULL, &hints, &gairesults) != 0) return;
  if (ifStart) {
    ifname = &buffer[ifStart];
    for (i = ifStart + 1; i < length; i++) {
      if (buffer[i] == ' ' || buffer[i] == ',' || buffer[i] == '\t') { buffer[i] = 0; break; }
    }
  }
  i = EtcHostsParseOneName(i + 1, length, buffer, &name1);
  if (i == length) {
    if (!MakeDomainNameFromDNSNameString(&name1d, name1)) { freeaddrinfo(gairesults); return; }
    CreateEntry(&name1d, gairesults->ai_addr, NULL, ifname);
  } else if (i != -1) {
    domainname first;
    if (!MakeDomainNameFromDNSNameString(&first, name1)) { freeaddrinfo(gairesults); return; }
    CreateEntry(&first, gairesults->ai_addr, NULL, ifname);
    aliasIndex = 0;
    while (i < length) {
      i = EtcHostsParseOneName(i + 1, length, buffer, &name2);
      if (name2) {
        if ((aliasIndex) && (*buffer == *name2)) break;
        if (!MakeDomainNameFromDNSNameString(&name2d, name2)) { freeaddrinfo(gairesults); return; }
        if (!SameDomainName(&first, &name2d)) {
          if (!CreateEntry(&name2d, NULL, &first, ifname)) { freeaddrinfo(gairesults); return; }
        }
        aliasIndex++;
      } else if (!aliasIndex) break;
    }
  }
  freeaddrinfo(gairesults);
}

/* CHANGED: mDNSMacOSXParseEtcHosts reads the file at path, without logs. */
static void ParseEtcHosts(const char *path) {
  char buf[1024]; size_t len; FILE *fp = fopen(path, "r"); if (!fp) return;
  while (fgets(buf, 1024, fp) != NULL) {
    if (buf[0] == '#' || buf[0] == '\r' || buf[0] == '\n') continue;
    len = strlen(buf); if (!len) break;
    if (buf[len - 1] == '\r' || buf[len - 1] == '\n') { buf[len - 1] = '\0'; len--; }
    if (len) { if (buf[len - 1] == '\r' || buf[len - 1] == '\n') { buf[len - 1] = '\0'; len--; } }
    if (!len) continue;
    ParseEtcHostsLine(buf, (int)len);
  }
  fclose(fp);
}

/* ---- Libinfo part (Apple Public Source License 2.0) ---- */

/* CHANGED: _fsi_append_string, reformatted, without the NULL check after reallocf. */
static char **append_string(char *s, char **l) {
  int i, len; if (s == NULL) return l;
  if (l != NULL) { for (i = 0; l[i] != NULL; i++) {} len = i; } else len = 0;
  l = (char **)reallocf(l, (len + 2) * sizeof(char *)); l[len] = s; l[len + 1] = NULL; return l;
}
/* CHANGED: _fsi_tokenize, reformatted; ntokens must not be NULL; no trailing empty token (the hosts lookup passes 0). */
static char **fsi_tokenize(char *data, const char *sep, int trailing_empty, int *ntokens) {
  char **tokens = NULL; int p, i, start, end, more, len, end_on_sep = 0, scanning;
  if (data == NULL) return NULL;
  *ntokens = 0; len = strlen(sep); p = 0;
  while (data[p] != '\0') {
    end_on_sep = 1;
    while ((data[p] == ' ') || (data[p] == '\t') || (data[p] == '\n')) p++;
    if (data[p] == '\0') break;
    start = p; end = p; scanning = 1; end_on_sep = 0;
    while (scanning == 1) {
      if (data[p] == '\0') break;
      for (i = 0; i < len; i++) if (data[p] == sep[i]) { scanning = 0; end_on_sep = 1; break; }
      if ((scanning == 1) && (data[p] != ' ') && (data[p] != '\t') && (data[p] != '\n')) end = p;
      p += scanning;
    }
    more = 0; if (data[p] != '\0') more = 1;
    if (start == p) data[p] = '\0'; else data[end + 1] = '\0';
    tokens = append_string(data + start, tokens); *ntokens = *ntokens + 1;
    p += more;
  }
  (void)trailing_empty; (void)end_on_sep;
  return tokens;
}
/* CHANGED: _fsi_get_line, with strdup for _fsi_copy_string. */
static char *fsi_get_line(FILE *fp) {
  char s[4096]; char *x; s[0] = '\0';
  x = fgets(s, sizeof(s), fp);
  if ((x == NULL) || (s[0] == '\0')) return NULL;
  if (s[0] != '#') s[strlen(s) - 1] = '\0';
  return strdup(s);
}
/* CHANGED: the loop of _fsi_get_host and the address logic of _fsi_parse_host; prints each name instead of a match. */
static void LibinfoHosts(const char *path) {
  FILE *f = fopen(path, "r"); if (!f) return;
  for (;;) {
    char *line = fsi_get_line(f); if (line == NULL) break;
    if (line[0] == '#') { free(line); continue; }
    int ntokens = 0; char **tokens = fsi_tokenize(line, " \t", 0, &ntokens);
    if (ntokens >= 2) {
      unsigned char a[16]; char b[64]; int ok = 0;
      if (inet_pton(AF_INET, tokens[0], a) == 1) { inet_ntop(AF_INET, a, b, sizeof b); ok = 1; }
      else if (inet_pton(AF_INET6, tokens[0], a) == 1) { inet_ntop(AF_INET6, a, b, sizeof b); ok = 1; }
      if (ok) for (int i = 1; i < ntokens; i++) {
        printf("LA %s ", b); for (unsigned char *q = (unsigned char *)tokens[i]; *q; q++) printf("%02x", *q); printf("\n");
      }
    }
    free(tokens); free(line);
  }
  fclose(f);
}

/* ---- Driver (license of the repository) ---- */

int main(int argc, char **argv) {
  for (int k = 1; k < argc; k++) { printf("F %s\n", argv[k]); ParseEtcHosts(argv[k]); LibinfoHosts(argv[k]); }
  return 0;
}
