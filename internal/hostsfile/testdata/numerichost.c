/*
 * numerichost prints how the macOS readers of /etc/hosts read each input
 * line as an address. It writes one line per input line with three
 * fields separated by tabs:
 *
 *   1. the input;
 *   2. the address of getaddrinfo with AI_NUMERICHOST on the input cut at
 *      the first "%": what mDNSResponder passes (mDNSMacOSX.c:5773-5787);
 *   3. the address of inet_pton, IPv4 then IPv6, on the whole input: what
 *      Libinfo passes (file_module.c:1321-1328).
 *
 * "ERR" means that the call refuses the input. An address is written as
 * inet_ntop writes it.
 *
 * Regenerate numerichost.tsv on macOS:
 *
 *   cc -o /tmp/numerichost numerichost.c
 *   cut -f1 numerichost.tsv | /tmp/numerichost > numerichost.tsv.new
 *   mv numerichost.tsv.new numerichost.tsv
 */
#include <arpa/inet.h>
#include <netdb.h>
#include <netinet/in.h>
#include <stdio.h>
#include <string.h>
#include <sys/socket.h>

static void ntop(int af, const void *src, char *dst, socklen_t size) {
  if (inet_ntop(af, src, dst, size) == NULL) {
    snprintf(dst, size, "NTOP-ERR");
  }
}

int main(void) {
  static char line[8192], cut[8192];
  while (fgets(line, sizeof line, stdin) != NULL) {
    line[strcspn(line, "\n")] = '\0';
    strcpy(cut, line);
    cut[strcspn(cut, "%")] = '\0';

    char gai[INET6_ADDRSTRLEN] = "ERR";
    struct addrinfo hints, *res = NULL;
    memset(&hints, 0, sizeof hints);
    hints.ai_flags = AI_NUMERICHOST;
    if (getaddrinfo(cut, NULL, &hints, &res) == 0) {
      if (res->ai_family == AF_INET) {
        ntop(AF_INET, &((struct sockaddr_in *)res->ai_addr)->sin_addr, gai, sizeof gai);
      } else {
        ntop(AF_INET6, &((struct sockaddr_in6 *)res->ai_addr)->sin6_addr, gai, sizeof gai);
      }
      freeaddrinfo(res);
    }

    char pton[INET6_ADDRSTRLEN] = "ERR";
    unsigned char buf[16];
    if (inet_pton(AF_INET, line, buf) == 1) {
      ntop(AF_INET, buf, pton, sizeof pton);
    } else if (inet_pton(AF_INET6, line, buf) == 1) {
      ntop(AF_INET6, buf, pton, sizeof pton);
    }

    printf("%s\t%s\t%s\n", line, gai, pton);
  }
  return 0;
}
