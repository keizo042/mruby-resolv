#ifndef MRB_RESOLV_RESOLVER_H
#define MRB_RESOLV_RESOLVER_H

#include "mruby.h"

#include <stdint.h>
#include <string.h>


#if __linux__ == 1
#include <sys/socket.h>
#include <sys/types.h>
#include <unistd.h>
#endif

#include "dns_types.h"
#include "dns_codec.h"

#define MRB_RESOLV_RESOLVER_VERSION "0.1.0"
#define MRB_RESOLV_RESOLVER_VARSION_MAJOR 0
#define MRB_RESOLV_RESOLVER_VARSION_MINOR_FIRST 1
#define MRB_RESOLV_RESOLVER_VERSION_MINOR_LAST 0

typedef struct mrb_dns_state_s {
    int sock;

    struct sockaddr_in *saddr;
    int slen;
} mrb_dns_state;

typedef struct mrb_dns_option_s {
    int tcp;
    uint32_t nameserver;
} mrb_dns_option_t;

typedef struct mrb_dns_info_s {
  struct sockaddr_in *server;
  mrb_dns_option_t *option;
}mrb_dns_info_t;


mrb_dns_state *mrb_resolver_new(mrb_dns_option *);
int mrb_resolver_getresources(mrb_state *mrb, mrb_dns_state *, mrb_value, mrb_int);
#endif
