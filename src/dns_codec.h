#ifndef MRB_DNS_CODEC_H
#define MRB_DNS_CODEC_H

#include <stdint.h>

#if __linux__ == 1
#include <arpa/inet.h>
#endif

#include "mruby.h"
#include "dns_resolver.h"

typedef struct mrb_dns_put_s {
        char *buff;
        uint64_t size;
}mrb_dns_put_state;

typedef struct mrb_dns_get_s {
        char *buff;
        uint64_t pos;
        uint64_t end;
}mrb_dns_get_state;

#endif
