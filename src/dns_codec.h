#ifndef MRB_DNS_CODEC_H
#define MRB_DNS_CODEC_H

#include <stdint.h>

#if __linux__ == 1
#include <arpa/inet.h>
#endif

#include "mruby.h"
#include <stdint.h>

#include "dns_types.h"

#define MRB_GETTER_PEEK(getter) ((getter)->buff + (getter)->pos)

/**
  * put data
  **/

typedef struct mrb_dns_put_s {
        uint8_t *buff;
        uint64_t size;
}mrb_dns_put_state;


mrb_dns_put_state *mrb_dns_codec_put_open(mrb_state *);
int mrb_dns_codec_put_close(mrb_state *mrb, mrb_dns_put_state *) ;
int mrb_dns_codec_put(mrb_state *, mrb_dns_put_state*, mrb_dns_pkt_t *);
uint8_t *mrb_dns_codec_put_result(mrb_state *, mrb_dns_put_state*);

/**
  * get data
  **/

typedef struct mrb_dns_get_s {
        uint8_t *buff;
        uint64_t pos;
        uint64_t end;
}mrb_dns_get_state;

mrb_dns_get_state *mrb_dns_codec_get_open(mrb_state *, uint8_t *, size_t len) ;
int mrb_dns_codec_get_close(mrb_state *, mrb_dns_get_state *) ;
mrb_dns_pkt_t *mrb_dns_codec_get(mrb_state *, mrb_dns_get_state *);

#endif
