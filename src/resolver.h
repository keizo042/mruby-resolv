#ifndef MRB_RESOLV_RESOLVER_H
#define MRB_RESOLV_RESOLVER_H
#include "mruby.h"
#include <stdint.h>
#include <string.h>

#define MRB_RESOLV_RESOLVER_VERSION "0.1.0"
#define MRB_RESOLV_RESOLVER_VARSION_MAJOR 0
#define MRB_RESOLV_RESOLVER_VARSION_MINOR_FIRST 1
#define MRB_RESOLV_RESOLVER_VERSION_MINOR_LAST 0



typedef struct mrb_dns_question_s {
    uint64_t qname;
    uint16_t qtype;
    uint16_t qklass;
} mrb_dns_question;

typedef struct mrb_dns_rdata_s {
    uint64_t name;
    uint16_t type;
    uint16_t klass;
    uint16_t ttl;
    uint16_t rlength;
    char *rdata;
} mrb_dns_rdata;

typedef struct mrb_dns_header_s {
    uint16_t id;
    unsigned qr : 1;
    unsigned opcode : 4;
    unsigned aa : 1;
    unsigned tc : 1;
    unsigned rd : 1;
    unsigned ra : 1;
    unsigned z : 3;
    unsigned rcode : 4;
    uint16_t qdcount;
    uint16_t ancount;
    uint16_t nscount;
    uint16_t arcount;
} mrb_dns_header;

typedef struct mrb_dns_body_s { char *body; } mrb_dns_body;

typedef struct mrb_dns_s {
    mrb_dns_header header;
    mrb_dns_body body;
} mrb_dns_t;

typedef struct mrb_dns_lex_s {
    char *start;
    uint64_t pos;
    mrb_dns_t *data;
} mrb_dns_lex;

typedef struct mrb_dns_state_s { mrb_dns_header *header; } mrb_dns_state;

mrb_dns_lex *mrb_resolver_lex();
mrb_dns_state *mrb_resolver_new();
int mrb_resolver_getresources(mrb_state *mrb, mrb_dns_state *, mrb_value, mrb_int);
#endif
