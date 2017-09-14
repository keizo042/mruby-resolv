#ifndef MRB_DNS_TYPES_H
#define MRB_DNS_TYPES_H

#include "mruby.h"
#include <stdint.h>

typedef struct mrb_dns_header_s {
    uint16_t id;
    unsigned qr : 1;
    unsigned opcode : 4;
    unsigned aa : 1;
    unsigned tc : 1;
    unsigned rd : 1;
    unsigned ra : 1;
    unsigned z : 1;
    unsigned ad : 1;
    unsigned cd : 1;
    unsigned rcode : 4;
    uint16_t qdcount;
    uint16_t ancount;
    uint16_t nscount;
    uint16_t arcount;
} mrb_dns_header_t;

typedef struct mrb_dns_name_s {
        char *name;
        size_t len;
}mrb_dns_name_t;

typedef struct mrb_dns_question_s {
    mrb_dns_name_t *qname;
    uint16_t qtype;
    uint16_t qklass;
} mrb_dns_question_t;

typedef struct mrb_dns_rdata_s {
    mrb_dns_name_t *name;
    uint16_t typ;
    uint16_t klass;
    uint16_t ttl;
    uint16_t rlength;
    uint8_t *rdata;
} mrb_dns_rdata_t;

typedef struct mrb_dns_pkt_s {
    mrb_dns_header_t *header;
    mrb_dns_question_t **questions;
    mrb_dns_rdata_t **answers;
    mrb_dns_rdata_t **authorities;
    mrb_dns_rdata_t **additionals;
} mrb_dns_pkt_t;


/**
 *
 * functions
 *
 *
 **/

mrb_dns_pkt_t *mrb_dns_query2cpkt(mrb_state *, mrb_value);
mrb_value mrb_dns_ctype2query(mrb_state *, mrb_dns_pkt_t*);

mrb_dns_header_t *mrb_dns_header_new(mrb_state *mrb, uint16_t id, unsigned qr, unsigned opcode,
                                       unsigned aa, unsigned tc, unsigned rd, unsigned ra,
                                       unsigned rcode, uint16_t qdcount, uint16_t ancount,
                                       uint16_t nscount, uint16_t arcount) ;

mrb_dns_header_t *mrb_dns_header2ctype(mrb_state *, mrb_value);
mrb_dns_question_t *mrb_dns_question_new(mrb_state *mrb, mrb_dns_name_t *name, uint16_t typ,
                                         uint16_t klass) ;
mrb_dns_question_t *mrb_dns_question2ctype(mrb_state *, mrb_value);

mrb_dns_rdata_t *mrb_dns_rdata_new(mrb_state *mrb, mrb_dns_name_t *name, uint16_t typ,
                                   uint16_t klass, uint16_t rlength, uint8_t *rdata) ;
mrb_dns_rdata_t*mrb_dns_rdata2ctype(mrb_state *, mrb_value);

mrb_dns_name_t *mrb_cstr2dns_name(mrb_state *mrb, const char *str) ;
#endif
