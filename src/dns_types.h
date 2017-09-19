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

#define MRB_DNS_RECORD_A 1
#define MRB_DNS_RECORD_AAAA 28
#define MRB_DNS_RECORD_SOA 6
#define MRB_DNS_RECORD_MX 15
#define MRB_DNS_RECORD_ANY 255
#define MRB_DNS_RECORD_PTR 12
#define MRB_DNS_RECORD_TXT 16
#define MRB_DNS_RECORD_OPT 41
#define MRB_DNS_RECORD_NS 2
#define MRB_DNS_RECORD_CNAME 5
#define MRB_DNS_RECORD_SRV 33

typedef struct mrb_dns_rdata_data_s {
    union rdata {
            struct a {
                    uint8_t address[4];
            }a;
            struct a4 {
                    uint8_t address[16];
            }a4;
            struct soa {
                    mrb_dns_name_t *mname;
                    mrb_dns_name_t *rname;
                    uint32_t serial;
                    uint32_t refresh;
                    uint32_t _retry;
                    uint32_t expire;
                    uint32_t minimum;
            }soa;
            struct mx {
                    uint16_t preference;
                    mrb_dns_name_t *exchange;
            }mx;
            struct ns {
                    mrb_dns_name_t *nsdname;
            }ns;
            struct ptr {
                    mrb_dns_name_t *ptrdname;
            }ptr;
            struct txt {
                    uint8_t *buf;
            }txt;
            struct  cname {
                    mrb_dns_name_t *cname;
            }cname;
            struct srv {
            }srv;
            void *raw;
    }rdata;
}mrb_dns_rdata_data_t;

typedef struct mrb_dns_rdata_s {
    mrb_dns_name_t *name;
    uint16_t typ;
    uint16_t klass;
    uint32_t ttl;
    uint16_t rlength;
    union {
            uint8_t *rdata;
            struct {
                    uint8_t address[4];
            }a;
            struct {
                    mrb_dns_name_t *nsdname;
            }ns;
            struct {
                    uint16_t preference;
                    mrb_dns_name_t *exchange;

            }mx;
            struct {
                    uint8_t address[16];
            }aaaa;
            struct {
                    mrb_dns_name_t *mname;
                    mrb_dns_name_t *rname;
                    uint32_t serial;
                    uint32_t refresh;
                    uint32_t retry;
                    uint32_t expire;

            }soa;
            struct {
                    mrb_dns_name_t *ptrname;
            }ptr;
    }rdata;
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
                                   uint16_t klass, uint16_t rlength, mrb_dns_rdata_data_t *rdata) ;
mrb_dns_rdata_t*mrb_dns_rdata2ctype(mrb_state *, mrb_value);

mrb_dns_name_t *mrb_cstr2dns_name(mrb_state *mrb, const char *str) ;
#endif
