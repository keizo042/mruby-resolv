#ifndef MRB_DNS_TYPES_H
#define MRB_DNS_TYPES_H


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
} mrb_dns_header_t;

typedef struct mrb_dns_name_s {
        char *name;
        char count;
}mrb_dns_name_t;

typedef struct mrb_dns_question_s {
    mrb_dns_name_t *qname;
    uint16_t qtype;
    uint16_t qklass;
} mrb_dns_question_t;

typedef struct mrb_dns_rdata_s {
    mrb_dns_name_t *name;
    uint16_t type;
    uint16_t klass;
    uint16_t ttl;
    uint16_t rlength;
    char *rdata;
} mrb_dns_rdata_t;

typedef struct mrb_dns_pkt_s {
    mrb_dns_header_t *header;
    mrb_dns_question_t **questions;
    mrb_dns_rdata_t **answers;
    mrb_dns_rdata_t **authorities;
    mrb_dns_rdata_t **additionals;
} mrb_dns_pkt_t;

#endif
