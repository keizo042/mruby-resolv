#ifndef MRB_RESOLVER_H
#define MRB_RESOLVER_H

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <unistd.h>

#include <sys/types.h>
#include <sys/socket.h>
#include <netdb.h>

#include <netinet/in.h>
#include <arpa/inet.h>

#include <errno.h>
#include <sys/select.h>

#define UDP_LEN 65535

#define PACKED_RRECORD_LEN(x) (x & (0xc000 ^ 0xffff))

typedef struct dns_header {

    uint16_t id;


    uint8_t rd :1;
    uint8_t zero :3;
    uint8_t rcode :4;
    uint8_t ra :1;

    uint8_t qr :1;
    uint8_t opcode :4;
    uint8_t  aa :1;
    uint8_t tc :1;

    uint16_t qdcount;

    uint16_t ancount;

    uint16_t nscount ;

    uint16_t arcount;

}dns_header;

typedef struct dns_question {
    uint16_t qtype;
    uint16_t qclass;
}dns_question;


typedef struct dns_query {
    char* qname; 
    int qtype;   
    int qclass;  
    char** rdata; /* array of rdata items, NULL terminated*/
    int* legnth;    /* array with lengths of rdata items */
    char* canonname; 
    int rcode;   
    void* answer_packet;
    int answer_len; 
    int havedata;
    int nxdomain; 
    int secure;  
    int bogus;   
    int ttl;
}dns_query;


typedef struct dns_rrecord{
    uint16_t type;
    uint16_t klass;
    uint32_t ttl;
    uint16_t rdlength;
    void *rdata;
}dns_rrecord;

typedef struct dns_context {
    dns_header header;
    dns_question question;
    dns_rrecord *answer;
    dns_rrecord *authority;
    dns_rrecord *addtional;
}dns_context;



//==============================



dns_context* mrb_resolver_new();
int dns_context_set(dns_context *,char *,int,int);
int mrb_resolver(dns_context *query, dns_context *result);
int parse_records(dns_context *r);
char* format2fqdn(char *name);
char* fqdn2format(char *name);
#endif
