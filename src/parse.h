#ifndef PARSER_H
#define PARSER_H

#include "resolver.h"
#include "mrb_resolv.h"
void dns_debug_pp(dns_context* query);

typedef struct dns_result {
    int ans_count;
    char **ans_list;
    dns_rrecord **records;
}dns_result;

#endif
