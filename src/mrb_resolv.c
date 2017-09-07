#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "mruby.h"
#include "mruby/array.h"
#include "mruby/class.h"
#include "mruby/data.h"
#include "mruby/string.h"
#include "mruby/value.h"
#include "mruby/variable.h"


typedef struct {
} mrb_dns_data;

static void mrb_dns_free(mrb_state *mrb, void *p) {}

static const mrb_data_type mrb_dns_data_type = {
    "mrb_dns_data", mrb_dns_free,
};

/**
  *
  * Resolv  class
  *
 **/

/**
 * Resolv#initialize
 **/

static mrb_value mrb_resolv_init(mrb_state *mrb, mrb_value self) {
    char *cache_server            = NULL;
    const char *google_public_dns = "8.8.8.8";
    struct RClass *resolv         = NULL;

    resolv = mrb_module_get(mrb, "Resolv");

    // TODO:  
    // mrb_get_args(mrb, "|z", &cache_server);

    if (cache_server == NULL) {
        cache_server = (char *)mrb_malloc(mrb, strlen(google_public_dns));
        strncpy(cache_server, google_public_dns, strlen(google_public_dns));
    }

    return self;
}

/**
 *
 * Resolv::DNS class
 *
 **/

/**
 * Resolv::DNS#initialize
 **/
static mrb_value mrb_dns_init(mrb_state *mrb, mrb_value self) {

    mrb_value option;

    if (mrb_get_args(mrb, "|o", &option) > 1) {
    }
    return self;
}

/**
 * Resolv::DNS#getaddress
 **/

static mrb_value mrb_dns_getaddress(mrb_state *mrb, mrb_value self) {
    mrb_value address;

    mrb_get_args(mrb, "o", &address);

    return mrb_nil_value();
}

/**
 * Resolv::DNS#getname
 **/

static mrb_value mrb_dns_getname(mrb_state *mrb, mrb_value self) {
    mrb_value name;

    mrb_get_args(mrb, "o", &name);

    return self;
}

static mrb_value mrb_dns_get_resource(mrb_state *mrb, mrb_value self) {
    mrb_value v;
    mrb_int rr;
    mrb_get_args(mrb, "oi", &v, &rr);
    return mrb_nil_value();
}

static mrb_value mrb_dns_get_resources(mrb_state *mrb, mrb_value self) {
    mrb_value v;
    mrb_int rrecord;

    mrb_get_args(mrb, "oi", &v, &rrecord);
    return mrb_nil_value();
}

/**
 * Init
 **/

void mrb_mruby_resolv_dns_init(mrb_state *mrb, struct RClass *dns) {
    mrb_define_method(mrb, dns, "initialize", mrb_dns_init, MRB_ARGS_ANY());

    mrb_define_method(mrb, dns, "getaddress", mrb_dns_getaddress, MRB_ARGS_REQ(1));
    mrb_define_method(mrb, dns, "getname", mrb_dns_getaddress, MRB_ARGS_REQ(1));
    mrb_define_method(mrb, dns, "getresource", mrb_dns_get_resource, MRB_ARGS_REQ(2));
    mrb_define_method(mrb, dns, "getresources", mrb_dns_get_resource, MRB_ARGS_REQ(2));
}

void mrb_mruby_resolv_dns_resource_init(mrb_state *mrb, struct RClass *dns) {
    struct RClass *rsrc, *in;
    struct RClass *a, *aaaa, *mx, *soa, *any, *txt, *ptr, *cname;
    resrc = mrb_define_class_under(mrb, dns, "Resource", mrb->object_class);
    in   = mrb_define_module_under(mrb, resrc, "IN");

    a     = mrb_define_class_under(mrb, in, "A",        mrb->object_class);
    MRB_SET_INSTANCE_TT(a, MRB_TT_DATA);
    aaaa  = mrb_define_class_under(mrb, in, "AAAA",     mrb->object_class);
    MRB_SET_INSTANCE_TT(aaaa, MRB_TT_DATA);
    mx    = mrb_define_class_under(mrb, in, "MX",       mrb->object_class);
    MRB_SET_INSTANCE_TT(mx, MRB_TT_DATA);
    soa   = mrb_define_class_under(mrb, in, "SOA",      mrb->object_class);
    MRB_SET_INSTANCE_TT(soa, MRB_TT_DATA);
    any   = mrb_define_class_under(mrb, in, "ANY",      mrb->object_class);
    MRB_SET_INSTANCE_TT(any, MRB_TT_DATA);
    txt   = mrb_define_class_under(mrb, in, "TXT",      mrb->object_class);
    MRB_SET_INSTANCE_TT(txt, MRB_TT_DATA);
    ptr   = mrb_define_class_under(mrb, in, "PTR",      mrb->object_class);
    MRB_SET_INSTANCE_TT(ptr, MRB_TT_DATA);
    cname = mrb_define_class_under(mrb, in, "CNAME",    mrb->object_class);
    MRB_SET_INSTANCE_TT(cname, MRB_TT_DATA);
}

void mrb_mruby_resolv_errors_init(mrb_state *mrb)
{
    struct RClass *resolv, *dns, *requester;
    resolv = mrb_class_get(mrb, "Resolv");
    dns = mrb_class_get_under(mrb, "DNS", resolv);
    requester = mrb_define_class_under(mrb, dns, "Requester", mrb->object_class);


    // Resolv
    mrb_define_class_under(mrb, resolv, "DecodeError", mrb->StandardError_class);
    mrb_define_class_under(mrb, resolv, "EncodeError", mrb->StandardError_class);
    
    // DNS
    mrb_define_class_under(mrb, dns, "ResolvError", mrb->StandardError_class);

    // Requester
    mrb_define_class_under(mrb, requester, "RequestError", mrb->StandardError_class);
}


void mrb_mruby_resolv_gem_init(mrb_state *mrb) {
    struct RClass *resolv = NULL, *dns = NULL;
    resolv = mrb_define_class(mrb, "Resolv", mrb->object_class);
    MRB_SET_INSTANCE_TT(resolv, MRB_TT_DATA);

    dns = mrb_define_class_under(mrb, resolv, "DNS", mrb->object_class);
    MRB_SET_INSTANCE_TT(dns, MRB_TT_DATA);

    mrb_define_method(mrb, resolv, "initialize", mrb_resolv_init, MRB_ARGS_ANY());

    mrb_mruby_resolv_dns_init(mrb, dns);
    mrb_mruby_resolv_dns_resource_init(mrb, dns);
    mrb_mruby_resolv_errors_init(mrb);
}

void mrb_mruby_resolv_gem_final(mrb_state *mrb) {}
