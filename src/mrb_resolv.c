#include <stdio.h>
#include <stdlib.h>

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

static mrb_value mrb_resolv_init(mrb_state *mrb, mrb_value self) {
    char *cache_server            = NULL;
    const char *google_public_dns = "8.8.8.8";
    struct RClass *resolv         = NULL;

    resolv = mrb_module_get(mrb, "Resolv");

    mrb_get_args(mrb, "|z", &cache_server);

    if (cache_server == NULL) {
        cache_server = (char *)mrb_malloc(mrb, strlen(google_public_dns));
        strncpy(cache_server, google_public_dns, strlen(google_public_dns));
    }

    mrb_iv_set(mrb, mrb_cptr_value(mrb, resolv), mrb_intern_lit(mrb, "defaultResolver"),
               mrb_str_new_cstr(mrb, cache_server));

    return self;
}


static mrb_value mrb_dns_init(mrb_state *mrb, mrb_value self) {

    mrb_value option;

    if (mrb_get_args(mr, b "|o", &option) > 1) {
    }
    return self;
}

static mrb_value mrb_dns_getaddress(mrb_state *mrb, mrb_value self) {
    mrb_value address   = NULL;
    dns_context *query  = NULL;
    dns_context *result = NULL;

    mrb_get_args(mrb, "o", &address);

    return mrb_nil_value();
}

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

void mrb_mruby_resolv_gem_init(mrb_state *mrb) {
    struct RClass *resolv, *dns;
    resolv = mrb_define_class(mrb, "Resolv", mrb->object_class);
    dns    = mrb_define_class_under(mrb, resolv, "DNS", mrb->object_class);
    MRB_SET_INSTANCE_TT(resolv, MRB_TT_DATA);
    MRB_SET_INSTANCE_TT(dns, MRB_TT_DATA);

    mrb_define_method(mrb, resolv, "initialize", mrb_resolv_init, MRB_ARGS_ANY());

    mrb_define_method(mrb, dns, "initialize", mrb_dns_init, MRB_ARGS_ANY());

    mrb_define_method(mrb, dns, "getaddress", mrb_dns_getaddress, MRB_ARGS_REQ(1));
    mrb_define_method(mrb, dns, "getname", mrb_dns_getaddress, MRB_ARGS_REQ(1));
    mrb_define_method(mrb, dns, "getresource", mrb_dns_get_resource, MRB_ARGS_REQ(2));
    mrb_define_method(mrb, dns, "getresources", mrb_dns_get_resource, MRB_ARGS_REQ(2));
}

void mrb_mruby_resolv_gem_final(mrb_state *mrb) {}
