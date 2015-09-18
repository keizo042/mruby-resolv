
#include<stdio.h>
#include<stdlib.h>

#include "mruby.h"
#include "mruby/string.h"
#include "mruby/class.h"
#include "mruby/data.h"
#include "mruby/variable.h"
#include "mruby/value.h"


typedef struct {
}mrb_resolv_data;

static void mrb_dns_free(mrb_state *mrb, void* p)
{

}

static const mrb_data_type mrb_dns_data_type = {
    "mrb_dns_data", mrb_dns_free,
};

static mrb_value mrb_dns_init(mrb_state *mrb, mrb_value self)
{
    return self;
}

static mrb_value mrb_dns_getaddress(mrb_state *mrb, mrb_value self)
{
    char *address = NULL;
    mrb_get_args(mrb,"z",address);


    return self;
}

static mrb_value mrb_dns_getname(mrb_state *mrb, mrb_value self)
{
    char *name= NULL;

    mrb_get_args(mrb,"z",name);

    return self;
}

static mrb_value mrb_dns_get_resource(mrb_state *mrb, mrb_value self)
{
    char *v = NULL;
    mrb_int rr;
    mrb_get_args(mrb,"zi",v,&rr);
    return self;
}

void mrb_mruby_resolv_gem_init(mrb_state *mrb)
{
    struct RClass *resolv,
                  *dns;
    resolv = mrb_class_get(mrb, "Resolv");
    dns = mrb_define_class(mrb,"DNS", resolv);
    MRB_SET_INSTANCE_TT(dns,MRB_TT_DATA);

    mrb_define_class_method(mrb,    dns, "initialize",      mrb_dns_init,              MRB_ARGS_NONE() );
    mrb_define_class_method(mrb,    dns, "getaddress",      mrb_dns_getaddress,        MRB_ARGS_REQ(1) );
    mrb_define_class_method(mrb,    dns, "getname",         mrb_dns_getname,         MRB_ARGS_REQ(1) );
    mrb_define_class_method(mrb,    dns, "getresource",     mrb_dns_get_resource,      MRB_ARGS_REQ(1));
}

void mrb_mruby_resolv_gem_final(mrb_state *mrb)
{
}
