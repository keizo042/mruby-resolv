#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "mruby.h"
#include "mruby/array.h"
#include "mruby/class.h"
#include "mruby/data.h"
#include "mruby/hash.h"
#include "mruby/string.h"
#include "mruby/value.h"
#include "mruby/variable.h"

#include "dns_codec.h"
#include "dns_types.h"


/**
 *
 * Resolv::DNS::Codec class
 *
 **/

/**
 * Resolv::DNS::Codec#initialize
 **/
static mrb_value mrb_dns_codec_init(mrb_state *mrb, mrb_value self) { return self; }

/**
 * Resolv::DNS::Codec#decode(bytes)
 * @param bytes is [Fixnum]
 * @return Resolv::DNS::Query
 **/

static mrb_value mrb_dns_codec_decode(mrb_state *mrb, mrb_value self) {
    mrb_value buff;
    mrb_value query           = mrb_nil_value();
    mrb_dns_get_state *getter = NULL;
    mrb_dns_pkt_t *pkt        = NULL;
    uint8_t *b                = NULL;
    mrb_int len;

    mrb_get_args(mrb, "o", &buff);
    if (!mrb_array_p(buff)) {
        mrb_raise(mrb, E_ARGUMENT_ERROR, "require Array of Fixnum 0~255");
        return mrb_nil_value();
    }

    len = RARRAY_LEN(buff);
    b   = (uint8_t *)mrb_malloc(mrb, len * sizeof(uint8_t));
    for (int i = 0; i < len; i++) {
        b[i] = mrb_fixnum(mrb_ary_entry(buff, i));
    }

    getter = mrb_dns_codec_get_open(mrb, b, len);
    if (!getter) {
        mrb_raise(mrb, E_RUNTIME_ERROR, "fail memory allocation");
        return mrb_nil_value();
    }
    pkt = mrb_dns_codec_get(mrb, getter);
    if (!pkt) {
        mrb_raise(mrb, E_RUNTIME_ERROR, "fail decode"); // TODO: therea are prefer exception
        return mrb_nil_value();
    }

    return mrb_dns_ctype2query(mrb, pkt);
}


/**
 * Resolv::DNS::Codec#encode(query)
 *
 * @param query is a Resolv::DNS::Query
 * @return [Fixnum]
 **/

static mrb_value mrb_dns_codec_encode(mrb_state *mrb, mrb_value self) {
    int ret    = 0;
    uint8_t *b = NULL;

    mrb_value p, bytes;
    mrb_dns_put_state *putter = NULL;
    mrb_dns_pkt_t *pkt        = NULL;

    mrb_get_args(mrb, "o", &p);
    if (!mrb_obj_is_kind_of(
            mrb, p,
            mrb_class_get_under(mrb, mrb_class_get_under(mrb, mrb_class_get(mrb, "Resolv"), "DNS"),
                                "Query"))) {
        mrb_raisef(mrb, E_ARGUMENT_ERROR, "Resolv::DNS::Query");
        return mrb_nil_value();
    }

    pkt = mrb_dns_query2cpkt(mrb, p);
    if (!pkt) {
        mrb_raise(mrb, E_RUNTIME_ERROR, "Resolv#encode: faliure converting to c ");
        return mrb_nil_value();
    }

    putter = mrb_dns_codec_put_open(mrb);
    if (!putter) {
        mrb_raise(mrb, E_RUNTIME_ERROR, "Resolv#encode: invaild putter state");
        return mrb_nil_value();
    }

    ret = mrb_dns_codec_put(mrb, putter, pkt);
    if (ret) {
        char buff[1024];
        sprintf(buff, "Resolv#encode failure: ecode %d", ret);
        mrb_raisef(mrb, E_RUNTIME_ERROR, buff);
        return mrb_nil_value();
    }

    b     = mrb_dns_codec_put_result(mrb, putter);
    bytes = mrb_ary_new(mrb);
    for (int i = 0; i < putter->size; i++) 
        mrb_ary_push(mrb, bytes, mrb_fixnum_value(b[i]));

    mrb_dns_codec_put_close(mrb, putter);
    return bytes;
}


/**
 * Init
 **/

void mrb_mruby_resolv_gem_init(mrb_state *mrb) {
    struct RClass *resolv = NULL, *dns = NULL, *codec = NULL;
    resolv = mrb_define_class(mrb, "Resolv", mrb->object_class);
    MRB_SET_INSTANCE_TT(resolv, MRB_TT_DATA);

    dns = mrb_define_class_under(mrb, resolv, "DNS", mrb->object_class);
    MRB_SET_INSTANCE_TT(dns, MRB_TT_DATA);

    codec = mrb_define_class_under(mrb, dns, "Codec", mrb->object_class);

    mrb_define_method(mrb, codec, "initialize", mrb_dns_codec_init, MRB_ARGS_NONE());
    mrb_define_method(mrb, codec, "decode", mrb_dns_codec_decode, MRB_ARGS_REQ(1));
    mrb_define_method(mrb, codec, "encode", mrb_dns_codec_encode, MRB_ARGS_REQ(1));
}

void mrb_mruby_resolv_gem_final(mrb_state *mrb) {}
