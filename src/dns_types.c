#include "dns_types.h"

#include "mruby.h"
#include "mruby/array.h"
#include "mruby/class.h"
#include "mruby/string.h"
#include "mruby/variable.h"
#include <stdint.h>
#include <string.h>


mrb_dns_pkt_t *mrb_dns_query2cpkt(mrb_state *mrb, mrb_value q) {
    struct RClass *qcls = NULL;
    mrb_value header, questions, answers, authorities, addtionals;
    mrb_dns_pkt_t *pkt = NULL;

    qcls = mrb_class_get_under(mrb, mrb_class_get_under(mrb, mrb_class_get(mrb, "Resolv"), "DNS"),
                               "Query");
    if (!mrb_obj_is_instance_of(mrb, q, qcls)) {
        mrb_raise(mrb, E_ARGUMENT_ERROR, "mrb_dns_question2ctype require Resolv::DNS::Query");
        return NULL;
    }

    pkt = (mrb_dns_pkt_t *)mrb_malloc(mrb, sizeof(mrb_dns_pkt_t));
    if (!pkt) {
        mrb_raise(mrb, E_RUNTIME_ERROR, "mrb_dns_query2cpkt: fail memory allocation");
        return NULL;
    }

    header      = mrb_iv_get(mrb, q, mrb_intern_lit(mrb, "@header"));
    questions   = mrb_iv_get(mrb, q, mrb_intern_lit(mrb, "@questions"));
    answers     = mrb_iv_get(mrb, q, mrb_intern_lit(mrb, "@answers"));
    authorities = mrb_iv_get(mrb, q, mrb_intern_lit(mrb, "@authorities"));
    addtionals  = mrb_iv_get(mrb, q, mrb_intern_lit(mrb, "@addtionals"));
    if (mrb_nil_p(header) && mrb_nil_p(questions) && mrb_nil_p(answers) && mrb_nil_p(authorities) &&
        mrb_nil_p(addtionals)) {
        mrb_raise(mrb, E_RUNTIME_ERROR, "not all iv is present");
        return NULL;
    }

    pkt->header = mrb_dns_header2ctype(mrb, header);
    if (!pkt->header) {
        mrb_raise(mrb, E_RUNTIME_ERROR, "empty Query.header");
        return NULL;
    }
    pkt->questions =
        (mrb_dns_question_t **)mrb_malloc(mrb, sizeof(mrb_dns_question_t *) * pkt->header->qdcount);
    for (int i = 0; i < pkt->header->qdcount; i++) {
        mrb_value qd;
        qd = mrb_ary_entry(questions, i);
        if (mrb_nil_p(qd)) {
            mrb_raise(mrb, E_RUNTIME_ERROR, "invaild qdcount in header");
            return NULL;
        }

        pkt->questions[i] = mrb_dns_question2ctype(mrb, qd);
    }

    pkt->answers =
        (mrb_dns_rdata_t **)mrb_malloc(mrb, sizeof(mrb_dns_rdata_t *) * pkt->header->ancount);
    for (int i = 0; i < pkt->header->ancount; i++) {
        mrb_value an;
        an = mrb_ary_entry(answers, i);
        if (mrb_nil_p(an)) {
            mrb_raise(mrb, E_RUNTIME_ERROR, "invaild ancount in header");
            return NULL;
        }

        pkt->answers[i] = mrb_dns_rdata2ctype(mrb, an);
    }

    pkt->authorities =
        (mrb_dns_rdata_t **)mrb_malloc(mrb, sizeof(mrb_dns_rdata_t *) * pkt->header->nscount);
    for (int i = 0; i < pkt->header->nscount; i++) {
        mrb_value ns;
        ns = mrb_ary_entry(authorities, i);
        if (mrb_nil_p(ns)) {
            mrb_raise(mrb, E_RUNTIME_ERROR, "invaild nscount in header");
            return NULL;
        }

        pkt->authorities[i] = mrb_dns_rdata2ctype(mrb, ns);
    }

    pkt->additionals =
        (mrb_dns_rdata_t **)mrb_malloc(mrb, sizeof(mrb_dns_rdata_t *) * pkt->header->arcount);
    for (int i = 0; i < pkt->header->arcount; i++) {
        mrb_value ar;
        ar = mrb_ary_entry(addtionals, i);
        if (mrb_nil_p(ar)) {
            mrb_raise(mrb, E_RUNTIME_ERROR, "invalid arcount in header");
            return NULL;
        }

        pkt->additionals[i] = mrb_dns_rdata2ctype(mrb, ar);
    }

    return pkt;
}

mrb_dns_header_t *mrb_dns_header_new(mrb_state *mrb, uint16_t id, unsigned qr, unsigned opcode,
                                     unsigned aa, unsigned tc, unsigned rd, unsigned ra,
                                     unsigned rcode, uint16_t qdcount, uint16_t ancount,
                                     uint16_t nscount, uint16_t arcount) {
    mrb_dns_header_t *hdr = NULL;
    if (!mrb)
        return NULL;

    if (opcode < 0 || 7 < opcode)
        return NULL;
    if (rcode < 0 || 15 < rcode)
        return NULL;

    hdr = (mrb_dns_header_t *)mrb_malloc(mrb, sizeof(mrb_dns_header_t));
    if (!hdr)
        return NULL;

    hdr->id      = id;
    hdr->qr      = qr ? 1 : 0;
    hdr->opcode  = opcode;
    hdr->aa      = aa ? 1 : 0;
    hdr->tc      = tc ? 1 : 0;
    hdr->rd      = rd ? 1 : 0;
    hdr->ra      = ra ? 1 : 0;
    hdr->rcode   = rcode;
    hdr->qdcount = qdcount;
    hdr->ancount = ancount;
    hdr->nscount = nscount;
    hdr->arcount = arcount;

    return hdr;
}


mrb_dns_header_t *mrb_dns_header2ctype(mrb_state *mrb, mrb_value hdr) {
    struct RClass *hcls;
    mrb_dns_header_t *c_hdr = NULL;
    mrb_value v;
#define p(v) (!mrb_nil_p(v) && mrb_fixnum_p(v))

    hcls = mrb_class_get_under(
        mrb, mrb_class_get_under(mrb, mrb_class_get_under(mrb, mrb_class_get(mrb, "Resolv"), "DNS"),
                                 "Query"),
        "Header");

    if (!mrb_obj_is_instance_of(mrb, hdr, hcls)) {
        mrb_raise(mrb, E_ARGUMENT_ERROR, "mrb_dns_header2ctype require Resolv::DNS::Query::Header");
        return NULL;
    }
    c_hdr = (mrb_dns_header_t *)mrb_malloc(mrb, sizeof(mrb_dns_header_t));
    if (!c_hdr) {
        mrb_raise(mrb, E_RUNTIME_ERROR, "something wrong, please see src/dns_types.c");
        return NULL;
    }
    v = mrb_iv_get(mrb, hdr, mrb_intern_lit(mrb, "@id"));
    if (p(v))
        c_hdr->id = mrb_fixnum(v);

    v = mrb_iv_get(mrb, hdr, mrb_intern_lit(mrb, "@qr"));
    if (p(v))
        c_hdr->qr = mrb_fixnum(v);

    v = mrb_iv_get(mrb, hdr, mrb_intern_lit(mrb, "@opcode"));
    if (p(v))
        c_hdr->opcode = mrb_fixnum(v);

    v = mrb_iv_get(mrb, hdr, mrb_intern_lit(mrb, "@aa"));
    if (p(v))
        c_hdr->aa = mrb_fixnum(v);

    v = mrb_iv_get(mrb, hdr, mrb_intern_lit(mrb, "@tc"));
    if (p(v))
        c_hdr->tc = mrb_fixnum(v);

    v = mrb_iv_get(mrb, hdr, mrb_intern_lit(mrb, "@rd"));
    if (p(v))
        c_hdr->rd = mrb_fixnum(v);

    v = mrb_iv_get(mrb, hdr, mrb_intern_lit(mrb, "@ra"));
    if (p(v))
        c_hdr->ra = mrb_fixnum(v);

    c_hdr->z  = 0;
    c_hdr->ad = 0;
    c_hdr->cd = 0;

    v = mrb_iv_get(mrb, hdr, mrb_intern_lit(mrb, "@rcode"));
    if (p(v))
        c_hdr->rcode = mrb_fixnum(v);

    v = mrb_iv_get(mrb, hdr, mrb_intern_lit(mrb, "@qdcount"));
    if (p(v))
        c_hdr->qdcount = mrb_fixnum(v);

    v = mrb_iv_get(mrb, hdr, mrb_intern_lit(mrb, "@ancount"));
    if (p(v))
        c_hdr->ancount = mrb_fixnum(v);

    v = mrb_iv_get(mrb, hdr, mrb_intern_lit(mrb, "@nscount"));
    if (p(v))
        c_hdr->nscount = mrb_fixnum(v);

    v = mrb_iv_get(mrb, hdr, mrb_intern_lit(mrb, "@arcount"));
    if (!mrb_nil_p(v))
        c_hdr->arcount = mrb_fixnum(v);
    return c_hdr;
}

mrb_value mrb_dns_header_value(mrb_state *mrb, mrb_dns_header_t *c_hdr) {
    mrb_value hdr, *argv;
    const mrb_int argc = 12;
    struct RClass *cls = NULL;

    cls = mrb_class_get_under(
        mrb, mrb_class_get_under(mrb, mrb_class_get_under(mrb, mrb_class_get(mrb, "Resolv"), "DNS"),
                                 "Query"),
        "Header");
    if (!cls) {
        mrb_raise(mrb, E_RUNTIME_ERROR, "not found \"Resolv::DNS::Query::Header\" class");
        return mrb_nil_value();
    }
    argv     = (mrb_value *)mrb_malloc(mrb, argc * sizeof(mrb_value));
    argv[0]  = mrb_fixnum_value(c_hdr->id);
    argv[1]  = mrb_fixnum_value(c_hdr->qr);
    argv[2]  = mrb_fixnum_value(c_hdr->opcode);
    argv[3]  = mrb_fixnum_value(c_hdr->aa);
    argv[4]  = mrb_fixnum_value(c_hdr->tc);
    argv[5]  = mrb_fixnum_value(c_hdr->rd);
    argv[6]  = mrb_fixnum_value(c_hdr->ra);
    argv[7]  = mrb_fixnum_value(c_hdr->rcode);
    argv[8]  = mrb_fixnum_value(c_hdr->qdcount);
    argv[9]  = mrb_fixnum_value(c_hdr->ancount);
    argv[10] = mrb_fixnum_value(c_hdr->nscount);
    argv[11] = mrb_fixnum_value(c_hdr->arcount);


    hdr = mrb_obj_new(mrb, cls, argc, argv);
    mrb_free(mrb, argv);

    if (mrb_nil_p(hdr)) {
        mrb_raise(mrb, E_RUNTIME_ERROR, "invaild heade value");
        return mrb_nil_value();
    }
    return hdr;
}
mrb_dns_question_t *mrb_dns_question_new(mrb_state *mrb, mrb_dns_name_t *name, uint16_t typ,
                                         uint16_t klass) {
    mrb_dns_question_t *q = NULL;
    if (!mrb)
        return NULL;

    q = (mrb_dns_question_t *)mrb_malloc(mrb, sizeof(mrb_dns_question_t));
    if (!q)
        return NULL;

    q->qname  = name;
    q->qtype  = typ;
    q->qklass = klass;
    return q;
}

mrb_dns_question_t *mrb_dns_question2ctype(mrb_state *mrb, mrb_value obj) {
    struct RClass *qcls;
    mrb_value qname, qtype, qklass;
    mrb_dns_question_t *q = NULL;

    qcls = mrb_class_get_under(
        mrb, mrb_class_get_under(mrb, mrb_class_get_under(mrb, mrb_class_get(mrb, "Resolv"), "DNS"),
                                 "Query"),
        "Question");
    if (!mrb_obj_is_instance_of(mrb, obj, qcls)) {
        mrb_raise(mrb, E_ARGUMENT_ERROR,
                  "mrb_dns_question2ctype require Resolv::DNS::Query::Question");
        return NULL;
    }

    qname = mrb_iv_get(mrb, obj, mrb_intern_lit(mrb, "@qname"));
    if (mrb_nil_p(qname)) {
        mrb_raise(mrb, E_RUNTIME_ERROR, "empty Question.qname");
        return NULL;
    }

    qtype = mrb_iv_get(mrb, obj, mrb_intern_lit(mrb, "@qtype"));
    if (mrb_nil_p(qtype)) {
        mrb_raise(mrb, E_RUNTIME_ERROR, "empty Question.qname");
        return NULL;
    }

    qklass = mrb_iv_get(mrb, obj, mrb_intern_lit(mrb, "@qklass"));
    if (mrb_nil_p(qklass)) {
        mrb_raise(mrb, E_RUNTIME_ERROR, "empty Question.qname");
        return NULL;
    }
    q = (mrb_dns_question_t *)mrb_malloc(mrb, sizeof(mrb_dns_question_t));

    q->qname  = mrb_cstr2dns_name(mrb, mrb_str_to_cstr(mrb, qname));
    q->qtype  = mrb_fixnum(qtype);
    q->qklass = mrb_fixnum(qklass);
    return q;
}

mrb_dns_rdata_t *mrb_dns_rdata_new(mrb_state *mrb, mrb_dns_name_t *name, uint16_t typ,
                                   uint16_t klass, uint16_t rlength, uint8_t *rdata) {
    mrb_dns_rdata_t *r = NULL;
    if (!mrb)
        return NULL;
    r = (mrb_dns_rdata_t *)mrb_malloc(mrb, sizeof(mrb_dns_rdata_t));
    if (!r)
        return NULL;

    r->name    = name;
    r->typ     = typ;
    r->klass   = klass;
    r->rlength = sizeof(rdata) / sizeof(uint8_t);
    r->rdata   = rdata;

    return r;
}

mrb_dns_rdata_t *mrb_dns_rdata2ctype(mrb_state *mrb, mrb_value obj) {
    mrb_value name, typ, klass, ttl, rlength, rdata;
    mrb_dns_rdata_t *r = NULL;
    if (mrb_nil_p(obj)) {
        mrb_raise(mrb, E_RUNTIME_ERROR, "nil value");
        return NULL;
    }
    name    = mrb_iv_get(mrb, obj, mrb_intern_lit(mrb, "@name"));
    typ     = mrb_iv_get(mrb, obj, mrb_intern_lit(mrb, "@type"));
    klass   = mrb_iv_get(mrb, obj, mrb_intern_lit(mrb, "@klass"));
    ttl     = mrb_iv_get(mrb, obj, mrb_intern_lit(mrb, "@ttl"));
    rlength = mrb_iv_get(mrb, obj, mrb_intern_lit(mrb, "@rlength"));
    rdata   = mrb_iv_get(mrb, obj, mrb_intern_lit(mrb, "@rdata"));
    if (mrb_nil_p(name)) {
        mrb_raise(mrb, E_RUNTIME_ERROR, "types: empty name in RData");
        return NULL;
    }
    if (mrb_nil_p(typ)) {
        mrb_raise(mrb, E_RUNTIME_ERROR, "types: empty type in RData");
        return NULL;
    }
    if (mrb_nil_p(klass)) {
        mrb_raise(mrb, E_RUNTIME_ERROR, "types: empty class in RData");
        return NULL;
    }
    if (mrb_nil_p(ttl)) {
        mrb_raise(mrb, E_RUNTIME_ERROR, "types: empty ttl in RData");
        return NULL;
    }
    if (mrb_nil_p(rlength)) {
        mrb_raise(mrb, E_RUNTIME_ERROR, "types: empty rlength in RData");
        return NULL;
    }
    if ((mrb_nil_p(rdata))) {
        mrb_raise(mrb, E_RUNTIME_ERROR, "types: empty rdata in RData");
        return NULL;
    }

    r = (mrb_dns_rdata_t *)mrb_malloc(mrb, sizeof(mrb_dns_rdata_t));
    if (!r) {
        mrb_raise(mrb, E_RUNTIME_ERROR, "memory error");
        return NULL;
    }
    r->name    = mrb_cstr2dns_name(mrb, RSTRING_PTR(name));
    r->typ     = mrb_fixnum(typ);
    r->klass   = mrb_fixnum(klass);
    r->ttl     = mrb_fixnum(ttl);
    r->rlength = mrb_fixnum(rlength);
    r->rdata   = (uint8_t *)mrb_str_to_cstr(mrb, rdata);
    return NULL;
}


// TODO: support offset compression
mrb_dns_name_t *mrb_cstr2dns_name(mrb_state *mrb, const char *str) {
    mrb_dns_name_t *name = NULL;
    size_t len;

    if (!str) {
        mrb_raise(mrb, E_ARGUMENT_ERROR, "mrb_cstr2dns_name: str");
        return NULL;
    }

    name = (mrb_dns_name_t *)mrb_malloc(mrb, sizeof(mrb_dns_name_t));
    len  = strlen(str);

    name->name = (char *)mrb_malloc(mrb, len + 1);
    name->len = len;
    strncpy(name->name, str, len + 1);
    return name;
}
