#include "mruby.h"
#include "mruby/object.h"

#include "dns_codec.h"
#include "dns_types.h"


mrb_dns_rdata_data_t *mrb_dns_codec_get_rdata_data(mrb_state *mrb, mrb_dns_get_state *getter,
                                                   uint16_t typ) {
    mrb_dns_rdata_data_t *rdata = mrb_malloc(mrb, sizeof(mrb_dns_rdata_data_t));
    switch (typ) {
    case MRB_DNS_RECORD_A:
    case MRB_DNS_RECORD_AAAA:
    case MRB_DNS_RECORD_SOA:
    case MRB_DNS_RECORD_MX:
    case MRB_DNS_RECORD_PTR:
    case MRB_DNS_RECORD_ANY:
    case MRB_DNS_RECORD_TXT:
    case MRB_DNS_RECORD_NS:
    case MRB_DNS_RECORD_OPT:
    case MRB_DNS_RECORD_CNAME:
    case MRB_DNS_RECORD_SRV:

    default:
        return NULL;
    }
    return rdata;
}
