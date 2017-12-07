#ifndef _MRB_DNS_RDATA_H
#define _MRB_DNS_RDATA_H


#include "dns_types.h"
#include "dns_codec.h"
#include <stdint.h>

mrb_dns_rdata_data_t* mrb_dns_codec_get_rdata_data(mrb_state *, mrb_dns_get_state*,  uint16_t);

#endif
