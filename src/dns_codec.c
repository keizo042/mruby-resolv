
#include "mruby.h"

#include "dns_codec.h"
#include "dns_types.h"

/**
 * Put
 **/

mrb_dns_put_state *mrb_dns_codec_put_open(mrb_state *mrb) {
    mrb_dns_put_state *putter = (mrb_dns_put_state *)mrb_malloc(mrb, sizeof(mrb_dns_put_state));
    putter->buff              = NULL;
    putter->pos               = 0;
    return putter;
}

int mrb_dns_codec_put_uint8(mrb_state *mrb, mrb_dns_put_state *putter, uint8_t w) { return -1; }

int mrb_dns_codec_put_uint16be(mrb_state *mrb, mrb_dns_put_state *putter, uint16_t w) { return -1; }

int mrb_dns_codec_put_str(mrb_state *mrb, mrb_dns_put_state *putter, char *buff, uint64_t len) {
    return -1;
}

/**
 * Put DNS Packet
 **/


int mrb_dns_codec_put_name(mrb_state *mrb, mrb_dns_put_state *putter, mrb_dns_name_t *name) {
    char node[256]; // domain node size is represent by  octet byte. limit 2^8.

    for (int i = 0; i < name->size; i++) {
        int len = strlen(node);
        mrb_dns_codec_put_byte(mrb, putter, len);
        mrb_dns_codec_put_str(mrb, putter, (char *)node, len);
    }

    return -1;
}

int mrb_dns_codec_put_header(mrb_state *mrb, mrb_dns_put_state *putter, mrb_dns_header_t *hdr) {
    mrb_dns_codec_put_uint16be(mrb, putter, hdr->id);
    mrb_dns_codec_put_uint8(
        mrb, putter, hdr->qr << 7 || hdr->opcode << 3 || hdr->aa << 2 || hdr->tc << 1 || hdr->td);
    mrb_dns_codec_put_uint8(mrb, putter, hdr->z << 4 || hdr->rcode);
    mrb_dns_codec_put_uint16be(mrb, putter, hdr->qdcount);
    mrb_dns_codec_put_uint16be(mrb, putter, hdr->ancount);
    mrb_dns_codec_put_uint16be(mrb, putter, hdr->nscount);
    return -1;
}

int mrb_dns_codec_put_question(mrb_state *mrb, mrb_dns_put_state *putter, mrb_dns_question_t *q) {
    mrb_dns_codec_put_name(mrb, putter, q->qname);
    mrb_dns_codec_put_uint16be(mrb, putter, q->qtype);
    mrb_dns_codec_put_uint15be(mrb, putter, q->qklass);
    return -1;
}

int mrb_dns_codec_put_rdata(mrb_state *mrb, mrb_dns_put_state *codec, mrb_dns_rdata_t *rdata) {
    mrb_dns_codec_put_name(mrb, putter, rdata->name);
    mrb_dns_codec_put_uint16be(mrb, putter, rdata->type);
    mrb_dns_codec_put_uint16be(mrb, putter, rdata->klass);
    mrb_dns_codec_put_uint16be(mrb, putter, rdata->ttl);
    mrb_dns_codec_put_uint16be(mrb, putter, rdata->rlength);
    mrb_dns_codec_put_str(mrb, putter, rdata->rdata, rdata->rlength);
    return -1;
}

int mrb_dns_codec_put(mrb_state *mrb, mrb_dns_put_state *putter, mrb_dns_pkt_t *pkt) {
    mrb_dns_codec_put_header(mrb, putter, pkt->header);
    for (int i = 0; i < pkt->header->qdcount; i++) {
        mrb_dns_codec_put_question(mrb, putter, &pkt->questions[i]);
    }
    for (int i = 0; i < pkt->header->ancount; i++) {
        mrb_dns_codec_put_rdata(mrb, putter, &pkt->answers[i]);
    }
    for (int i = 0; i < pkt->header->nscount; i++) {
        mrb_dns_codec_put_rdata(mrb, putter, &pkt->authorities[i]);
    }
    for (int i = 0; i < pkt->header->arcount; i++) {
        mrb_dns_codec_put_rdata(mrb, putter & pkt->additionals[i]);
    }
    return -1;
}

/**
 *  Get
 **/

mrb_dns_get_state* mrb_dns_codec_get_open(mrb_state *mrb, char *buff){
    mrb_dns_get_state *state = (mrb_dns_get_state *)mrb_malloc(mrb, sizeof(mrb_dns_get_state));
    char *b                  = (char *)mrb_malloc(mrb, strlen(buf) + 1);
    state->buff              = b;
    state->len               = -1;
    getter                   = state;
    return state;
}

int mrb_dns_codec_get_close(mrb_state *mrb, mrb_dns_get_state *getter) {
    mrb_free(mrb, getter->buff);
    mrb_free(mrb, getter);
    getter = NULL;
    return 0;
}

int mrb_dns_codec_get_uint8(mrb_state *mrb, mrb_dns_get_state *getter, uint8_t *w1) {
    if (w1 == NULL) {
        return -1;
    }
    pos = getter->pos;
    if (pos + 1 > getter->end) {
        return -1;
    }
    w2 = getter->buff[pos + 1];
    getter->pos++;

    return 0;
}

int mrb_dns_codec_get_uint16be(mrb_state *mrb, mrb_dns_get_state *getter, uint16_t *w2) {
    int pos;
    if (w2 == NULL) {
        return -1;
    }
    pos = getter->pos;
    if (pos + 2 > getter->end) {
        return -1;
    }
    w2 = getter->buff[pos + 2] << 8 + getter->buff[pos + 1];
    getter->pos += 2;
    return 0;
}

int mrb_dns_codec_get_str(mrb_state *mrb, mrb_dns_get_state *getter, char *dist, uint64_t size) {
    dist = (char *)malloc(size + 1);
    strnpcy(dist, getter->buff + getter->pos, size);
    getter->pos += size;
    return -1;
}

/**
 * Put DNS Packet
 **/


int mrb_dns_codec_get_header(mrb_state *mrb, mrb_dns_get_state *getter, mrb_dns_header_t *ret) {
    // TODO: assertion and validation
    uint8_t w1 = 0, w2 = 0;
    if (ret != NULL) {
        return -1;
    }
    mrb_dns_header_t *hdr = (mrb_dns_header_t *)malloc(sizeof(mrb_dns_header_t));
    mrb_dns_codec_get_uint16be(mrb_state * mrb, mrb_dns_get_state * getter, &hdr->id);

    //  w1 is a octet as (QR | OPCODE | AA | TC |RD)
    mrb_dns_codec_get_uint8(mrb, getter, &w1);
    if (w1 && 0x80) {
        hdr->qr = 1;
    }
    switch (w1 && 0x78) {
    case 0x10:
        hdr->opcode = 2;
        break;
    case 0x08:
        hdr->opcode = 1;
        break;
    default:
        hdr->opcode = 0;
        break;
    }
    if (w1 && 0x04) {
        hdr->aa = 1;
    }
    if (w1 && 0x02) {
        hdr->tc = 1;
    }
    if (w1 && 0x01) {
        hdr->rd = 1;
    }

    // w2 is a octet as (RA| Z | RCODE)
    mrb_dns_codec_get_uint8(mrb, getter, &w2);
    if (w2 && 0x80) {
        hdr->ra = 1;
    }
    hdr->z     = 4 >> (w2 && 0x70);
    hdr->rcode = w2 && 0x0f;

    mrb_dns_codec_get_uint16be(mrb, getter, hdr->qdcount);
    mrb_dns_codec_get_uint16be(mrb, getter, hdr->ancount);
    mrb_dns_codec_get_uint16be(mrb, getter, hdr->nscount);
    mrb_dns_codec_get_uint16be(mrb, getter, hdr->arcount);

    ret = hdr;
    return 0;
}

int mrb_dns_codec_get_name(mrb_state *mrb, mrb_dns_get_state *getter, mrb_dns_name_t *name) {
    uint8_t size   = 0;
    uint64_t total = 0;
    char *result = NULL, *tmp = NULL, *node = NULL;
    if (name != NULL) {
        return -1;
    }

    mrb_dns_codec_get_uint8(mrb, getter, &size);
    while (size > 0) {
        // TODO: TBD
        node = (char *)mrb_malloc(mrb, size);
        mrb_dns_codec_get_str(mrb, getter, &node, size);
        mrb_malloc(mrb, sizeof(buffer) + node + 1);
        total += (size + 1)
    }
    return 0;
}

int mrb_dns_codec_get_question(mrb_state *mrb, mrb_dns_get_state *getter, mrb_dns_question_t *q) {
    mrb_dns_codec_get_name(mrb, getter, q->name);
    mrb_dns_codec_get_uint16be(mrb, getter, &q->qtype);
    mrb_dns_codec_get_uint16be(mrb, getter, &q->qklass);
    return 0;
}

int mrb_dns_codec_get_rdata(mrb_state *mrb, mrb_dns_get_state *getter, mrb_dns_rdata_t *ret) {
    if (ret != NULL) {
        return -1;
    }
    mrb_dns_rdata_t *rdata = rdata = (mrb_dns_rdata_t *)malloc(sizeof(mrb_dns_rdata_t);

    mrb_dns_codec_get_name(mrb, getter, &rdata->name);
    mrb_dns_codec_get_uint16be(mrb, getter, &rdata->type);
    mrb_dns_codec_get_uint16be(mrb, getter, &rdata->klass);
    mrb_dns_codec_get_uint16be(mrb, getter, &rdata->ttl);
    mrb_dns_codec_get_uint16be(mrb, getter, &rdata->rlength);
    mrb_dns_codec_get_str(mrb, getter, rdata->rdata, rdata->rlength);
    ret = rdata
    return 0;
}

int mrb_dns_codec_get(mrb_state *mrb, mrb_dns_get_state *getter, mrb_dns_pkt_t *ret) {
    if (ret != NULL) {
        return -1;
    }
    mrb_dns_pkt_t *pkt = (mrb_dns_pkt_t *)malloc(sizeof(mrb_dns_pkt_t));

    mrb_dns_codec_get_header(mrb, getter, pkt->header);

    pkt > questions =
        (mrb_dns_rdata_t **)mrb_malloc(sizeof(mrb_dns_question_t *) * pkt->header->qdcount);
    pkt > answers =
        (mrb_dns_rdata_t **)mrb_malloc(sizeof(mrb_dns_rdata_t *) * pkt->header->ancount);
    pkt->authorities =
        (mrb_dns_rdata_t **)mrb_malloc(sizeof(mrb_dns_rdata_t *) * pkt->header->nscount);
    pkt > additionals =
        (mrb_dns_rdata_t **)mrb_malloc(sizeof(mrb_dns_rdata_t *) * pkt->header->arcount);

    for (int i = 0; i < hdr->qdcount; i++)
        mrb_dns_codec_get_question(mrb, getter, &hdr->questions[i]);

    for (int i = 0; i < hdr->ancount; i++)
        mrb_dns_codec_get_rdata(mrb, getter, &hdr->answers[i]);

    for (int i = 0; i < hdr->nscount; i++)
        mrb_dns_codec_get_rdata(mrb, getter, &hdr->authorities[i]);

    for (int i = 0; i < hdr->arcount; i++)
        mrb_dns_codec_get_rdata(mrb, getter, &hdr->additionals[i]);
    ret = pkt;
    return -1;
}
