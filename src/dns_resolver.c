#include "resolver.h"
#include "mruby.h"
#include "mruby/value.h"
#include "mruby/variable.h"

#if __linux__ == 1
#include <netinet/in.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <unistd.h>

#if defined(__GLIBC__) && defined(__GLIBC_MINOR__)
#if (__GLIBC__ >= 2) && (__GLIBC_MINOR__ > 3)
#include <sys/epoll.h>
#endif
#endif

#if defined(__GNU_LIBRARY__) && defined(__GNU_LIBRARY__MINOR__)
#if (__GLIB_LIBRARY__ >= 2) && (__GLIB_LIBRARY_MINOR__ > 3)
#include <sys/epoll.h>
#endif
#endif

#endif

#if __WIN32__ == 1
#error "not yet implement win32api support"
#endif

#if __APPLE__ == 1
#error "not yet imlement mac os x support"
#endif

mrb_dns_state *mrb_resolver_new(mrb_dns_option *option) { 
    mrb_dns_state *state = NULL;
    struct sockaddr_in saddr;
    int fd;
    fd = socket(AF_INET, SOCK_DGRAM, 0);
    if( fd < 0 ) {
        return NULL;
    }
    return state; 
}

int mrb_resolver_send(mrb_state *mrb, mrb_dns_state *dns, mrb_dns_pkt_t *req) { 
    mrb_dns_put_state *putter = mrb_dns_codec_put_open(mrb);
    if(mrb_dns_codec_put(mrb, putter, req) != 0){
        return -1;
    }
    n = sendTo(dns->sock, putter->buf, putter->size, 0, dns->saddr, dns->slen);
    if ( n < 0 )
        return -1;

    return 0;
}

int mrb_resolver_recv(mrb_state *mrb, mrb_dns_state *dns, mrb_dns_pkt_t *resp) { 
    // TODO: support END0, TCP 
    // TODO: configurable buffer size
    char buff[512 * 8];
    struct sockaddr_in saddr;
    int slen, ecode;
    mrb_dns_pkt_t *pkt = NULL;
    mrb_dns_get_state *getter = NULL;
    ecode =recvFrom(dns->sock, buf, strlen(buf), 0 &saddr, &slen);
    if(ecode < 0) {
        return -1;
    }
    getter = mrb_dns_codec_get_open(mrb, buff); 
    if(mrb_dns_codec_get(mrb, getter, pkt)) {
        return -1;
    }
    resp = pkt;
    mrb_dns_codec_close(mrb, getter);
    return -1;
}

int mrb_resolver_getresources(mrb_state *mrb, mrb_dns_state *dns, mrb_value v, mrb_int typ) {
    return -1;
}
