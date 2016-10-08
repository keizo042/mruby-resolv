#include "resolver.h"
#include "mruby.h"
#include "mruby/variable.h"
#include "mruby/value.h"

#if __linux__ == 1
#include <sys/types.h>
#include <sys/socket.h>

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
#error  "not yet implement win32api support"
#endif

#if __APPLE__ == 1
#error "not yet imlement mac os x support"
#endif

int mrb_resolver_send(mrb_state *mrb, mrb_dns_state *dns, mrb_dns_t *request);

mrb_dns_lex* mrb_resolver_lex(){
    return NULL;
}
mrb_dns_state* mrb_resolver_new(){
    return NULL;
}

int mrb_resolver_send(mrb_state *mrb, mrb_dns_state *dns, mrb_dns_t *request){
    return -1;
}

int mrb_resolver_recv(mrb_state *mrb, mrb_dns_state *dns, nrb_dns_t *response){
}

int mrb_resolver_getresources(mrb_state *mrb, mrb_dns_state *dns, mrb_value v, mrb_int typ){
    return -1;
}
