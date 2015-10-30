#include "mrb_resolv.h"
#include "resolver.h"

dns_header *
dns_header_get(dns_context *context)
{
    dns_header *header;
    header = (dns_header *)malloc(sizeof(dns_header));
    strncpy((char *)header, (char *)context, 12);
    return  header;
    /*
     * access 
    ("question:%d\n",ntohs(query->header.qdcount));
    ("answer:%d\n", ntohs(query->header.ancount));
    ("auth:%d\n", ntohs(query->header.nscount));
    ("addtional:%d\n",  ntohs(query->header.arcount));
    */
}

dns_query *
dns_query_get(dns_context *context)
{
    dns_query *query = NULL;

    char *ptr;
    int len;

    query = (dns_query *)malloc( sizeof(dns_query) );
    

    ptr = (char *)context + sizeof(dns_header) + 2;

    len = strlen(ptr) + sizeof(dns_question);
    ptr =  ptr + len + 1  ;

    return  query;
}


dns_query *
dns_answer_get(dns_context *context)
{
    dns_rrecord *record;
    char *ptr, *name;
    int len;
    struct in_addr *in;
    char dist[1024] = {0};

    ptr = (char *)context + sizeof(dns_header) + 2;

    len = strlen(ptr) + sizeof(dns_question);
    ptr =  ptr + len + 1  ;

    //49152
    if( (*(uint16_t*)ptr & 0x0c00) == 0x0c00)
    {
        // decode
        name = (char*) context +  (ntohs(*(uint16_t*)ptr) - 49152);
        ptr += 2;

        record = (dns_rrecord *)ptr;
        printf("type:%d, class:%d, ttl:%x\n", ntohs(record->type), ntohs(record->klass), ntohs(record->ttl) );
        printf("%s\n", format2fqdn( name) );

    }else{

        printf("length:%d\n",   *(uint16_t*)ptr );
        
        record = (dns_rrecord *)ptr;

        printf("type:%d, class:%d, ttl:%d\n", ntohs(record->type), ntohs(record->klass), ntohs(record->ttl) );
        printf("%s\n", ptr + 13);

        printf("length:%d\n", ntohs(record->rdlength) );
    }


    switch(ntohs(record->type)){
        case 1:
            puts("***A***");

            ptr +=  10;
            in = (struct in_addr *)(ptr);
            printf("rdata:%s\n", inet_ntoa(*in));
            break;
        case 5:
            puts("***CNAME***");
            //p += 2 + 1;            
            //p += 11;  // got garnet
            ptr += 10;
            printf("%d\n", *(uint8_t*)ptr);
            ptr++;
            strncpy(dist, ptr, *(uint8_t*)ptr);
            strcat(dist, ".");
            strcat(dist, format2fqdn( name));
            printf("%s\n", dist);

            break;
        default :
            break;
    }
    
    printf("fin\n");
    return NULL;
}

int parse_records(dns_context *context)
{
    dns_rrecord *record;
    char *ptr, *name;
    int len;
    struct in_addr *in;
    char dist[1024] = {0};

    printf("question:%d\n",ntohs(context->header.qdcount));
    printf("answer:%d\n", ntohs(context->header.ancount));
    printf("auth:%d\n", ntohs(context->header.nscount));
    printf("addtional:%d\n",  ntohs(context->header.arcount));

    ptr = (char *)context + sizeof(dns_header) + 2;

    len = strlen(ptr) + sizeof(dns_question);
    ptr =  ptr + len + 1  ;


    //49152
    if( (*(uint16_t*)ptr & 0x0c00) == 0x0c00)
    {
        // decode
        name = (char*) context +  (ntohs(*(uint16_t*)ptr) - 49152);
        ptr += 2;

        record = (dns_rrecord *)ptr;
        printf("type:%d, class:%d, ttl:%x\n", ntohs(record->type), ntohs(record->klass), ntohs(record->ttl) );
        printf("%s\n", format2fqdn( name) );

    }else{

        printf("length:%d\n",   *(uint16_t*)ptr );
        
        record = (dns_rrecord *)ptr;

        printf("type:%d, class:%d, ttl:%d\n", ntohs(record->type), ntohs(record->klass), ntohs(record->ttl) );
        printf("%s\n", ptr + 13);

        printf("length:%d\n", ntohs(record->rdlength) );
    }


    switch(ntohs(record->type)){
        case 1:
            puts("***A***");

            ptr +=  10;
            in = (struct in_addr *)(ptr);
            printf("rdata:%s\n", inet_ntoa(*in));
            break;
        case 5:
            puts("***CNAME***");
            //p += 2 + 1;            
            //p += 11;  // got garnet
            ptr += 10;
            printf("%d\n", *(uint8_t*)ptr);
            ptr++;
            strncpy(dist, ptr, *(uint8_t*)ptr);
            strcat(dist, ".");
            strcat(dist, format2fqdn( name));
            printf("%s\n", dist);

            break;
        default :
            break;
    }
    
    printf("fin\n");
    return 0;
}


