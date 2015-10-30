#include "resolver.h"
#include "parse.h"


static int dns_header_init(dns_header *header)
{
    //work on Little Endian only.

    header->opcode =0;
    header->qr =0;

    header->id = 0;
    header->tc =0;
    header->aa =0;
    header->rd =1;
    header->ra =0;
    header->rcode =0;

    header->qdcount = htons(1);
    header->ancount =0;
    header->nscount =0;
    header->arcount =0;

    return 0; 
}

dns_context* mrb_resolver_new(){
    dns_context *query;
    dns_header *header;

    query = (dns_context *)malloc(sizeof(dns_context) );
    header = (dns_header *)query;
    dns_header_init(header);

    return query;
}


char* fqdn2format(char *name)
{
    int i = 0, start = 0;
    char *qname;
    qname = (char *)malloc( sizeof(char) + sizeof(name));
    sprintf(qname," %s",name);


    for(i = 1; qname[i] != '\0'; i++)
    {

        if( qname[i] == '.')
        {
            qname[start] = i - 1 - start ;
            start = i;
        }
    }
    qname[start] = i - 1 - start ;

    return qname;

}


int dns_context_set(dns_context *context, char *name, int type, int class)
{
    char *qname, *state;
    dns_question *question;

    qname = fqdn2format(name);

    state = (char*)context + sizeof(dns_header);

    strncpy(state, qname, strlen(qname)+1 );

    state = state + strlen(name) + 2;

    question = (dns_question *)state;

    question->qtype =  htons(type);
    question->qclass = htons(class);

    return 0;
}

static void sockaddr_init(struct sockaddr_in *addr, int port)
{
    /*
     * Work well linux.
     */
    const char *cache = "8.8.8.8"; // cache Server

    memset(addr, 0, sizeof(*addr));
    addr->sin_family =  AF_INET;
    addr->sin_port = htons(port);
    inet_aton(cache, &addr->sin_addr);
}


char* format2fqdn(char *name)
{
    int pos=0;
    int nsize=0;

    nsize = (int)name[pos];
    pos = pos + nsize;

    while(1)
    {
        nsize = (int)name[pos+1];
        if(nsize ==0)
        {
            break;
        }
        name[pos+1] = '.';
        pos = pos + nsize +1;

    }
    return  name+1;
}






int
mrb_resolver(dns_context *query, dns_context* result) {
    dns_context *t = NULL,
              *r = NULL;
    dns_header *header = NULL;
    char *name = NULL;
    uint8_t buff[UDP_LEN] = {};
    int sock= 0,
        ecode = 0;
    socklen_t len = 0;
    struct sockaddr_in addr ={},
                       d ={};

    memset(buff, 0, UDP_LEN);

    sockaddr_init(&addr, 53);

    header = (dns_header*)&buff;
    t = (dns_context*)&buff;

    dns_header_init(header);
    dns_context_set(t, name, 1, 1);

    sock = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
    if( sock == -1)
    {
        printf("socket error\n");
        return -1;
    }
    
    ecode = sendto(sock, (void*)t, sizeof(dns_header) +   strlen(name) + 2 + sizeof(dns_question) , 0, (struct sockaddr* )&addr, sizeof(addr) );
    if(ecode == -1)
    {
        printf("send error\n");
        return -1;
    }

    len = sizeof(struct sockaddr);
    ecode = recvfrom(sock, (void*)buff, UDP_LEN, 0, (struct sockaddr*)&d, &len);
    if(ecode  < 0)
    {
        close(sock);
        printf("recv error\n");
        return -1;
    }
    r = (dns_context*)buff;
    

    parse_records(r);

    close(sock);
    return 0;
}

