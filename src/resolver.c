#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <unistd.h>

#include <sys/types.h>
#include <sys/socket.h>
#include <netdb.h>

#include <netinet/in.h>
#include <arpa/inet.h>

#include <errno.h>
#include <sys/select.h>


#define UDP_LEN 65535

#define PACKED_RRECORD_LEN(x) (x & (0xc000 ^ 0xffff))

typedef struct dns_header {

    uint16_t id;


    uint8_t rd :1;
    uint8_t zero :3;
    uint8_t rcode :4;
    uint8_t ra :1;

    uint8_t qr :1;
    uint8_t opcode :4;
    uint8_t  aa :1;
    uint8_t tc :1;

    uint16_t qdcount;

    uint16_t ancount;

    uint16_t nscount ;

    uint16_t arcount;

}dns_header;

typedef struct dns_question {
    uint16_t qtype;
    uint16_t qclass;
}dns_question;



typedef struct dns_rrecord{
    uint16_t type;
    uint16_t class;
    uint32_t ttl;
    uint16_t rdlength;
    // void *rdata;
}dns_rrecord;

typedef struct dns_query {
    dns_header header;
    dns_question question;
    dns_rrecord *answer;
    dns_rrecord *authority;
    dns_rrecord *addtional;
}dns_query;


void dns_header_init(dns_header *header)
{

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

    return; 
}


static char* fqdn2query_format(char *name)
{
    int i,
        start = 0;
    char *qname;
    qname = (char *)malloc( sizeof(char) + sizeof(name));
    sprintf(qname," %s",name);


    for(i=1; qname[i] != '\0'; i++)
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


int dns_query_set(dns_query *t, char *name, int type)
{
    char *n, *q;
    dns_question *question;

    n = fqdn2query_format(name);

    q = (char*)t + sizeof(dns_header);
    strncpy(q, n, strlen(n) +1);

    q = q + strlen(name)   + 2;

    question = (dns_question *)q;
    question->qtype =  htons(1);
    question->qclass = htons(1);

    return 0;
}

void sockaddr_init(struct sockaddr_in *addr)
{
    char *cache = "8.8.8.8"; // cache Server

    memset(addr, 0, sizeof(*addr));
    addr->sin_family =  AF_INET;
    addr->sin_port = htons(53);
    inet_aton(cache, &addr->sin_addr);
}


char * query_format2fqdn(dns_query *q, char *name)
{
    int i=0;
    int l=0;

    l = (int)name[i];
    i = i+l;

    while(1)
    {
        l = (int)name[i+1];
        if(l ==0)
        {
            break;
        }
        name[i+1] = '.';
        i = i+l+1;

    }
    return  name+1;
}


int show_me_records(dns_query *r)
{
    dns_rrecord *record;
    char *ptr, *name;
    int len;
    struct in_addr *in;

    printf("question:%d\n",ntohs(r->header.qdcount));
    printf("answer:%d\n", ntohs(r->header.ancount));
    printf("auth:%d\n", ntohs(r->header.nscount));
    printf("addtional:%d\n",  ntohs(r->header.arcount));

    ptr = (char *)r + sizeof(dns_header) + 2;

    len = strlen(ptr) + sizeof(dns_question);
    ptr +=  len + 1  ;

    printf("%x\n", *(uint16_t*)ptr );
    puts("");
    puts("");

    //49152
    if( (*(uint16_t*)ptr & 0x0c00) == 0x0c00)
    {
        puts("=======masked======= ");

        // decode
        name = (char*) r +  (ntohs(*(uint16_t*)ptr) - 49152);
        ptr += 2;

        record = (dns_rrecord *)ptr;
        printf("type:%d, class:%d, ttl:%x\n", ntohs(record->type), ntohs(record->class), ntohs(record->ttl) );
        printf("%s\n", query_format2fqdn(r, name) );

    }else{

        printf("length:%d\n",   *(uint16_t*)ptr );
        
        record = (dns_rrecord *)ptr;

        printf("type:%d, class:%d, ttl:%d\n", ntohs(record->type), ntohs(record->class), ntohs(record->ttl) );
        printf("%s\n", ptr + 13);

        printf("length:%d\n", ntohs(record->rdlength) );
    }

   char dist[1024] = {};

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
            strcat(dist, query_format2fqdn(r, name));
            printf("%s\n", dist);

            break;
        default :
            break;
    }
    
    printf("fin\n");
    return 0;
}

void show_unzip(dns_query *q)
{
    printf("\n");
    return ;
}


int
main(int argc, char* argv[]) {
    dns_query *t = NULL,
              *r = NULL;
    dns_header *header = NULL;
    //char *name = "ac.jp";
    //char *name = "twitter.com";
    //char *name = "www.club.kyutech.ac.jp";
    //char *name = "www.google.com";
    char *name = "garnet.club.kyutech.ac.jp";
    //char *name = "www.kyutech.ac.jp";
    //char *name= "www.nicovideo.jp";
    uint8_t buff[UDP_LEN] = {};
    int sock= 0,
        ecode = 0;
    socklen_t len = 0;
    struct sockaddr_in addr ={},
                       d ={};

    memset(buff, 0, UDP_LEN);

    sockaddr_init(&addr);

    header = (dns_header*)&buff;
    t = (dns_query*)&buff;

    dns_header_init(header);
    dns_query_set(t, name, 1);

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
    r = (dns_query*)buff;
    

    show_me_records(r);
    show_unzip(r);

    close(sock);
    return 0;
}

