#include <netinet/in.h>
#include <errno.h>
#include <netdb.h>
#include <stdio.h> //For standard things
#include <stdlib.h>    //malloc
#include <string.h>    //strlen
 
#include <netinet/in.h>
#include <netinet/ip_icmp.h>   //Provides declarations for icmp header
#include <netinet/udp.h>   //Provides declarations for udp header
#include <netinet/tcp.h>   //Provides declarations for tcp header
#include <netinet/ip.h>    //Provides declarations for ip header
#include <netinet/if_ether.h>  //For ETH_P_ALL
#include <net/ethernet.h>  //For ether_header
#include <sys/socket.h>
#include <arpa/inet.h>
#include <sys/ioctl.h>
#include <sys/time.h>
#include <sys/types.h>
#include <unistd.h>
#include "pcat.h"

extern char ethernet[1000][300];
extern char network[1000][400];
extern char transport[1000][400];
extern char app[1000][5000];
extern char payload[1000][5000];

extern char buff_ethernet[300];
extern char buff_network[400];
extern char buff_transport[400];
extern char buff_app[5000];
extern char buff_payload[5000];
char curr[5000];
int counter[1000][4];
FILE *logfile;
struct sockaddr_in source,dest;
int tcp=0,udp=0,icmp=0,others=0,igmp=0,total=0,i,j;
int line;
//DNS header structure
struct DNS_HEADER
{
    unsigned short id; // identification number
 
    unsigned char rd :1; // recursion desired
    unsigned char tc :1; // truncated message
    unsigned char aa :1; // authoritive answer
    unsigned char opcode :4; // purpose of message
    unsigned char qr :1; // query/response flag
 
    unsigned char rcode :4; // response code
    unsigned char cd :1; // checking disabled
    unsigned char ad :1; // authenticated data
    unsigned char z :1; // its z! reserved
    unsigned char ra :1; // recursion available
 
    unsigned short q_count; // number of question entries
    unsigned short ans_count; // number of answer entries
    unsigned short auth_count; // number of authority entries
    unsigned short add_count; // number of resource entries
};
 
//Constant sized fields of query structure
struct QUESTION
{
    unsigned short qtype;
    unsigned short qclass;
};

//Constant sized fields of the resource record structure
#pragma pack(push, 1)
struct R_DATA
{
    unsigned short type;
    unsigned short _class;
    unsigned int ttl;
    unsigned short data_len;
};
#pragma pack(pop)
 
//Pointers to resource record contents
struct RES_RECORD
{
    unsigned char *name;
    struct R_DATA *resource;
    unsigned char *rdata;
};
 
//Structure of a Query
typedef struct
{
    unsigned char *name;
    struct QUESTION *ques;
} QUERY;

// Structure of ARP

struct ARPhdr
  {
    unsigned short int ar_hrd;      /* Format of hardware address.  */
    unsigned short int ar_pro;      /* Format of protocol address.  */
    unsigned char ar_hln;       /* Length of hardware address.  */
    unsigned char ar_pln;       /* Length of protocol address.  */
    unsigned short int ar_op;       /* ARP opcode (command).  */
    unsigned char ar_sha[ETH_ALEN]; /* Sender hardware address.  */
    unsigned char ar_sip[4];        /* Sender IP address.  */
    unsigned char ar_tha[ETH_ALEN]; /* Target hardware address.  */
    unsigned char ar_tip[4];        /* Target IP address.  */

  };

void ProcessPacket(unsigned char* buffer, int size)
{
    
    struct ethhdr *ehdr = (struct ethhdr*)(buffer);
    if (ehdr->h_proto == 1544)
    {
        print_arp_packet(buffer , size);
        ++total;
        return;
    }

    //Get the IP Header part of this packet , excluding the ethernet header
    struct iphdr *iph = (struct iphdr*)(buffer + sizeof(struct ethhdr));
    switch (iph->protocol) //Check the Protocol and do accordingly...
    {
        case 1:  //ICMP Protocol
            ++icmp;
            print_icmp_packet( buffer , size);
            break;
         
        case 6:  //TCP Protocol
            ++tcp;
            print_tcp_packet(buffer , size);
            break;
         
        case 17: //UDP Protocol
            ++udp;
            print_udp_packet(buffer , size);
            break;
         
        default: //Some Other Protocol like ARP etc.
            ++others;
            // total--;
            break;
    }
    ++total;
    printf("\nTCP : %d   UDP : %d   ICMP : %d   IGMP : %d   Others : %d   Total : %d\r", tcp , udp , icmp , igmp , others , total);
    // sprintf(stdout);
}
 
void print_ethernet_header(unsigned char* Buffer, int Size)
{
    struct ethhdr *eth = (struct ethhdr *)Buffer;
     
    // sprintf(logfile, "\n");
    sprintf(curr, "Ethernet Header\n");
    sprintf(curr,"%s",ethernet[total]);
    sprintf(curr, "   |-Destination Address : %.2X-%.2X-%.2X-%.2X-%.2X-%.2X \n", eth->h_dest[0] , eth->h_dest[1] , eth->h_dest[2] , eth->h_dest[3] , eth->h_dest[4] , eth->h_dest[5] );
    strcat(ethernet[total],curr);
    sprintf(curr, "   |-Source Address      : %.2X-%.2X-%.2X-%.2X-%.2X-%.2X \n", eth->h_source[0] , eth->h_source[1] , eth->h_source[2] , eth->h_source[3] , eth->h_source[4] , eth->h_source[5] );
    strcat(ethernet[total],curr);
    sprintf(curr, "   |-Protocol            : %u \n",(unsigned short)eth->h_proto);
    strcat(ethernet[total],curr);
    printf("%s\n",ethernet[total] );
}

void print_arp_packet(unsigned char* Buffer, int Size)
{

    print_ethernet_header(Buffer , Size);
    int header_size = sizeof(struct ethhdr);
    struct ARPhdr *arph = (struct ARPhdr *)(Buffer  + header_size);
    sprintf(curr , "ARP Header\n");
    sprintf(curr,"%s",network[total]);
    sprintf(curr , "   |-Format of hardware address : %d \n",arph->ar_hrd);
    strcat(network[total],curr);
    sprintf(curr , "   |-Format of protocol address : %d \n",arph->ar_pro);
    strcat(network[total],curr);
    sprintf(curr , "   |-Length of hardware address : %d \n",arph->ar_hln);
    strcat(network[total],curr);
    sprintf(curr , "   |-Length of protocol address : %d \n",arph->ar_pln);
    strcat(network[total],curr);
    sprintf(curr , "   |-Operation (command)        : %d \n",arph->ar_op);
    strcat(network[total],curr);
    sprintf(curr , "   |-Source MAC address         : %.2X-%.2X-%.2X-%.2X-%.2X-%.2X \n",arph->ar_sha[0],arph->ar_sha[1],arph->ar_sha[2],arph->ar_sha[3],arph->ar_sha[4],arph->ar_sha[5]);
    strcat(network[total],curr);
    sprintf(curr , "   |-Source IP address          : %d.%d.%d.%d \n",arph->ar_sip[0],arph->ar_sip[1],arph->ar_sip[2],arph->ar_sip[3]);
    strcat(network[total],curr);
    sprintf(curr , "   |-Destination MAC address    : %.2X-%.2X-%.2X-%.2X-%.2X-%.2X \n",arph->ar_tha[0],arph->ar_tha[1],arph->ar_tha[2],arph->ar_tha[3],arph->ar_tha[4],arph->ar_tha[5]);
    strcat(network[total],curr);
    sprintf(curr , "   |-Destination IP address     : %d.%d.%d.%d \n",arph->ar_tip[0],arph->ar_tip[1],arph->ar_tip[2],arph->ar_tip[3]);
    strcat(network[total],curr);
    printf("%s\n",network[total] );
}
 
void print_ip_header(unsigned char* Buffer, int Size)
{
    print_ethernet_header(Buffer , Size);
    
    struct iphdr *iph = (struct iphdr *)(Buffer  + sizeof(struct ethhdr) );
     
    memset(&source, 0, sizeof(source));
    source.sin_addr.s_addr = iph->saddr;
     
    memset(&dest, 0, sizeof(dest));
    dest.sin_addr.s_addr = iph->daddr;
     
    // sprintf(logfile, "\n");
    sprintf(curr, "IP Header\n");
    sprintf(curr,"%s",network[total]);
    sprintf(curr, "   |-IP Version        : %d\n",(unsigned int)iph->version);
    strcat(network[total],curr);
    sprintf(curr, "   |-IP Header Length  : %d DWORDS or %d Bytes\n",(unsigned int)iph->ihl,((unsigned int)(iph->ihl))*4);
    strcat(network[total],curr);
    sprintf(curr, "   |-Type Of Service   : %d\n",(unsigned int)iph->tos);
    strcat(network[total],curr);
    sprintf(curr, "   |-IP Total Length   : %d  Bytes(Size of Packet)\n",ntohs(iph->tot_len));
    strcat(network[total],curr);
    sprintf(curr, "   |-Identification    : %d\n",ntohs(iph->id));
    //sprintf(curr, "   |-Reserved ZERO Field   : %d\n",(unsigned int)iphdr->ip_reserved_zero);
    //sprintf(curr, "   |-Dont Fragment Field   : %d\n",(unsigned int)iphdr->ip_dont_fragment);
    //sprintf(curr, "   |-More Fragment Field   : %d\n",(unsigned int)iphdr->ip_more_fragment);
    strcat(network[total],curr);
    sprintf(curr, "   |-TTL      : %d\n",(unsigned int)iph->ttl);
    strcat(network[total],curr);
    sprintf(curr, "   |-Protocol : %d\n",(unsigned int)iph->protocol);
    strcat(network[total],curr);
    sprintf(curr, "   |-Checksum : %d\n",ntohs(iph->check));
    strcat(network[total],curr);
    sprintf(curr, "   |-Source IP        : %s\n",inet_ntoa(source.sin_addr));
    strcat(network[total],curr);
    sprintf(curr, "   |-Destination IP   : %s\n",inet_ntoa(dest.sin_addr));
    strcat(network[total],curr);
    printf("%s\n",network[total] );
}
 
void print_tcp_packet(unsigned char* Buffer, int Size)
{
    unsigned short iphdrlen;
     
    struct iphdr *iph = (struct iphdr *)( Buffer  + sizeof(struct ethhdr) );
    iphdrlen = iph->ihl*4;
     
    struct tcphdr *tcph=(struct tcphdr*)(Buffer + iphdrlen + sizeof(struct ethhdr));
             
    int header_size =  sizeof(struct ethhdr) + iphdrlen + tcph->doff*4;
     
    // sprintf(logfile, "\n\n***********************TCP Packet*************************\n");  
         
    print_ip_header(Buffer,Size);
    // sprintf(logfile, "\n");
    sprintf(curr, "TCP Header\n");
    sprintf(curr,"%s",transport[total]);
    sprintf(curr, "   |-Source Port      : %u\n",ntohs(tcph->source));
    strcat(transport[total],curr);
    sprintf(curr, "   |-Destination Port : %u\n",ntohs(tcph->dest));
    strcat(transport[total],curr);
    sprintf(curr, "   |-Sequence Number    : %u\n",ntohl(tcph->seq));
    strcat(transport[total],curr);
    sprintf(curr, "   |-Acknowledge Number : %u\n",ntohl(tcph->ack_seq));
    strcat(transport[total],curr);
    sprintf(curr, "   |-Header Length      : %d DWORDS or %d BYTES\n" ,(unsigned int)tcph->doff,(unsigned int)tcph->doff*4);
    strcat(transport[total],curr);
    //sprintf(curr, "   |-CWR Flag : %d\n",(unsigned int)tcph->cwr);
    //sprintf(curr, "   |-ECN Flag : %d\n",(unsigned int)tcph->ece);
    sprintf(curr, "   |-Urgent Flag          : %d\n",(unsigned int)tcph->urg);
    strcat(transport[total],curr);
    sprintf(curr, "   |-Acknowledgement Flag : %d\n",(unsigned int)tcph->ack);
    strcat(transport[total],curr);
    sprintf(curr, "   |-Push Flag            : %d\n",(unsigned int)tcph->psh);
    strcat(transport[total],curr);
    sprintf(curr, "   |-Reset Flag           : %d\n",(unsigned int)tcph->rst);
    strcat(transport[total],curr);
    sprintf(curr, "   |-Synchronise Flag     : %d\n",(unsigned int)tcph->syn);
    strcat(transport[total],curr);
    sprintf(curr, "   |-Finish Flag          : %d\n",(unsigned int)tcph->fin);
    strcat(transport[total],curr);
    sprintf(curr, "   |-Window         : %d\n",ntohs(tcph->window));
    strcat(transport[total],curr);
    sprintf(curr, "   |-Checksum       : %d\n",ntohs(tcph->check));
    strcat(transport[total],curr);
    sprintf(curr, "   |-Urgent Pointer : %d\n",tcph->urg_ptr);
    strcat(transport[total],curr);
    // sprintf(logfile, "\n");
    if (ntohs(tcph->source) == 80 || ntohs(tcph->dest) == 80)
    {
        print_http_header(Buffer, Size);
    }
    
    if (ntohs(tcph->source) == 53 || ntohs(tcph->dest) == 53)
    {
        print_dns_header(Buffer, Size);
    }
    printf("%s\n",transport[total] );
    sprintf(curr, "                        DATA Dump                         \n");
    sprintf(curr,"%s",payload[total]);    
    sprintf(curr, "IP Header\n");
    strcat(payload[total],curr);
    PrintData(Buffer,iphdrlen);
         
    sprintf(curr, "TCP Header\n");
    strcat(payload[total],curr);
    PrintData(Buffer+iphdrlen,tcph->doff*4);

    sprintf(curr, "Data Payload\n");
    strcat(payload[total],curr);    
    PrintData(Buffer + header_size , Size - header_size );
    // sprintf(logfile, "\n###########################################################");
}
 
void print_udp_packet(unsigned char *Buffer , int Size)
{
     
    unsigned short iphdrlen;
     
    struct iphdr *iph = (struct iphdr *)(Buffer +  sizeof(struct ethhdr));
    iphdrlen = iph->ihl*4;
     
    struct udphdr *udph = (struct udphdr*)(Buffer + iphdrlen  + sizeof(struct ethhdr));
     
    int header_size =  sizeof(struct ethhdr) + iphdrlen + sizeof udph;
     
    // sprintf(logfile, "\n\n***********************UDP Packet*************************\n");
     
    print_ip_header(Buffer,Size);           
    sprintf(curr, "UDP Header\n");
    sprintf(curr,"%s",transport[total]);
    sprintf(curr, "   |-Source Port      : %d\n" , ntohs(udph->source));
    strcat(transport[total],curr);
    sprintf(curr, "   |-Destination Port : %d\n" , ntohs(udph->dest));
    strcat(transport[total],curr);
    sprintf(curr, "   |-UDP Length       : %d\n" , ntohs(udph->len));
    strcat(transport[total],curr);
    sprintf(curr, "   |-UDP Checksum     : %d\n" , ntohs(udph->check));
    strcat(transport[total],curr);
    if (ntohs(udph->source) == 53 || ntohs(udph->dest) == 53)
    {        
        print_dns_header(Buffer, Size);
    }
    printf("%s\n",transport[total] );

    sprintf(curr, "                        DATA Dump                         \n");
    sprintf(curr,"%s",payload[total]);    
    sprintf(curr, "IP Header\n");
    strcat(payload[total],curr);
    PrintData(Buffer,iphdrlen);
         
    sprintf(curr, "UDP Header\n");
    strcat(payload[total],curr);
    PrintData(Buffer+iphdrlen , sizeof udph);
         
    sprintf(curr, "Data Payload\n");    
    strcat(payload[total],curr);
    //Move the pointer ahead and reduce the size of string
    PrintData(Buffer + header_size , Size - header_size);

    // sprintf(curr, "\n###########################################################");
}
 
void print_icmp_packet(unsigned char* Buffer , int Size)
{
    unsigned short iphdrlen;
     
    struct iphdr *iph = (struct iphdr *)(Buffer  + sizeof(struct ethhdr));
    iphdrlen = iph->ihl * 4;
     
    struct icmphdr *icmph = (struct icmphdr *)(Buffer + iphdrlen  + sizeof(struct   ethhdr));
     
    int header_size =  sizeof(struct ethhdr) + iphdrlen + sizeof icmph;
     
    // sprintf(logfile, "\n\n***********************ICMP Packet*************************\n"); 
     
    print_ip_header(Buffer , Size);
    // sprintf(logfile, "\n");
    
    sprintf(curr, "ICMP Header\n");
    strcat(network[total],curr);
    
    sprintf(curr, "   |-Type : %d\n",(unsigned int)(icmph->type));
    strcat(network[total],curr);

    if((unsigned int)(icmph->type) == 11)
    {
        sprintf(curr, "  (TTL Expired)\n");
        strcat(network[total],curr);
    }

    else if((unsigned int)(icmph->type) == ICMP_ECHOREPLY)
    {
        
        sprintf(curr, "  (ICMP Echo Reply)\n");
        strcat(network[total],curr);
    }

     
    
    sprintf(curr, "   |-Code : %d\n",(unsigned int)(icmph->code));
    strcat(network[total],curr);

    sprintf(curr, "   |-Checksum : %d\n",ntohs(icmph->checksum));
    strcat(network[total],curr);
    //sprintf(logfile, "   |-ID       : %d\n",ntohs(icmph->id));
    //sprintf(logfile, "   |-Sequence : %d\n",ntohs(icmph->sequence));
    // sprintf(logfile, "\n");
    printf("%s\n",network[total] );
    sprintf(curr, "                        DATA Dump                         \n");
    strcat(payload[total],curr);
    sprintf(curr, "IP Header\n");
    strcat(payload[total],curr);
    PrintData(Buffer,iphdrlen);
         
    sprintf(curr, "UDP Header\n");
    strcat(payload[total],curr);
    PrintData(Buffer + iphdrlen , sizeof icmph);
         
    sprintf(curr, "Data Payload\n");    
    strcat(payload[total],curr);
    //Move the pointer ahead and reduce the size of string
    PrintData(Buffer + header_size , (Size - header_size) );
    // sprintf(curr, "\n###########################################################");
}

void print_http_header(unsigned char* Buffer , int Size)
{
    unsigned short iphdrlen;
     
    struct iphdr *iph = (struct iphdr *)( Buffer  + sizeof(struct ethhdr) );
    iphdrlen = iph->ihl*4;
     
    struct tcphdr *tcph=(struct tcphdr*)(Buffer + iphdrlen + sizeof(struct ethhdr));
             
    int tcp_header_size = tcph->doff*4;

    unsigned char* http_data = Buffer + iphdrlen + sizeof(struct ethhdr) + tcp_header_size;

    int http_size = Size - iphdrlen - sizeof(struct ethhdr) - tcp_header_size;

    int i;
    sprintf(curr, "HTTP Header\n");
    sprintf(curr,"%s",app[total]);
    for (i = 0; i < http_size; ++i)
    {
        if (http_data[i] >= 32 && http_data[i] <= 128)
            sprintf(curr, "%c",(unsigned char)http_data[i]);
        else
            sprintf(curr, "\n");
        strcat(app[total],curr);
    }
    printf("%s\n",app[total] );
    // sprintf(buff_app,"%s",app[total]);
}

u_char* ReadName(unsigned char* reader,unsigned char* buffer,int* count)
{
    unsigned char *name;
    unsigned int p=0,jumped=0,offset;
    int i , j;
 
    *count = 1;
    name = (unsigned char*)malloc(256);
 
    name[0]='\0';
 
    //read the names in 3www6google3com format
    while(*reader!=0)
    {
        if(*reader>=192)
        {
            offset = (*reader)*256 + *(reader+1) - 49152; //49152 = 11000000 00000000 ;)
            reader = buffer + offset - 1;
            jumped = 1; //we have jumped to another location so counting wont go up!
        }
        else
        {
            name[p++]=*reader;
        }
 
        reader = reader+1;
 
        if(jumped==0)
        {
            *count = *count + 1; //if we havent jumped to another location then we can count up
        }
    }
 
    name[p]='\0'; //string complete
    if(jumped==1)
    {
        *count = *count + 1; //number of steps we actually moved forward in the packet
    }
 
    //now convert 3www6google3com0 to www.google.com
    for(i=0;i<(int)strlen((const char*)name);i++) 
    {
        p=name[i];
        for(j=0;j<(int)p;j++) 
        {
            name[i]=name[i+1];
            i=i+1;
        }
        name[i]='.';
    }
    name[i-1]='\0'; //remove the last dot
    return name;
}

void print_dns_header(unsigned char* Buffer , int Size)
{
    unsigned short iphdrlen;
    
    struct iphdr *iph = (struct iphdr *)( Buffer  + sizeof(struct ethhdr) );
    iphdrlen = iph->ihl*4;
     
    struct udphdr *udph=(struct udphdr*)(Buffer + iphdrlen + sizeof(struct ethhdr));
             
    // int tcp_header_size =  tcph->doff*4;
    struct DNS_HEADER* dns = (struct DNS_HEADER*)(Buffer + sizeof udph + iphdrlen + sizeof(struct ethhdr));


    struct RES_RECORD answers[20],auth[20],addit[20];
    struct sockaddr_in a;
    unsigned char *reader, *qname;
    Buffer+=sizeof udph + iphdrlen + sizeof(struct ethhdr);
    qname =(unsigned char*)&Buffer[sizeof(struct DNS_HEADER)];
    //move ahead of the dns header and the query field
    sprintf(curr, "DNS Header\n");
    sprintf(curr,"%s",app[total]);
    reader = (Buffer+sizeof(struct DNS_HEADER) + (strlen((const char*)qname)+1) + sizeof(struct QUESTION));
    sprintf(curr, "\nThe response contains : ");
    strcat(app[total],curr);
    sprintf(curr, "\n %d Questions.",ntohs(dns->q_count));
    strcat(app[total],curr);
    sprintf(curr, "\n %d Answers.",ntohs(dns->ans_count));
    strcat(app[total],curr);
    sprintf(curr, "\n %d Authoritative Servers.",ntohs(dns->auth_count));
    strcat(app[total],curr);
    sprintf(curr, "\n %d Additional records.\n\n",ntohs(dns->add_count));
    strcat(app[total],curr);
    //Start reading answers
    int stop=0;
 
    for(i=0;i<ntohs(dns->ans_count);i++)
    {
        answers[i].name=ReadName(reader,Buffer,&stop);
        reader = reader + stop;
 
        answers[i].resource = (struct R_DATA*)(reader);
        reader = reader + sizeof(struct R_DATA);
 
        if(ntohs(answers[i].resource->type) == 1) //if its an ipv4 address
        {
            answers[i].rdata = (unsigned char*)malloc(ntohs(answers[i].resource->data_len));
 
            for(j=0 ; j<ntohs(answers[i].resource->data_len) ; j++)
            {
                answers[i].rdata[j]=reader[j];
            }
 
            answers[i].rdata[ntohs(answers[i].resource->data_len)] = '\0';
 
            reader = reader + ntohs(answers[i].resource->data_len);
        }
        else
        {
            answers[i].rdata = ReadName(reader,Buffer,&stop);
            reader = reader + stop;
        }
    }
 
    //read authorities
    for(i=0;i<ntohs(dns->auth_count);i++)
    {
        auth[i].name=ReadName(reader,Buffer,&stop);
        reader+=stop;
 
        auth[i].resource=(struct R_DATA*)(reader);
        reader+=sizeof(struct R_DATA);
 
        auth[i].rdata=ReadName(reader,Buffer,&stop);
        reader+=stop;
    }
 
    //read additional
    for(i=0;i<ntohs(dns->add_count);i++)
    {
        addit[i].name=ReadName(reader,Buffer,&stop);
        reader+=stop;
 
        addit[i].resource=(struct R_DATA*)(reader);
        reader+=sizeof(struct R_DATA);
 
        if(ntohs(addit[i].resource->type)==1)
        {
            addit[i].rdata = (unsigned char*)malloc(ntohs(addit[i].resource->data_len));
            for(j=0;j<ntohs(addit[i].resource->data_len);j++)
            addit[i].rdata[j]=reader[j];
 
            addit[i].rdata[ntohs(addit[i].resource->data_len)]='\0';
            reader+=ntohs(addit[i].resource->data_len);
        }
        else
        {
            addit[i].rdata=ReadName(reader,Buffer,&stop);
            reader+=stop;
        }
    }
 
    //print answers
    sprintf(curr, "\nAnswer Records : %d \n" , ntohs(dns->ans_count) );
    strcat(app[total],curr);
    for(i=0 ; i < ntohs(dns->ans_count) ; i++)
    {
        sprintf(curr, "Name : %s ",answers[i].name);
    strcat(app[total],curr);

        if( ntohs(answers[i].resource->type) == 1) //IPv4 address
        {
            long *p;
            p=(long*)answers[i].rdata;
            a.sin_addr.s_addr=(*p); //working without ntohl
            sprintf(curr, "has IPv4 address : %s",inet_ntoa(a.sin_addr));
            strcat(app[total],curr);
        }
         
        if(ntohs(answers[i].resource->type)==5) 
        {
            //Canonical name for an alias
            sprintf(curr, "has alias name : %s",answers[i].rdata);
            strcat(app[total],curr);
        }
 
        sprintf(curr, "\n");
        strcat(app[total],curr);
    }
 
    //print authorities
    sprintf(curr, "\nAuthoritive Records : %d \n" , ntohs(dns->auth_count) );
    strcat(app[total],curr);
    for( i=0 ; i < ntohs(dns->auth_count) ; i++)
    {
         
        sprintf(curr, "Name : %s ",auth[i].name);
        strcat(app[total],curr);
        if(ntohs(auth[i].resource->type)==2)
        {
            sprintf(curr, "has nameserver : %s",auth[i].rdata);
            strcat(app[total],curr);
        }
        sprintf(curr, "\n");
        strcat(app[total],curr);
    }
 
    //print additional resource records
    sprintf(curr, "\nAdditional Records : %d \n" , ntohs(dns->add_count) );
    strcat(app[total],curr);
    for(i=0; i < ntohs(dns->add_count) ; i++)
    {
        sprintf(curr, "Name : %s ",addit[i].name);
        strcat(app[total],curr);
        if(ntohs(addit[i].resource->type)==1)
        {
            long *p;
            p=(long*)addit[i].rdata;
            a.sin_addr.s_addr=(*p);
            sprintf(curr, "has IPv4 address : %s",inet_ntoa(a.sin_addr));
            strcat(app[total],curr);
        }
        // sprintf(curr, "\n");
    }
    printf("%s\n",app[total] );
        // sprintf(buff_app,"%s",app[total]);
}
 
void PrintData (unsigned char* data , int Size)
{
    int i , j;
    for(i=0 ; i < Size ; i++)
    {
        if( i!=0 && i%16==0)   //if one line of hex printing is complete...
        {
            sprintf(curr, "         ");
            strcat(payload[total],curr);
            for(j=i-16 ; j<i ; j++)
            {
                if(data[j]>=32 && data[j]<=128){
                    sprintf(curr, "%c",(unsigned char)data[j]); //if its a number or alphabet
                    strcat(payload[total],curr);
                }
                 
                else {
                    sprintf(curr, "."); 
                    strcat(payload[total],curr);
                }
                //otherwise print a dot
            }
            sprintf(curr, "\n");
            strcat(payload[total],curr);
        } 
         
        if(i%16==0) sprintf(curr, "   ");
            sprintf(curr, " %02X",(unsigned int)data[i]);
            strcat(payload[total],curr);
                 
        if( i==Size-1)  //print the last spaces
        {
            for(j=0;j<15-i%16;j++) 
            {
              sprintf(curr, "   "); //extra spaces
              strcat(payload[total],curr);
            }
             
            sprintf(curr, "         ");
            strcat(payload[total],curr);
             
            for(j=i-i%16 ; j<=i ; j++)
            {
                if(data[j]>=32 && data[j]<=128) 
                {
                  sprintf(curr, "%c",(unsigned char)data[j]);
                  strcat(payload[total],curr);
                }
                else
                {
                  sprintf(curr, ".");
                  strcat(payload[total],curr);
                }
            }
             
            sprintf(curr,  "\n" );
            strcat(payload[total],curr);
        }
    }
    printf("%s\n",payload[total] );
}


void initiateCapture()
{
    int saddr_size , data_size;
    struct sockaddr saddr;
         
    unsigned char *buffer = (unsigned char *) malloc(65536); //Its Big!
     
    // logfile=fopen("log1.txt","w");
    // if(logfile==NULL) 
    // {
    //     printf("Unable to create log.txt file.");
    // }
    printf("Starting...\n");
     
    int sock_raw = socket( AF_PACKET , SOCK_RAW , htons(ETH_P_ALL)) ;
    //setsockopt(sock_raw , SOL_SOCKET , SO_BINDTODEVICE , "eth0" , strlen("eth0")+ 1 );
     
    if(sock_raw < 0)
    {
        //Print the error with proper message
        perror("Socket Error");
        return ;
    }
    while(1)
    {
        saddr_size = sizeof saddr;
        //Receive a packet
        data_size = recvfrom(sock_raw , buffer , 65536 , 0 , &saddr , (socklen_t*)&saddr_size);
        if(data_size <0 )
        {
            printf("Recvfrom error , failed to get packets\n");
            return ;
        }
        //Now process the packet
        ProcessPacket(buffer , data_size);
        // printf("Processed:%d\n\n",total );
        if(total==1000){
            tcp=0,udp=0,icmp=0,others=0,igmp=0,total=0;
            break;
        }
    }
    for(int i=0;i<1000;i++)
    {
        printf("%s\n", ethernet[i]);
        printf("%s\n", network[i]);
        printf("%s\n", transport[i]);
        printf("%s\n", app[i]);
        printf("%s\n", payload[i]);
    }
    close(sock_raw);
    printf("\nFinished");
    return ;
}

