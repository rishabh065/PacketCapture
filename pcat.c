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
 
void ProcessPacket(unsigned char* , int);
void print_ethernet_header(unsigned char*, int);
void print_arp_packet(unsigned char * , int );
void print_ip_header(unsigned char* , int);
void print_icmp_packet(unsigned char* , int );
void print_tcp_packet(unsigned char * , int );
void print_udp_packet(unsigned char * , int );
void print_http_header(unsigned char * , int );
void print_dns_header(unsigned char* , int );
void PrintData (unsigned char* , int);
 
FILE *logfile;
struct sockaddr_in source,dest;
int tcp=0,udp=0,icmp=0,others=0,igmp=0,total=0,i,j;

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
 
int main()
{
    int saddr_size , data_size;
    struct sockaddr saddr;
         
    unsigned char *buffer = (unsigned char *) malloc(65536); //Its Big!
     
    logfile=fopen("log_app.txt","w");
    if(logfile==NULL) 
    {
        printf("Unable to create log.txt file.");
    }
    printf("Starting...\n");
    
    int sock_raw = socket( AF_PACKET , SOCK_RAW , htons(ETH_P_ALL)) ;
    //setsockopt(sock_raw , SOL_SOCKET , SO_BINDTODEVICE , "eth0" , strlen("eth0")+ 1 );
    if(sock_raw < 0)
    {
        //Print the error with proper message
        perror("Socket Error");
        return 1;
    }
    while(1)
    {
        saddr_size = sizeof saddr;
        //Receive a packet
        data_size = recvfrom(sock_raw , buffer , 65536 , 0 , &saddr , (socklen_t*)&saddr_size);
        if(data_size <0 )
        {
            printf("Recvfrom error , failed to get packets\n");
            return 1;
        }
        //Now process the packet
        ProcessPacket(buffer , data_size);
    }
    close(sock_raw);
    printf("Finished");
    return 0;
}
 
void ProcessPacket(unsigned char* buffer, int size)
{
    
    struct ethhdr *ehdr = (struct ethhdr*)(buffer);
    if (ehdr->h_proto == 1544)
    {
        print_arp_packet(buffer , size);
        return;
    }

    //Get the IP Header part of this packet , excluding the ethernet header
    struct iphdr *iph = (struct iphdr*)(buffer + sizeof(struct ethhdr));
    ++total;
    switch (iph->protocol) //Check the Protocol and do accordingly...
    {
        case 1:  //ICMP Protocol
            ++icmp;
            print_icmp_packet( buffer , size);
            break;
         
        case 2:  //IGMP Protocol
            ++igmp;
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
            break;
    }
    printf("TCP : %d   UDP : %d   ICMP : %d   IGMP : %d   Others : %d   Total : %d\r", tcp , udp , icmp , igmp , others , total);
}
 
void print_ethernet_header(unsigned char* Buffer, int Size)
{
    struct ethhdr *eth = (struct ethhdr *)Buffer;
     
    fprintf(logfile, "\n");
    fprintf(logfile, "Ethernet Header\n");
    fprintf(logfile, "   |-Destination Address : %.2X-%.2X-%.2X-%.2X-%.2X-%.2X \n", eth->h_dest[0] , eth->h_dest[1] , eth->h_dest[2] , eth->h_dest[3] , eth->h_dest[4] , eth->h_dest[5] );
    fprintf(logfile, "   |-Source Address      : %.2X-%.2X-%.2X-%.2X-%.2X-%.2X \n", eth->h_source[0] , eth->h_source[1] , eth->h_source[2] , eth->h_source[3] , eth->h_source[4] , eth->h_source[5] );
    fprintf(logfile, "   |-Protocol            : %u \n",(unsigned short)eth->h_proto);
}

void print_arp_packet(unsigned char* Buffer, int Size)
{
    print_ethernet_header(Buffer , Size);
    int header_size = sizeof(struct ethhdr);
    struct ARPhdr *arph = (struct ARPhdr *)(Buffer  + header_size);
    fprintf(logfile , "\n");
    fprintf(logfile , "ARP Header\n");
    fprintf(logfile , "   |-Format of hardware address : %d \n",arph->ar_hrd);
    fprintf(logfile , "   |-Format of protocol address : %d \n",arph->ar_pro);
    fprintf(logfile , "   |-Length of hardware address : %d \n",arph->ar_hln);
    fprintf(logfile , "   |-Length of protocol address : %d \n",arph->ar_pln);
    fprintf(logfile , "   |-Operation (command)        : %d \n",arph->ar_op);
    fprintf(logfile , "   |-Source MAC address         : %.2X-%.2X-%.2X-%.2X-%.2X-%.2X \n",arph->ar_sha[0],arph->ar_sha[1],arph->ar_sha[2],arph->ar_sha[3],arph->ar_sha[4],arph->ar_sha[5]);
    fprintf(logfile , "   |-Source IP address          : %d.%d.%d.%d \n",arph->ar_sip[0],arph->ar_sip[1],arph->ar_sip[2],arph->ar_sip[3]);
    fprintf(logfile , "   |-Destination MAC address    : %.2X-%.2X-%.2X-%.2X-%.2X-%.2X \n",arph->ar_tha[0],arph->ar_tha[1],arph->ar_tha[2],arph->ar_tha[3],arph->ar_tha[4],arph->ar_tha[5]);
    fprintf(logfile , "   |-Destination IP address     : %d.%d.%d.%d \n",arph->ar_tip[0],arph->ar_tip[1],arph->ar_tip[2],arph->ar_tip[3]);
}
 
void print_ip_header(unsigned char* Buffer, int Size)
{
    print_ethernet_header(Buffer , Size);
   
    unsigned short iphdrlen;
         
    struct iphdr *iph = (struct iphdr *)(Buffer  + sizeof(struct ethhdr) );
    iphdrlen =iph->ihl*4;
     
    memset(&source, 0, sizeof(source));
    source.sin_addr.s_addr = iph->saddr;
     
    memset(&dest, 0, sizeof(dest));
    dest.sin_addr.s_addr = iph->daddr;
     
    fprintf(logfile, "\n");
    fprintf(logfile, "IP Header\n");
    fprintf(logfile, "   |-IP Version        : %d\n",(unsigned int)iph->version);
    fprintf(logfile, "   |-IP Header Length  : %d DWORDS or %d Bytes\n",(unsigned int)iph->ihl,((unsigned int)(iph->ihl))*4);
    fprintf(logfile, "   |-Type Of Service   : %d\n",(unsigned int)iph->tos);
    fprintf(logfile, "   |-IP Total Length   : %d  Bytes(Size of Packet)\n",ntohs(iph->tot_len));
    fprintf(logfile, "   |-Identification    : %d\n",ntohs(iph->id));
    //fprintf(logfile, "   |-Reserved ZERO Field   : %d\n",(unsigned int)iphdr->ip_reserved_zero);
    //fprintf(logfile, "   |-Dont Fragment Field   : %d\n",(unsigned int)iphdr->ip_dont_fragment);
    //fprintf(logfile, "   |-More Fragment Field   : %d\n",(unsigned int)iphdr->ip_more_fragment);
    fprintf(logfile, "   |-TTL      : %d\n",(unsigned int)iph->ttl);
    fprintf(logfile, "   |-Protocol : %d\n",(unsigned int)iph->protocol);
    fprintf(logfile, "   |-Checksum : %d\n",ntohs(iph->check));
    fprintf(logfile, "   |-Source IP        : %s\n",inet_ntoa(source.sin_addr));
    fprintf(logfile, "   |-Destination IP   : %s\n",inet_ntoa(dest.sin_addr));
}
 
void print_tcp_packet(unsigned char* Buffer, int Size)
{
    unsigned short iphdrlen;
     
    struct iphdr *iph = (struct iphdr *)( Buffer  + sizeof(struct ethhdr) );
    iphdrlen = iph->ihl*4;
     
    struct tcphdr *tcph=(struct tcphdr*)(Buffer + iphdrlen + sizeof(struct ethhdr));
             
    int header_size =  sizeof(struct ethhdr) + iphdrlen + tcph->doff*4;
     
    fprintf(logfile, "\n\n***********************TCP Packet*************************\n");  
         
    print_ip_header(Buffer,Size);
         
    fprintf(logfile, "\n");
    fprintf(logfile, "TCP Header\n");
    fprintf(logfile, "   |-Source Port      : %u\n",ntohs(tcph->source));
    fprintf(logfile, "   |-Destination Port : %u\n",ntohs(tcph->dest));
    fprintf(logfile, "   |-Sequence Number    : %u\n",ntohl(tcph->seq));
    fprintf(logfile, "   |-Acknowledge Number : %u\n",ntohl(tcph->ack_seq));
    fprintf(logfile, "   |-Header Length      : %d DWORDS or %d BYTES\n" ,(unsigned int)tcph->doff,(unsigned int)tcph->doff*4);
    //fprintf(logfile, "   |-CWR Flag : %d\n",(unsigned int)tcph->cwr);
    //fprintf(logfile, "   |-ECN Flag : %d\n",(unsigned int)tcph->ece);
    fprintf(logfile, "   |-Urgent Flag          : %d\n",(unsigned int)tcph->urg);
    fprintf(logfile, "   |-Acknowledgement Flag : %d\n",(unsigned int)tcph->ack);
    fprintf(logfile, "   |-Push Flag            : %d\n",(unsigned int)tcph->psh);
    fprintf(logfile, "   |-Reset Flag           : %d\n",(unsigned int)tcph->rst);
    fprintf(logfile, "   |-Synchronise Flag     : %d\n",(unsigned int)tcph->syn);
    fprintf(logfile, "   |-Finish Flag          : %d\n",(unsigned int)tcph->fin);
    fprintf(logfile, "   |-Window         : %d\n",ntohs(tcph->window));
    fprintf(logfile, "   |-Checksum       : %d\n",ntohs(tcph->check));
    fprintf(logfile, "   |-Urgent Pointer : %d\n",tcph->urg_ptr);
    fprintf(logfile, "\n");
    fprintf(logfile, "                        DATA Dump                         ");
    fprintf(logfile, "\n");
         
    fprintf(logfile, "IP Header\n");
    PrintData(Buffer,iphdrlen);
         
    fprintf(logfile, "TCP Header\n");
    PrintData(Buffer+iphdrlen,tcph->doff*4);
         
    fprintf(logfile, "Data Payload\n");    
    PrintData(Buffer + header_size , Size - header_size );
                         
    

    if (ntohs(tcph->source) == 80 || ntohs(tcph->dest) == 80)
    {
        print_http_header(Buffer, Size);
    }
    
    if (ntohs(tcph->source) == 53 || ntohs(tcph->dest) == 53)
    {
        print_dns_header(Buffer, Size);
    }

    fprintf(logfile, "\n###########################################################");
}
 
void print_udp_packet(unsigned char *Buffer , int Size)
{
     
    unsigned short iphdrlen;
     
    struct iphdr *iph = (struct iphdr *)(Buffer +  sizeof(struct ethhdr));
    iphdrlen = iph->ihl*4;
     
    struct udphdr *udph = (struct udphdr*)(Buffer + iphdrlen  + sizeof(struct ethhdr));
     
    int header_size =  sizeof(struct ethhdr) + iphdrlen + sizeof udph;
     
    fprintf(logfile, "\n\n***********************UDP Packet*************************\n");
     
    print_ip_header(Buffer,Size);           
     
    fprintf(logfile, "\nUDP Header\n");
    fprintf(logfile, "   |-Source Port      : %d\n" , ntohs(udph->source));
    fprintf(logfile, "   |-Destination Port : %d\n" , ntohs(udph->dest));
    fprintf(logfile, "   |-UDP Length       : %d\n" , ntohs(udph->len));
    fprintf(logfile, "   |-UDP Checksum     : %d\n" , ntohs(udph->check));
     
    fprintf(logfile, "\n");
    fprintf(logfile, "IP Header\n");
    PrintData(Buffer , iphdrlen);
         
    fprintf(logfile, "UDP Header\n");
    PrintData(Buffer+iphdrlen , sizeof udph);
         
    fprintf(logfile, "Data Payload\n");    
     
    //Move the pointer ahead and reduce the size of string
    PrintData(Buffer + header_size , Size - header_size);
     
   

    if (ntohs(udph->source) == 53 || ntohs(udph->dest) == 53)
    {        
        print_dns_header(Buffer, Size);
    }

    fprintf(logfile, "\n###########################################################");
}
 
void print_icmp_packet(unsigned char* Buffer , int Size)
{
    unsigned short iphdrlen;
     
    struct iphdr *iph = (struct iphdr *)(Buffer  + sizeof(struct ethhdr));
    iphdrlen = iph->ihl * 4;
     
    struct icmphdr *icmph = (struct icmphdr *)(Buffer + iphdrlen  + sizeof(struct   ethhdr));
     
    int header_size =  sizeof(struct ethhdr) + iphdrlen + sizeof icmph;
     
    fprintf(logfile, "\n\n***********************ICMP Packet*************************\n"); 
     
    print_ip_header(Buffer , Size);
             
    fprintf(logfile, "\n");
         
    fprintf(logfile, "ICMP Header\n");
    fprintf(logfile, "   |-Type : %d",(unsigned int)(icmph->type));
             
    if((unsigned int)(icmph->type) == 11)
    {
        fprintf(logfile, "  (TTL Expired)\n");
    }
    else if((unsigned int)(icmph->type) == ICMP_ECHOREPLY)
    {
        fprintf(logfile, "  (ICMP Echo Reply)\n");
    }
     
    fprintf(logfile, "   |-Code : %d\n",(unsigned int)(icmph->code));
    fprintf(logfile, "   |-Checksum : %d\n",ntohs(icmph->checksum));
    //fprintf(logfile, "   |-ID       : %d\n",ntohs(icmph->id));
    //fprintf(logfile, "   |-Sequence : %d\n",ntohs(icmph->sequence));
    fprintf(logfile, "\n");
 
    fprintf(logfile, "IP Header\n");
    PrintData(Buffer,iphdrlen);
         
    fprintf(logfile, "UDP Header\n");
    PrintData(Buffer + iphdrlen , sizeof icmph);
         
    fprintf(logfile, "Data Payload\n");    
     
    //Move the pointer ahead and reduce the size of string
    PrintData(Buffer + header_size , (Size - header_size) );
     
    fprintf(logfile, "\n###########################################################");
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

    for (i = 0; i < http_size; ++i)
    {
        if (http_data[i] >= 32 && http_data[i] <= 128)
            fprintf(logfile, "%c",(unsigned char)http_data[i]);
        else
            fprintf(logfile, "\n");
    }
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

    struct QUESTION *qinfo = NULL;

    struct RES_RECORD answers[20],auth[20],addit[20];
    struct sockaddr_in a;
    unsigned char *reader, *qname;
    Buffer+=sizeof udph + iphdrlen + sizeof(struct ethhdr);
    qname =(unsigned char*)&Buffer[sizeof(struct DNS_HEADER)];
    //move ahead of the dns header and the query field
   
    reader = (Buffer+sizeof(struct DNS_HEADER) + (strlen((const char*)qname)+1) + sizeof(struct QUESTION));
    fprintf(logfile, "\nThe response contains : ");
    fprintf(logfile, "\n %d Questions.",ntohs(dns->q_count));
    fprintf(logfile, "\n %d Answers.",ntohs(dns->ans_count));
    fprintf(logfile, "\n %d Authoritative Servers.",ntohs(dns->auth_count));
    fprintf(logfile, "\n %d Additional records.\n\n",ntohs(dns->add_count));
 fflush(logfile);
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
    fprintf(logfile, "\nAnswer Records : %d \n" , ntohs(dns->ans_count) );
    for(i=0 ; i < ntohs(dns->ans_count) ; i++)
    {
        fprintf(logfile, "Name : %s ",answers[i].name);
 
        if( ntohs(answers[i].resource->type) == 1) //IPv4 address
        {
            long *p;
            p=(long*)answers[i].rdata;
            a.sin_addr.s_addr=(*p); //working without ntohl
            fprintf(logfile, "has IPv4 address : %s",inet_ntoa(a.sin_addr));
        }
         
        if(ntohs(answers[i].resource->type)==5) 
        {
            //Canonical name for an alias
            fprintf(logfile, "has alias name : %s",answers[i].rdata);
        }
 
        fprintf(logfile, "\n");
    }
 
    //print authorities
    fprintf(logfile, "\nAuthoritive Records : %d \n" , ntohs(dns->auth_count) );
    for( i=0 ; i < ntohs(dns->auth_count) ; i++)
    {
         
        fprintf(logfile, "Name : %s ",auth[i].name);
        if(ntohs(auth[i].resource->type)==2)
        {
            fprintf(logfile, "has nameserver : %s",auth[i].rdata);
        }
        fprintf(logfile, "\n");
    }
 
    //print additional resource records
    fprintf(logfile, "\nAdditional Records : %d \n" , ntohs(dns->add_count) );
    for(i=0; i < ntohs(dns->add_count) ; i++)
    {
        fprintf(logfile, "Name : %s ",addit[i].name);
        if(ntohs(addit[i].resource->type)==1)
        {
            long *p;
            p=(long*)addit[i].rdata;
            a.sin_addr.s_addr=(*p);
            fprintf(logfile, "has IPv4 address : %s",inet_ntoa(a.sin_addr));
        }
        fprintf(logfile, "\n");
    }
}
 
void PrintData (unsigned char* data , int Size)
{
    int i , j;
    for(i=0 ; i < Size ; i++)
    {
        if( i!=0 && i%16==0)   //if one line of hex printing is complete...
        {
            fprintf(logfile, "         ");
            for(j=i-16 ; j<i ; j++)
            {
                if(data[j]>=32 && data[j]<=128)
                    fprintf(logfile, "%c",(unsigned char)data[j]); //if its a number or alphabet
                 
                else fprintf(logfile, "."); //otherwise print a dot
            }
            fprintf(logfile, "\n");
        } 
         
        if(i%16==0) fprintf(logfile, "   ");
            fprintf(logfile, " %02X",(unsigned int)data[i]);
                 
        if( i==Size-1)  //print the last spaces
        {
            for(j=0;j<15-i%16;j++) 
            {
              fprintf(logfile, "   "); //extra spaces
            }
             
            fprintf(logfile, "         ");
             
            for(j=i-i%16 ; j<=i ; j++)
            {
                if(data[j]>=32 && data[j]<=128) 
                {
                  fprintf(logfile, "%c",(unsigned char)data[j]);
                }
                else
                {
                  fprintf(logfile, ".");
                }
            }
             
            fprintf(logfile,  "\n" );
        }
    }
}

