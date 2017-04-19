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
#include <gtk/gtk.h>
#include <string.h>
#include <stdlib.h>
/* Our callback.
 * The data passed to this function is printed to stdout */

/* This callback quits the program */
char ethernet[1000][1000];
char network[1000][1000];
char transport[1000][5000];
char payload[1000][5000];
char app[1000][1000];
char name_button[1000][10];
GtkTextBuffer *buff_ethernet;
GtkTextBuffer *buff_network;
GtkTextBuffer *buff_transport;
GtkTextBuffer *buff_app;
GtkTextBuffer *buff_payload;
GtkTextBuffer *counter;
GtkTextBuffer *stream;
char cnt[200];
GtkWidget *net_text,*eth_text,*app_text,*pay_text,*trans_text,
*counter_text,*st_button,*ex_button;
GtkWidget *button[1000];
static gboolean delete_event( GtkWidget *widget, GdkEvent  *event, gpointer   data )
{
    gtk_main_quit ();
    return FALSE;
}

static void trigger( GtkWidget *widget, GdkEvent  *event, gpointer   data )
{
    initiateCapture();
   
}
static void packet_display( GtkWidget *widget, GdkEvent  *event, gpointer   data )
{
    const char* label=gtk_button_get_label (GTK_BUTTON(widget));
    int pos= atoi(label+6)-1;
    gtk_text_buffer_set_text(buff_ethernet,ethernet[pos] ,strlen(ethernet[pos]));
    gtk_text_buffer_set_text(buff_network,network[pos] ,strlen(network[pos]));
    gtk_text_buffer_set_text(buff_transport,transport[pos] ,strlen(transport[pos]));
    gtk_text_buffer_set_text(buff_app,app[pos] ,strlen(app[pos]));
    gtk_text_buffer_set_text(buff_payload,payload[pos] ,strlen(payload[pos]));
}

void button_clicked(GtkWidget *widget, gpointer data)
{
  printf("%d\n",(gint) (glong)data );
}

char curr[5000];

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
    sprintf(ethernet[total], "%s"," ");
    sprintf(network[total], "%s"," ");
    sprintf(transport[total], "%s"," ");
    sprintf(app[total], "%s"," ");
    sprintf(payload[total], "%s"," ");

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
            total--;
            break;
    }
    ++total;
    
    sprintf(cnt,"TCP : %d   UDP : %d   ICMP : %d   IGMP : %d   Others : %d   Total : %d", tcp , udp , icmp , igmp , others , total);
    printf("%s\n",cnt );
    
    // sprintf(stdout);
}
 
void print_ethernet_header(unsigned char* Buffer, int Size)
{
    struct ethhdr *eth = (struct ethhdr *)Buffer;
     
    // sprintf(logfile, "\n");
    sprintf(curr, "Ethernet Header\n");
    sprintf(ethernet[total],"%s",curr);
    sprintf(curr, "   |-Destination Address : %.2X-%.2X-%.2X-%.2X-%.2X-%.2X \n", eth->h_dest[0] , eth->h_dest[1] , eth->h_dest[2] , eth->h_dest[3] , eth->h_dest[4] , eth->h_dest[5] );
    strcat(ethernet[total],curr);
    sprintf(curr, "   |-Source Address      : %.2X-%.2X-%.2X-%.2X-%.2X-%.2X \n", eth->h_source[0] , eth->h_source[1] , eth->h_source[2] , eth->h_source[3] , eth->h_source[4] , eth->h_source[5] );
    strcat(ethernet[total],curr);
    sprintf(curr, "   |-Protocol            : %u \n",(unsigned short)eth->h_proto);
    strcat(ethernet[total],curr);
    sprintf(name_button[total],"%s","ETH" );
    // printf("%s\n",ethernet[total] );
}

void print_arp_packet(unsigned char* Buffer, int Size)
{

    print_ethernet_header(Buffer , Size);
    int header_size = sizeof(struct ethhdr);
    struct ARPhdr *arph = (struct ARPhdr *)(Buffer  + header_size);
    sprintf(curr , "ARP Header\n");
    sprintf(network[total],"%s",curr);
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
    sprintf(name_button[total],"%s","ARP" );
    // printf("%s\n",network[total] );
}
 
void print_ip_header(unsigned char* Buffer, int Size)
{
    print_ethernet_header(Buffer , Size);
    
    struct iphdr *iph = (struct iphdr *)(Buffer  + sizeof(struct ethhdr) );
     
    memset(&source, 0, sizeof(source));
    source.sin_addr.s_addr = iph->saddr;
     
    memset(&dest, 0, sizeof(dest));
    dest.sin_addr.s_addr = iph->daddr;
    sprintf(name_button[total],"%s","IP" );
    // sprintf(logfile, "\n");
    sprintf(curr, "IP Header\n");
    sprintf(network[total],"%s",curr);
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
    // printf("%s\n",network[total] );
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
    sprintf(transport[total],"%s",curr);
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
    sprintf(name_button[total],"%s","TCP" );
    if (ntohs(tcph->source) == 80 || ntohs(tcph->dest) == 80)
    {
        print_http_header(Buffer, Size);
    }
    
    if (ntohs(tcph->source) == 53 || ntohs(tcph->dest) == 53)
    {
        print_dns_header(Buffer, Size);
    }

    // printf("%s\n",transport[total] );
    sprintf(curr, "                        DATA Dump                         \n");
    sprintf(payload[total],"%s",curr);    
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
    sprintf(transport[total],"%s",curr);
    sprintf(curr, "   |-Source Port      : %d\n" , ntohs(udph->source));
    strcat(transport[total],curr);
    sprintf(curr, "   |-Destination Port : %d\n" , ntohs(udph->dest));
    strcat(transport[total],curr);
    sprintf(curr, "   |-UDP Length       : %d\n" , ntohs(udph->len));
    strcat(transport[total],curr);
    sprintf(curr, "   |-UDP Checksum     : %d\n" , ntohs(udph->check));
    strcat(transport[total],curr);
    sprintf(name_button[total],"%s","UDP" );
    if (ntohs(udph->source) == 53 || ntohs(udph->dest) == 53)
    {        
        print_dns_header(Buffer, Size);
    }
    // printf("%s\n",transport[total] );
    

    sprintf(curr, "                        DATA Dump                         \n");
    sprintf(payload[total],"%s",curr);    
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
    // printf("%s\n",network[total] );
    sprintf(curr, "                        DATA Dump                         \n");
    sprintf(payload[total],"%s",curr); 
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
    sprintf(name_button[total],"%s","ICMP" );
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
    sprintf(app[total],"%s",curr); 
    for (i = 0; i < http_size; ++i)
    {
        if (http_data[i] >= 32 && http_data[i] <= 128)
            sprintf(curr, "%c",(unsigned char)http_data[i]);
        else
            sprintf(curr, "\n");
        strcat(app[total],curr);
    }
    sprintf(name_button[total],"%s","HTTP" );
    // printf("%s\n",app[total] );
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
    sprintf(app[total],"%s",curr); 
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
    // printf("%s\n",app[total] );
        // sprintf(buff_app,"%s",app[total]);
    sprintf(name_button[total],"%s","DNS" );
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
    FILE* fp=fopen("log(n).txt","w");
    for (int i = 0; i < 1000; ++i)
    {
        fprintf(fp,"Position:%d\n",i );
        fprintf(fp,"%s\n", ethernet[i]);
        fprintf(fp,"%s\n", network[i]);
        fprintf(fp,"%s\n", transport[i]);
        fprintf(fp,"%s\n", app[i]);
        fprintf(fp,"%s\n", payload[i]);
    }
    gtk_text_buffer_set_text(counter,cnt ,strlen(cnt));
    
    close(sock_raw);
    printf("\nFinished");

    return ;
}

int main( int   argc,
          char *argv[] )
{

    GtkWidget *window,*scrolled_window,*table2;
    
    GtkWidget *table;
    buff_ethernet=gtk_text_buffer_new(NULL);
    buff_network=gtk_text_buffer_new(NULL);
    buff_transport=gtk_text_buffer_new(NULL);
    buff_app=gtk_text_buffer_new(NULL);
    buff_payload=gtk_text_buffer_new(NULL);
    counter=gtk_text_buffer_new(NULL);
    stream=gtk_text_buffer_new(NULL);
    gtk_init (&argc, &argv);

    /* Create a new window */
    window = gtk_window_new (GTK_WINDOW_TOPLEVEL);
    gtk_window_set_position(GTK_WINDOW(window), GTK_WIN_POS_CENTER);
    gtk_widget_set_size_request (window, 1100, 700);
    // gtk_window_fullscreen ((GtkWindow *)window);

    /* Set the window title */
    gtk_window_set_title (GTK_WINDOW (window), "P.C.A.T.");

    /* Set a handler for delete_event that immediately
     * exits GTK. */
    g_signal_connect (window, "delete-event",
                      G_CALLBACK (delete_event), NULL);

    /* Sets the border width of the window. */
    gtk_container_set_border_width (GTK_CONTAINER (window), 10);

    /* Create a 2x2 table */
    table = gtk_table_new (27, 23, TRUE);
    gtk_widget_show (table);
    /* Put the table in the main window */
    gtk_container_add (GTK_CONTAINER (window), table);

    gtk_widget_show (table);
    scrolled_window = gtk_scrolled_window_new (NULL, NULL);
    
    gtk_container_set_border_width (GTK_CONTAINER (scrolled_window), 5);

    gtk_scrolled_window_set_policy (GTK_SCROLLED_WINDOW (scrolled_window),
                                    GTK_POLICY_AUTOMATIC, GTK_POLICY_ALWAYS);

    gtk_table_attach(GTK_TABLE(table), scrolled_window, 21, 24, 0, 25, 
        GTK_FILL, GTK_FILL, 0, 0);
    gtk_widget_show (scrolled_window);
    table2 = gtk_table_new (1000, 1, FALSE);
    
    /* set the spacing to 10 on x and 10 on y */
    gtk_table_set_row_spacings (GTK_TABLE (table2), 5);
    // gtk_table_set_col_spacings (GTK_TABLE (table2), 5);
    
    /* pack the table into the scrolled window */
    gtk_scrolled_window_add_with_viewport (GTK_SCROLLED_WINDOW (scrolled_window), table2);
    gtk_widget_show (table2);
    /* Insert button 1 into the upper left quadrant of the table */
    
    for(int i=0;i<5;i++)
    {
        GtkWidget* scrolled_window = gtk_scrolled_window_new (NULL, NULL);
        gtk_container_set_border_width (GTK_CONTAINER (scrolled_window), 5);

        gtk_scrolled_window_set_policy (GTK_SCROLLED_WINDOW (scrolled_window),
                                    GTK_POLICY_AUTOMATIC, GTK_POLICY_AUTOMATIC);
        gtk_table_attach(GTK_TABLE(table), scrolled_window,  0, 21, i*5, 5*i+5, 
        GTK_FILL, GTK_FILL, 0, 0);
        gtk_widget_show (scrolled_window);
        if(i==0){
            eth_text=gtk_text_view_new_with_buffer (buff_ethernet);
            gtk_text_view_set_editable(GTK_TEXT_VIEW(eth_text), FALSE);
            gtk_text_view_set_cursor_visible(GTK_TEXT_VIEW(eth_text), TRUE);
            gtk_scrolled_window_add_with_viewport (GTK_SCROLLED_WINDOW (scrolled_window), eth_text);
            gtk_widget_show (eth_text);
        }
        if(i==1){
            net_text=gtk_text_view_new_with_buffer (buff_network);
            gtk_text_view_set_editable(GTK_TEXT_VIEW(net_text), FALSE);
            gtk_text_view_set_cursor_visible(GTK_TEXT_VIEW(net_text), FALSE);
            gtk_scrolled_window_add_with_viewport (GTK_SCROLLED_WINDOW (scrolled_window), net_text);
            gtk_widget_show (net_text);
        }
        if(i==2){
            trans_text=gtk_text_view_new_with_buffer (buff_transport);
            gtk_text_view_set_editable(GTK_TEXT_VIEW(trans_text), FALSE);
            gtk_text_view_set_cursor_visible(GTK_TEXT_VIEW(trans_text), FALSE);
            gtk_scrolled_window_add_with_viewport (GTK_SCROLLED_WINDOW (scrolled_window), trans_text);
            gtk_widget_show (trans_text);
        }
        if(i==3)
        {
            app_text=gtk_text_view_new_with_buffer (buff_app);
            gtk_text_view_set_editable(GTK_TEXT_VIEW(app_text), FALSE);
            gtk_text_view_set_cursor_visible(GTK_TEXT_VIEW(app_text), FALSE);
            gtk_scrolled_window_add_with_viewport (GTK_SCROLLED_WINDOW (scrolled_window), app_text);
            gtk_widget_show (app_text);
        }
        if(i==4){
            pay_text=gtk_text_view_new_with_buffer (buff_payload);
            gtk_text_view_set_editable(GTK_TEXT_VIEW(pay_text), FALSE);
            gtk_text_view_set_cursor_visible(GTK_TEXT_VIEW(pay_text), FALSE);
            gtk_scrolled_window_add_with_viewport (GTK_SCROLLED_WINDOW (scrolled_window), pay_text);
            gtk_widget_show (pay_text);
        }
    }
    char buffer[10];
    for (int i = 0; i < 1000; i++){
       // for (j = 0; j < 10; j++) {
          sprintf (buffer, "Packet %d\n", i+1);
          button[i] = gtk_button_new_with_label (buffer);
          gtk_table_attach(GTK_TABLE(table2), button[i],0,1, i, i+1, GTK_FILL | GTK_EXPAND, GTK_FILL | GTK_EXPAND, 2, 1);
          g_signal_connect (G_OBJECT(button[i]), "clicked",
                      G_CALLBACK (packet_display),NULL);
          gtk_widget_show (button[i]);
          sprintf(transport[i],"%s","");
          sprintf(network[i],"%s","");
          sprintf(app[i],"%s","");
          sprintf(ethernet[i],"%s","");
          sprintf(payload[i],"%s","");
       }
    /* Create second button[i] */
       // text=gtk_text_view_new();
       //  gtk_text_view_set_editable(GTK_TEXT_VIEW(text), FALSE);
       //  gtk_text_view_set_cursor_visible(GTK_TEXT_VIEW(text), FALSE);
       //  // gtk_table_attach(GTK_TABLE(table), text, 0, 10, i*2, 2*i+2, 
       //  // GTK_FILL | GTK_EXPAND, GTK_FILL | GTK_EXPAND, 1, 1);
       //  gtk_table_attach_defaults (GTK_TABLE (table), text, 0, 24, 26,27);
       //  gtk_widget_show (text);


    /* Create "Quit" button */
    ex_button = gtk_button_new_with_label ("Quit");
   
    /* When the button is clicked, we call the "delete-event" function
     * and the program exits */
    g_signal_connect (ex_button, "clicked",G_CALLBACK (delete_event), NULL);

    /* Insert the quit button into the both 
     * lower quadrants of the table */
    gtk_table_attach_defaults (GTK_TABLE (table), ex_button, 21, 24, 26,27);
    gtk_widget_show (ex_button);
    st_button = gtk_button_new_with_label ("Start");
    g_signal_connect (st_button, "clicked",G_CALLBACK (trigger), NULL);
    gtk_table_attach_defaults (GTK_TABLE (table), st_button, 18, 21, 26,27);
    gtk_widget_show (st_button);

    GtkWidget *stream_text=gtk_text_view_new_with_buffer (stream);
    gtk_text_view_set_editable(GTK_TEXT_VIEW(stream_text), FALSE);
    gtk_text_view_set_cursor_visible(GTK_TEXT_VIEW(stream_text), FALSE);
    gtk_table_attach_defaults (GTK_TABLE (table), stream_text, 11, 15, 26,27);
    gtk_widget_show (stream_text);
    counter_text=gtk_text_view_new_with_buffer (counter);
    gtk_text_view_set_editable(GTK_TEXT_VIEW(counter_text), FALSE);
    gtk_text_view_set_cursor_visible(GTK_TEXT_VIEW(counter_text), FALSE);
    gtk_table_attach_defaults (GTK_TABLE (table), counter_text, 0, 10, 26,27);
    gtk_widget_show (counter_text);
    gtk_widget_show (window);

    gtk_main ();

    return 0;
}

