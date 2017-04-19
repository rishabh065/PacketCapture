#include <string.h>     //For using helper string functions such as strlen, strcmp, strcpy etc.
#include <stdio.h>      //For standard input output and file I/O operations
#include <stdlib.h>     //For memorry allocation function
#include <gtk/gtk.h>    //For GUI
#include "pcat.h"
// The following headers support the network functionalities and provide necessary data structures
#include <unistd.h>
#include <netinet/in.h>
#include <netinet/ip_icmp.h>   //Contains data structure required to decode ICMP header
#include <netinet/udp.h>   //Contains data structure required to decode UDP header
#include <netinet/tcp.h>   //Contains data structure required to decode TCP header
#include <netinet/ip.h>    //Contains data structure required to decode IP header
#include <net/ethernet.h>  //Contains data structure required to decode Ethernet header
#include <sys/socket.h>     // Socket API
#include <arpa/inet.h>     // Big Endian / Little Endian conversions
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
int tcp_packet_count,udp_packet_count,icmp_packet_count,total_packet_count;
int arp_packet_count,http_packet_count,dns_packet_count, i,j;
int line;
//DNS header structure
struct DNS_HEADER
{
    unsigned short id_num; // identification number
 
    unsigned char rec_des :1; // recursion desired
    unsigned char truncated :1; // truncated message
    unsigned char authoritive :1; // authoritive answer
    unsigned char opcode :4; // purpose of message
    unsigned char query_response_flag :1; // query/response flag
 
    unsigned char response_code :4; // response code
    unsigned char checking_disabled :1; // checking disabled
    unsigned char authenticated :1; // authenticated data
    unsigned char z :1; // its z! reserved
    unsigned char recursion_available :1; // recursion available
 
    unsigned short DNS_QUESTION_count; // number of DNS_QUESTION entries
    unsigned short answer_count; // number of answer entries
    unsigned short auth_rec_count; // number of authority entries
    unsigned short additional_rec_count; // number of resource entries
};
//Constant sized fields of the resource record structure
#pragma pack(push, 1)
struct RECORD_DATA
{
    unsigned short type;
    unsigned short _class;
    unsigned int ttl;
    unsigned short data_len;
};
#pragma pack(pop)
 
//Constant sized fields of query structure
struct DNS_QUESTION
{
    unsigned short query_type;
    unsigned short query_class;
};

//Structure of a Query
typedef struct
{
    unsigned char *name;
    struct DNS_QUESTION *ques;
} QUERY;
 
//Pointers to resource record contents
struct RESOURCE_RECORD
{
    unsigned char *name;
    struct RECORD_DATA *resource;
    unsigned char *record_data;
};
 

// Structure of ARP

struct ARPhdr
  {
    unsigned short int arp_ha;      
    unsigned short int ar_pro;      
    unsigned char ar_hln;       
    unsigned char ar_pln;       
    unsigned short int ar_op;       
    unsigned char ar_sha[ETH_ALEN]; 
    unsigned char ar_sip[4];        
    unsigned char ar_tha[ETH_ALEN]; 
    unsigned char ar_tip[4];

  };

void Packet_Processor(unsigned char* buffer, int size)
{
    sprintf(ethernet[total_packet_count], "%s"," ");
    sprintf(network[total_packet_count], "%s"," ");
    sprintf(transport[total_packet_count], "%s"," ");
    sprintf(app[total_packet_count], "%s"," ");
    sprintf(payload[total_packet_count], "%s"," ");

    struct ethhdr *ehdr = (struct ethhdr*)(buffer);
    if (ehdr->h_proto == 1544)
    {
        ARP_Packet_Decoder(buffer , size);
        ++arp_packet_count;
        ++total_packet_count;
        return;
    }

    struct iphdr *iph = (struct iphdr*)(buffer + sizeof(struct ethhdr));
    switch (iph->protocol) 
    {
        case 1:  //ICMP Protocol
            ++icmp_packet_count;
            ICMP_Packet_Decoder( buffer , size);
            break;
         
        case 6:  //TCP Protocol
            ++tcp_packet_count;
            printf("%d\n",tcp_packet_count );
            TCP_Packet_Decoder(buffer , size);
            break;
         
        case 17: //UDP Protocol
            ++udp_packet_count;
            UDP_Packet_Decoder(buffer , size);
            break;
         
        default: 
            total_packet_count--;
            break;
    }
    ++total_packet_count;
    
    sprintf(cnt,"HTTP : %d   DNS : %d   ICMP : %d  ARP : %d Total : %d", http_packet_count , dns_packet_count , icmp_packet_count , arp_packet_count, total_packet_count);
    printf("%s\n",cnt );
    
    // sprintf(stdout);
}
 
void Ethernet_Header_Decoder(unsigned char* Buffer, int Size)
{
    struct ethhdr *eth = (struct ethhdr *)Buffer;
     
    // sprintf(logfile, "\n");
    sprintf(curr, "Ethernet Header\n");
    sprintf(ethernet[total_packet_count],"%s",curr);
    sprintf(curr, "\t--Destination Address : %.2X-%.2X-%.2X-%.2X-%.2X-%.2X \n", eth->h_dest[0] , eth->h_dest[1] , eth->h_dest[2] , eth->h_dest[3] , eth->h_dest[4] , eth->h_dest[5] );
    strcat(ethernet[total_packet_count],curr);
    sprintf(curr, "\t--Source Address      : %.2X-%.2X-%.2X-%.2X-%.2X-%.2X \n", eth->h_source[0] , eth->h_source[1] , eth->h_source[2] , eth->h_source[3] , eth->h_source[4] , eth->h_source[5] );
    strcat(ethernet[total_packet_count],curr);
    sprintf(curr, "\t--Protocol            : %u \n",(unsigned short)eth->h_proto);
    strcat(ethernet[total_packet_count],curr);
    sprintf(name_button[total_packet_count],"%s","ETH" );
    // printf("%s\n",ethernet[total_packet_count] );
}

void ARP_Packet_Decoder(unsigned char* Buffer, int Size)
{

    Ethernet_Header_Decoder(Buffer , Size);
    int header_size = sizeof(struct ethhdr);
    struct ARPhdr *arph = (struct ARPhdr *)(Buffer  + header_size);
    sprintf(curr , "ARP Header\n");
    sprintf(network[total_packet_count],"%s",curr);
    sprintf(curr , "\t--Format of hardware address : %d \n",arph->arp_ha);
    strcat(network[total_packet_count],curr);
    sprintf(curr , "\t--Format of protocol address : %d \n",arph->ar_pro);
    strcat(network[total_packet_count],curr);
    sprintf(curr , "\t--Length of hardware address : %d \n",arph->ar_hln);
    strcat(network[total_packet_count],curr);
    sprintf(curr , "\t--Length of protocol address : %d \n",arph->ar_pln);
    strcat(network[total_packet_count],curr);
    sprintf(curr , "\t--Operation (command)        : %d \n",arph->ar_op);
    strcat(network[total_packet_count],curr);
    sprintf(curr , "\t--Source MAC address         : %.2X-%.2X-%.2X-%.2X-%.2X-%.2X \n",arph->ar_sha[0],arph->ar_sha[1],arph->ar_sha[2],arph->ar_sha[3],arph->ar_sha[4],arph->ar_sha[5]);
    strcat(network[total_packet_count],curr);
    sprintf(curr , "\t--Source IP address          : %d.%d.%d.%d \n",arph->ar_sip[0],arph->ar_sip[1],arph->ar_sip[2],arph->ar_sip[3]);
    strcat(network[total_packet_count],curr);
    sprintf(curr , "\t--Destination MAC address    : %.2X-%.2X-%.2X-%.2X-%.2X-%.2X \n",arph->ar_tha[0],arph->ar_tha[1],arph->ar_tha[2],arph->ar_tha[3],arph->ar_tha[4],arph->ar_tha[5]);
    strcat(network[total_packet_count],curr);
    sprintf(curr , "\t--Destination IP address     : %d.%d.%d.%d \n",arph->ar_tip[0],arph->ar_tip[1],arph->ar_tip[2],arph->ar_tip[3]);
    strcat(network[total_packet_count],curr);
    sprintf(name_button[total_packet_count],"%s","ARP" );
    // printf("%s\n",network[total_packet_count] );
}
 
void IP_Header_Decoder(unsigned char* Buffer, int Size)
{
    Ethernet_Header_Decoder(Buffer , Size);
    
    struct iphdr *iph = (struct iphdr *)(Buffer  + sizeof(struct ethhdr) );
     
    memset(&source, 0, sizeof(source));
    source.sin_addr.s_addr = iph->saddr;
     
    memset(&dest, 0, sizeof(dest));
    dest.sin_addr.s_addr = iph->daddr;
    sprintf(name_button[total_packet_count],"%s","IP" );
    // sprintf(logfile, "\n");
    sprintf(curr, "IP Header\n");
    sprintf(network[total_packet_count],"%s",curr);
    sprintf(curr, "\t--IP Version        : %d\n",(unsigned int)iph->version);
    strcat(network[total_packet_count],curr);
    sprintf(curr, "\t--IP Header Length  : %d DWORDS or %d Bytes\n",(unsigned int)iph->ihl,((unsigned int)(iph->ihl))*4);
    strcat(network[total_packet_count],curr);
    sprintf(curr, "\t--Type Of Service   : %d\n",(unsigned int)iph->tos);
    strcat(network[total_packet_count],curr);
    sprintf(curr, "\t--IP total_packet_count Length   : %d  Bytes(Size of Packet)\n",ntohs(iph->tot_len));
    strcat(network[total_packet_count],curr);
    sprintf(curr, "\t--Identification    : %d\n",ntohs(iph->id));
    //sprintf(curr, "\t--Reserved ZERO Field   : %d\n",(unsigned int)iphdr->ip_reserved_zero);
    //sprintf(curr, "\t--Dont Fragment Field   : %d\n",(unsigned int)iphdr->ip_dont_fragment);
    //sprintf(curr, "\t--More Fragment Field   : %d\n",(unsigned int)iphdr->ip_more_fragment);
    strcat(network[total_packet_count],curr);
    sprintf(curr, "\t--TTL      : %d\n",(unsigned int)iph->ttl);
    strcat(network[total_packet_count],curr);
    sprintf(curr, "\t--Protocol : %d\n",(unsigned int)iph->protocol);
    strcat(network[total_packet_count],curr);
    sprintf(curr, "\t--Checksum : %d\n",ntohs(iph->check));
    strcat(network[total_packet_count],curr);
    sprintf(curr, "\t--Source IP        : %s\n",inet_ntoa(source.sin_addr));
    strcat(network[total_packet_count],curr);
    sprintf(curr, "\t--Destination IP   : %s\n",inet_ntoa(dest.sin_addr));
    strcat(network[total_packet_count],curr);
    // printf("%s\n",network[total_packet_count] );
}
 
void TCP_Packet_Decoder(unsigned char* Buffer, int Size)
{
    unsigned short ip_hdr_length;
     
    struct iphdr *iph = (struct iphdr *)( Buffer  + sizeof(struct ethhdr) );
    ip_hdr_length = iph->ihl*4;
     
    struct tcphdr *tcph=(struct tcphdr*)(Buffer + ip_hdr_length + sizeof(struct ethhdr));
             
    int header_size =  sizeof(struct ethhdr) + ip_hdr_length + tcph->doff*4;
     
    // sprintf(logfile, "\n\n***********************TCP Packet*************************\n");  
         
    IP_Header_Decoder(Buffer,Size);
    // sprintf(logfile, "\n");
    sprintf(curr, "TCP Header\n");
    sprintf(transport[total_packet_count],"%s",curr);
    sprintf(curr, "\t--Source Port      : %u\n",ntohs(tcph->source));
    strcat(transport[total_packet_count],curr);
    sprintf(curr, "\t--Destination Port : %u\n",ntohs(tcph->dest));
    strcat(transport[total_packet_count],curr);
    sprintf(curr, "\t--Sequence Number    : %u\n",ntohl(tcph->seq));
    strcat(transport[total_packet_count],curr);
    sprintf(curr, "\t--Acknowledge Number : %u\n",ntohl(tcph->ack_seq));
    strcat(transport[total_packet_count],curr);
    sprintf(curr, "\t--Header Length      : %d DWORDS or %d BYTES\n" ,(unsigned int)tcph->doff,(unsigned int)tcph->doff*4);
    strcat(transport[total_packet_count],curr);
    sprintf(curr, "\t--Urgent Flag          : %d\n",(unsigned int)tcph->urg);
    strcat(transport[total_packet_count],curr);
    sprintf(curr, "\t--Acknowledgement Flag : %d\n",(unsigned int)tcph->ack);
    strcat(transport[total_packet_count],curr);
    sprintf(curr, "\t--Push Flag            : %d\n",(unsigned int)tcph->psh);
    strcat(transport[total_packet_count],curr);
    sprintf(curr, "\t--Reset Flag           : %d\n",(unsigned int)tcph->rst);
    strcat(transport[total_packet_count],curr);
    sprintf(curr, "\t--Synchronise Flag     : %d\n",(unsigned int)tcph->syn);
    strcat(transport[total_packet_count],curr);
    sprintf(curr, "\t--Finish Flag          : %d\n",(unsigned int)tcph->fin);
    strcat(transport[total_packet_count],curr);
    sprintf(curr, "\t--Window         : %d\n",ntohs(tcph->window));
    strcat(transport[total_packet_count],curr);
    sprintf(curr, "\t--Checksum       : %d\n",ntohs(tcph->check));
    strcat(transport[total_packet_count],curr);
    sprintf(curr, "\t--Urgent Pointer : %d\n",tcph->urg_ptr);
    strcat(transport[total_packet_count],curr);
    // sprintf(logfile, "\n");
    sprintf(name_button[total_packet_count],"%s","TCP" );
    if (ntohs(tcph->source) == 80 || ntohs(tcph->dest) == 80)
    {
        ++http_packet_count;
        HTTP_Packet_Header(Buffer, Size);
    }
    
    if (ntohs(tcph->source) == 53 || ntohs(tcph->dest) == 53)
    {
        ++dns_packet_count;
        DNS_Packet_Decoder(Buffer, Size);
    }

    sprintf(curr, "                        DATA Dump                         \n");
    sprintf(payload[total_packet_count],"%s",curr);    
    sprintf(curr, "IP Header\n");
    strcat(payload[total_packet_count],curr);
    Print_Data_Dump(Buffer,ip_hdr_length);
         
    sprintf(curr, "TCP Header\n");
    strcat(payload[total_packet_count],curr);
    Print_Data_Dump(Buffer+ip_hdr_length,tcph->doff*4);

    sprintf(curr, "Data Payload\n");
    strcat(payload[total_packet_count],curr);    
    Print_Data_Dump(Buffer + header_size , Size - header_size );
}
 
void UDP_Packet_Decoder(unsigned char *Buffer , int Size)
{
     
    unsigned short ip_hdr_length;
     
    struct iphdr *iph = (struct iphdr *)(Buffer +  sizeof(struct ethhdr));
    ip_hdr_length = iph->ihl*4;
     
    struct udphdr *udph = (struct udphdr*)(Buffer + ip_hdr_length  + sizeof(struct ethhdr));
     
    int header_size =  sizeof(struct ethhdr) + ip_hdr_length + sizeof udph;
     
   
    IP_Header_Decoder(Buffer,Size);           
    sprintf(curr, "UDP Header\n");
    sprintf(transport[total_packet_count],"%s",curr);
    sprintf(curr, "\t--Source Port      : %d\n" , ntohs(udph->source));
    strcat(transport[total_packet_count],curr);
    sprintf(curr, "\t--Destination Port : %d\n" , ntohs(udph->dest));
    strcat(transport[total_packet_count],curr);
    sprintf(curr, "\t--UDP Length       : %d\n" , ntohs(udph->len));
    strcat(transport[total_packet_count],curr);
    sprintf(curr, "\t--UDP Checksum     : %d\n" , ntohs(udph->check));
    strcat(transport[total_packet_count],curr);
    sprintf(name_button[total_packet_count],"%s","UDP" );
    if (ntohs(udph->source) == 53 || ntohs(udph->dest) == 53)
    {        
        DNS_Packet_Decoder(Buffer, Size);
    }
   

    sprintf(curr, "                        DATA Dump                         \n");
    sprintf(payload[total_packet_count],"%s",curr);    
    sprintf(curr, "IP Header\n");
    strcat(payload[total_packet_count],curr);
    Print_Data_Dump(Buffer,ip_hdr_length);
         
    sprintf(curr, "UDP Header\n");
    strcat(payload[total_packet_count],curr);
    Print_Data_Dump(Buffer+ip_hdr_length , sizeof udph);
         
    sprintf(curr, "Data Payload\n");    
    strcat(payload[total_packet_count],curr);
    //Move the pointer ahead and reduce the size of string
    Print_Data_Dump(Buffer + header_size , Size - header_size);

    // sprintf(curr, "\n###########################################################");
}
 
void ICMP_Packet_Decoder(unsigned char* Buffer , int Size)
{
    unsigned short ip_hdr_length;
     
    struct iphdr *iph = (struct iphdr *)(Buffer  + sizeof(struct ethhdr));
    ip_hdr_length = iph->ihl * 4;
     
    struct icmphdr *icmph = (struct icmphdr *)(Buffer + ip_hdr_length  + sizeof(struct   ethhdr));
     
    int header_size =  sizeof(struct ethhdr) + ip_hdr_length + sizeof icmph;
     
    // sprintf(logfile, "\n\n***********************ICMP Packet*************************\n"); 
     
    IP_Header_Decoder(Buffer , Size);
    // sprintf(logfile, "\n");
    
    sprintf(curr, "ICMP Header\n");
    strcat(network[total_packet_count],curr);
    
    sprintf(curr, "\t--Type : %d\n",(unsigned int)(icmph->type));
    strcat(network[total_packet_count],curr);

    if((unsigned int)(icmph->type) == 11)
    {
        sprintf(curr, "  (TTL Expired)\n");
        strcat(network[total_packet_count],curr);
    }

    else if((unsigned int)(icmph->type) == ICMP_ECHOREPLY)
    {
        
        sprintf(curr, "  (ICMP Echo Reply)\n");
        strcat(network[total_packet_count],curr);
    }

     
    
    sprintf(curr, "\t--Code : %d\n",(unsigned int)(icmph->code));
    strcat(network[total_packet_count],curr);

    sprintf(curr, "\t--Checksum : %d\n",ntohs(icmph->checksum));
    strcat(network[total_packet_count],curr);
    sprintf(curr, "                        DATA Dump                         \n");
    sprintf(payload[total_packet_count],"%s",curr); 
    sprintf(curr, "IP Header\n");
    strcat(payload[total_packet_count],curr);
    Print_Data_Dump(Buffer,ip_hdr_length);
         
    sprintf(curr, "UDP Header\n");
    strcat(payload[total_packet_count],curr);
    Print_Data_Dump(Buffer + ip_hdr_length , sizeof icmph);
         
    sprintf(curr, "Data Payload\n");    
    strcat(payload[total_packet_count],curr);
    Print_Data_Dump(Buffer + header_size , (Size - header_size) );
    sprintf(name_button[total_packet_count],"%s","ICMP" );
}

void HTTP_Packet_Header(unsigned char* Buffer , int Size)
{
    unsigned short ip_hdr_length;
     
    struct iphdr *iph = (struct iphdr *)( Buffer  + sizeof(struct ethhdr) );
    ip_hdr_length = iph->ihl*4;
     
    struct tcphdr *tcph=(struct tcphdr*)(Buffer + ip_hdr_length + sizeof(struct ethhdr));
             
    int tcp_header_size = tcph->doff*4;

    unsigned char* http_data = Buffer + ip_hdr_length + sizeof(struct ethhdr) + tcp_header_size;

    int http_size = Size - ip_hdr_length - sizeof(struct ethhdr) - tcp_header_size;

    int i;
    sprintf(curr, "HTTP Header\n");
    sprintf(app[total_packet_count],"%s",curr); 
    for (i = 0; i < http_size; ++i)
    {
        if (http_data[i] >= 32 && http_data[i] <= 128)
            sprintf(curr, "%c",(unsigned char)http_data[i]);
        else
            sprintf(curr, "\n");
        strcat(app[total_packet_count],curr);
    }
    sprintf(name_button[total_packet_count],"%s","HTTP" );
    // printf("%s\n",app[total_packet_count] );
    // sprintf(buff_app,"%s",app[total_packet_count]);
}

u_char* DNS_Decodee_Helper(unsigned char* temp_buff,unsigned char* buffer,int* count)
{
    int i , j;
    unsigned char *server_name;
    unsigned int l=0,flag=0,ofst;
    server_name = (unsigned char*)malloc(256);
 
    *count = 1;
    server_name[0]='\0';
 
    while(*temp_buff!=0)
    {
        if(*temp_buff>=192)
        {
            ofst = (*temp_buff)*256 + *(temp_buff+1) - 49152;
            temp_buff = buffer + ofst - 1;
            flag = 1;
        }
        else
        {
            server_name[l++]=*temp_buff;
        }
 
        temp_buff = temp_buff+1;
 
        if(flag==0)
        {
            *count = *count + 1;
        }
    }
 
    server_name[l]='\0';
    if(flag==1)
    {
        *count = *count + 1;
    }
 
    for(i=0;i<(int)strlen((const char*)server_name);i++) 
    {
        l=server_name[i];
        for(j=0;j<(int)l;j++) 
        {
            server_name[i]=server_name[i+1];
            i=i+1;
        }
        server_name[i]='.';
    }
    server_name[i-1]='\0';
    return server_name;
}

void DNS_Packet_Decoder(unsigned char* Buffer , int Size)
{
    unsigned short ip_hdr_length;
    
    struct iphdr *iph = (struct iphdr *)( Buffer  + sizeof(struct ethhdr) );
    ip_hdr_length = iph->ihl*4;
     
    struct udphdr *udph=(struct udphdr*)(Buffer + ip_hdr_length + sizeof(struct ethhdr));
             
    struct DNS_HEADER* dns = (struct DNS_HEADER*)(Buffer + sizeof udph + ip_hdr_length + sizeof(struct ethhdr));


    struct RESOURCE_RECORD ans_arr[20],auth_arr[20],addit[20];
    struct sockaddr_in a;
    unsigned char *temp_buff, *qname;
    Buffer+=sizeof udph + ip_hdr_length + sizeof(struct ethhdr);
    qname =(unsigned char*)&Buffer[sizeof(struct DNS_HEADER)];
    sprintf(curr, "DNS Header\n");
    sprintf(app[total_packet_count],"%s",curr); 
    temp_buff = (Buffer+sizeof(struct DNS_HEADER) + (strlen((const char*)qname)+1) + sizeof(struct DNS_QUESTION));
    sprintf(curr, "\nThe response consists of : ");
    strcat(app[total_packet_count],curr);
    sprintf(curr, "\n %d Questions",ntohs(dns->DNS_QUESTION_count));
    strcat(app[total_packet_count],curr);
    sprintf(curr, "\n %d Answers",ntohs(dns->answer_count));
    strcat(app[total_packet_count],curr);
    sprintf(curr, "\n %d Authoritative Servers.",ntohs(dns->auth_rec_count));
    strcat(app[total_packet_count],curr);
    sprintf(curr, "\n %d Additional records\n\n",ntohs(dns->additional_rec_count));
    strcat(app[total_packet_count],curr);
    int stop_flag=0;
 
    for(i=0;i<ntohs(dns->answer_count);i++)
    {
        ans_arr[i].name=DNS_Decodee_Helper(temp_buff,Buffer,&stop_flag);
        temp_buff = temp_buff + stop_flag;
 
        ans_arr[i].resource = (struct RECORD_DATA*)(temp_buff);
        temp_buff = temp_buff + sizeof(struct RECORD_DATA);
 
        if(ntohs(ans_arr[i].resource->type) == 1) //if its an ipv4 address
        {
            ans_arr[i].record_data = (unsigned char*)malloc(ntohs(ans_arr[i].resource->data_len));
 
            for(j=0 ; j<ntohs(ans_arr[i].resource->data_len) ; j++)
            {
                ans_arr[i].record_data[j]=temp_buff[j];
            }
 
            ans_arr[i].record_data[ntohs(ans_arr[i].resource->data_len)] = '\0';
 
            temp_buff = temp_buff + ntohs(ans_arr[i].resource->data_len);
        }
        else
        {
            ans_arr[i].record_data = DNS_Decodee_Helper(temp_buff,Buffer,&stop_flag);
            temp_buff = temp_buff + stop_flag;
        }
    }
 
    for(i=0;i<ntohs(dns->auth_rec_count);i++)
    {
        auth_arr[i].name=DNS_Decodee_Helper(temp_buff,Buffer,&stop_flag);
        temp_buff+=stop_flag;
 
        auth_arr[i].resource=(struct RECORD_DATA*)(temp_buff);
        temp_buff+=sizeof(struct RECORD_DATA);
 
        auth_arr[i].record_data=DNS_Decodee_Helper(temp_buff,Buffer,&stop_flag);
        temp_buff+=stop_flag;
    }
 
    for(i=0;i<ntohs(dns->additional_rec_count);i++)
    {
        addit[i].name=DNS_Decodee_Helper(temp_buff,Buffer,&stop_flag);
        temp_buff+=stop_flag;
 
        addit[i].resource=(struct RECORD_DATA*)(temp_buff);
        temp_buff+=sizeof(struct RECORD_DATA);
 
        if(ntohs(addit[i].resource->type)==1)
        {
            addit[i].record_data = (unsigned char*)malloc(ntohs(addit[i].resource->data_len));
            for(j=0;j<ntohs(addit[i].resource->data_len);j++)
            addit[i].record_data[j]=temp_buff[j];
 
            addit[i].record_data[ntohs(addit[i].resource->data_len)]='\0';
            temp_buff+=ntohs(addit[i].resource->data_len);
        }
        else
        {
            addit[i].record_data=DNS_Decodee_Helper(temp_buff,Buffer,&stop_flag);
            temp_buff+=stop_flag;
        }
    }
 
    sprintf(curr, "\nAnswer Records : %d \n" , ntohs(dns->answer_count) );
    strcat(app[total_packet_count],curr);
    for(i=0 ; i < ntohs(dns->answer_count) ; i++)
    {
        sprintf(curr, "Name : %s ",ans_arr[i].name);
        strcat(app[total_packet_count],curr);

        if( ntohs(ans_arr[i].resource->type) == 1) //IPv4 address
        {
            long *p;
            p=(long*)ans_arr[i].record_data;
            a.sin_addr.s_addr=(*p); //working without ntohl
            sprintf(curr, "has IPv4 address : %s",inet_ntoa(a.sin_addr));
            strcat(app[total_packet_count],curr);
        }
         
        if(ntohs(ans_arr[i].resource->type)==5) 
        {
            //Canonical name for an alias
            sprintf(curr, "has alias name : %s",ans_arr[i].record_data);
            strcat(app[total_packet_count],curr);
        }
 
        sprintf(curr, "\n");
        strcat(app[total_packet_count],curr);
    }
 
    sprintf(curr, "\nAuthoritive Records : %d \n" , ntohs(dns->auth_rec_count) );
    strcat(app[total_packet_count],curr);
    for( i=0 ; i < ntohs(dns->auth_rec_count) ; i++)
    {
         
        sprintf(curr, "Name : %s ",auth_arr[i].name);
        strcat(app[total_packet_count],curr);
        if(ntohs(auth_arr[i].resource->type)==2)
        {
            sprintf(curr, "has nameserver : %s",auth_arr[i].record_data);
            strcat(app[total_packet_count],curr);
        }
        sprintf(curr, "\n");
        strcat(app[total_packet_count],curr);
    }
 
    sprintf(curr, "\nAdditional Records : %d \n" , ntohs(dns->additional_rec_count) );
    strcat(app[total_packet_count],curr);
    for(i=0; i < ntohs(dns->additional_rec_count) ; i++)
    {
        sprintf(curr, "Name : %s ",addit[i].name);
        strcat(app[total_packet_count],curr);
        if(ntohs(addit[i].resource->type)==1)
        {
            long *p;
            p=(long*)addit[i].record_data;
            a.sin_addr.s_addr=(*p);
            sprintf(curr, "has IPv4 address : %s",inet_ntoa(a.sin_addr));
            strcat(app[total_packet_count],curr);
        }
        // sprintf(curr, "\n");
    }
    // printf("%s\n",app[total_packet_count] );
        // sprintf(buff_app,"%s",app[total_packet_count]);
    sprintf(name_button[total_packet_count],"%s","DNS" );
}
 
void Print_Data_Dump (unsigned char* data , int Size)
{
    int i , j;
    for(i=0 ; i < Size ; i++)
    {
        if( i!=0 && i%16==0)   
        {
            sprintf(curr, "         ");
            strcat(payload[total_packet_count],curr);
            for(j=i-16 ; j<i ; j++)
            {
                if(data[j]>=32 && data[j]<=128){
                    sprintf(curr, "%c",(unsigned char)data[j]); 
                    strcat(payload[total_packet_count],curr);
                }
                 
                else {
                    sprintf(curr, "."); 
                    strcat(payload[total_packet_count],curr);
                }
                
            }
            sprintf(curr, "\n");
            strcat(payload[total_packet_count],curr);
        } 
         
        if(i%16==0) sprintf(curr, "   ");
            sprintf(curr, " %02X",(unsigned int)data[i]);
            strcat(payload[total_packet_count],curr);
                 
        if( i==Size-1)  
        {
            for(j=0;j<15-i%16;j++) 
            {
              sprintf(curr, "   "); 
              strcat(payload[total_packet_count],curr);
            }
             
            sprintf(curr, "         ");
            strcat(payload[total_packet_count],curr);
             
            for(j=i-i%16 ; j<=i ; j++)
            {
                if(data[j]>=32 && data[j]<=128) 
                {
                  sprintf(curr, "%c",(unsigned char)data[j]);
                  strcat(payload[total_packet_count],curr);
                }
                else
                {
                  sprintf(curr, ".");
                  strcat(payload[total_packet_count],curr);
                }
            }
             
            sprintf(curr,  "\n" );
            strcat(payload[total_packet_count],curr);
        }
    }
    
}


void initiateCapture()
{
    int saddr_size , data_size;
    struct sockaddr saddr;
         
    unsigned char *buffer = (unsigned char *) malloc(65536); //Its Big!

    printf("Starting...\n");
     
    int sock_raw = socket( AF_PACKET , SOCK_RAW , htons(ETH_P_ALL)) ;
     
    if(sock_raw < 0)
    {
        perror("Socket Error");
        return ;
    }
    while(1)
    {
        saddr_size = sizeof saddr;
        data_size = recvfrom(sock_raw , buffer , 65536 , 0 , &saddr , (socklen_t*)&saddr_size);
        if(data_size <0 )
        {
            printf("Recvfrom error , failed to get packets\n");
            return ;
        }
        Packet_Processor(buffer , data_size);
        if(total_packet_count==1000){
            icmp_packet_count=0,total_packet_count=0, arp_packet_count=0,http_packet_count=0,dns_packet_count=0;
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
    char str[50];
    if (tcp_packet_count>udp_packet_count){
        printf("%d\n",tcp_packet_count );
        sprintf(str,"%s","TCP Stream");
        gtk_text_buffer_set_text(stream,str,strlen(str));
    }
    else{
        printf("%d\n",udp_packet_count );
        sprintf(str,"%s","UDP Stream");
        gtk_text_buffer_set_text(stream,str,strlen(str));
    }
    tcp_packet_count=0,udp_packet_count=0;
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

