
#ifndef _pcat
#define _pcat


void Packet_Processor(unsigned char* , int);
void Ethernet_Header_Decoder(unsigned char*, int);
void ARP_Packet_Decoder(unsigned char * , int );
void IP_Header_Decoder(unsigned char* , int);
void ICMP_Packet_Decoder(unsigned char* , int );
void TCP_Packet_Decoder(unsigned char * , int );
void UDP_Packet_Decoder(unsigned char * , int );
void HTTP_Packet_Header(unsigned char * , int );
void DNS_Packet_Decoder(unsigned char* , int );
void Print_Data_Dump (unsigned char* , int);
void initiateCapture();

#endif