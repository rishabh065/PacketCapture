#ifndef _pcat
#define _pcat


void print_ip_header(unsigned char* , int);
void print_tcp_packet(unsigned char * , int );
void print_udp_packet(unsigned char * , int );
void print_icmp_packet(unsigned char* , int );
void print_arp_packet(unsigned char* , int );
void PrintData (unsigned char* , int);
void ProcessPacket(unsigned char* , int);
void initiateCapture();

#endif