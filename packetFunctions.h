#pragma once

#include <stdio.h>
#include <sys/socket.h>
#include <stdlib.h>
#include <stdbool.h>

#include "ethernet.h"
#include "ip.h"
#include "tcp.h"
#include "udp.h"
#include "dns.h"

#define LINK_LAYER_TYPE 0xff000000
#define ETHERNET_TYPE 0x01000000
#define NETWORK_LAYER_TYPE 0xff0000
#define IP_TYPE 0x010000
#define TRANSPORT_LAYER_TYPE 0xff00
#define TCP_TYPE 0x0100 
#define UDP_TYPE 0x0200
#define APPLICATION_LAYER_TYPE 0xff
#define DNS_QUERY_TYPE 0x01 
#define DNS_RESPONSE_TYPE 0x02
#define HTTP_TYPE 0x04

// =================================== structures =============================================
struct pcap_handler_arguments
{
	FILE* outputFilePtr;
	struct ethernet_packet* packet_list_head;
	struct ethernet_packet* packet_list_tail;
	int captured_count;
};

struct ethernet_packet
{
	int packet_type;
	struct ether_hdr* ethernet_header;
	void* network_layer_structure;
	void* transport_layer_structure;
	void* application_layer_structure;
	unsigned char* remaining_bytes;
	int remaining_length;
	struct ethernet_packet* next_packet;
};

struct tcp_packet
{
	char packet_type;
	struct ether_hdr* ethernet_header;
	struct ip_hdr* ip_header;
	struct tcp_hdr* tcp_header;
	void* application_layer_structure;
	unsigned char* remaining_bytes;
	int remaining_length;
	struct ethernet_packet* next_packet;
};

struct udp_packet
{
	char packet_type;
	struct ether_hdr* ethernet_header;
	struct ip_hdr* ip_header;
	struct udp_hdr* udp_header;
	void* application_layer_structure;
	unsigned char* remaining_bytes;
	int remaining_length;
	struct ethernet_packet* next_packet;
};

struct dns_query_packet
{
	char packet_type;
	struct ether_hdr* ethernet_header;
	struct ip_hdr* ip_header;
	struct udp_hdr* udp_header;
	struct dns_query* dns_query_payload;
	struct ethernet_packet* next_packet;
};

struct dns_response_packet
{
	char packet_type;
	struct ether_hdr* ethernet_header;
	struct ip_hdr* ip_header;
	struct udp_hdr* udp_header;
	struct dns_response* dns_response_payload;
	struct ethernet_packet* next_packet;
};

// pcap handler functions
void analyze_caught_packet(unsigned char *user_args, const struct pcap_pkthdr *cap_header, const unsigned char *packet);
void save_remaining_bytes(const int length, struct ethernet_packet* saved_packet, const unsigned char* remaining_bytes);
void print_packet(const struct ethernet_packet* packet, FILE* outputFilePtr);

// debugging functions
