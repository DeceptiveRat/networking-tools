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

#define ETHERNET_PACKET 0
#define TCP_PACKET 20
#define UDP_PACKET 40
#define DNS_QUERY_PACKET 41
#define DNS_RESPONSE_PACKET 42

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
	char packet_type;
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
