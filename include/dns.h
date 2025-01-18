#pragma once

#include <stdio.h>
#include <sys/socket.h>
#include <stdlib.h>
#include <stdbool.h>

#define DNS_COMPRESSION_PTR 0xC0

#define DNS_HDR_LEN 12
struct dns_hdr
{
	unsigned short dns_id;
	unsigned short dns_flags;
#define DNS_QR 0x8000
#define DNS_OPCODE 0x7800
#define DNS_AA 0x400
#define DNS_TC 0x200
#define DNS_RD 0x100
#define DNS_RA 0x80
#define DNS_ZERO 0x70
#define DNS_RCODE 0xF 

	unsigned short dns_question_count;
	unsigned short dns_answer_count;
	unsigned short dns_authority_count;
	unsigned short dns_additional_count;
};

// cast end of domain name
struct dns_query_section
{
	char* dns_domain_name;

	unsigned short dns_type;
#define DNS_RECORD_A 1
#define DNS_RECORD_NS 2
#define DNS_RECORD_CNAME 5
#define DNS_RECORD_MX 15
#define DNS_RECORD_PTR 12
#define DNS_RECORD_HINFO 13

	unsigned short dns_class;
#define DNS_CLASS_IN 1
};

struct dns_response_section
{
	char* dns_domain_name;

	unsigned short dns_type;
	unsigned short dns_class;
	unsigned int dns_TTL;
	unsigned short dns_data_length;
	unsigned char* dns_resource_data;
	bool is_opt_record; 
};

struct dns_opt_record
{
	// TODO: change to 8 bytes for x86_64, 4 bytes for x86
	int dns_opt_name;
	int padding;

	unsigned short dns_type;
	unsigned short dns_udp_payload_size;
	unsigned char dns_rcode;
	unsigned char dns_flags[3];
	unsigned short dns_data_length;
	unsigned char* dns_option_data;
	bool is_opt_record; 
};

struct dns_query
{
	struct dns_hdr dns_header;
	struct dns_query_section *dns_queries_list;
	struct dns_response_section *dns_additional_list;
};

struct dns_response 
{
	struct dns_hdr dns_header;
	struct dns_query_section* dns_queries_list;
	struct dns_response_section *dns_answer_list;
	struct dns_response_section *dns_authoritative_list;
	struct dns_response_section *dns_additional_list;
};

// functions
bool get_dns_query(const unsigned char *udp_payload_start, struct dns_query** dns_query_pointer);
bool get_dns_response(const unsigned char *udp_payload_start, struct dns_response* dns_response_pointer);
/*
 * return domain name as string
 * change query offset so it points to the correct place
 * returns NULL if domain name format is wrong
 */
char* get_domain_name(const unsigned char* query_start_pointer, int *query_offset);
void print_dns_query(struct dns_query* dns_query_packet, FILE* outputFilePtr);

// debugging functions
void debug_dns_packet(unsigned char *user_args, const unsigned char *packet, const int packet_length);
