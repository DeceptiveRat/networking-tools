/*
 * This file is part of networking-tools.
 *
 * networking-tools is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * networking-tools is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with networking-tools.  If not, see <https://www.gnu.org/licenses/>.
 */

#pragma once

#include <sys/types.h>
#include <netinet/in.h>
#include <pcap.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>

#include "ethernet.h"
#include "ip.h"
#include "otherFunctions.h"
#include "tcp.h"
#include "udp.h"

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
	char *dns_domain_name;

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
	char *dns_domain_name;

	unsigned short dns_type;
	unsigned short dns_class;
	unsigned int dns_TTL;
	unsigned short dns_data_length;
	unsigned char *dns_resource_data;
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
	unsigned char *dns_option_data;
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
	struct dns_query_section *dns_queries_list;
	struct dns_response_section *dns_answer_list;
	struct dns_response_section *dns_authoritative_list;
	struct dns_response_section *dns_additional_list;
};

// functions
int getDnsQuery(const unsigned char *payload_start, struct dns_query **query_location_pp);
int getDnsResponse(const unsigned char *payload_start, struct dns_response **response_location_pp);
int fillQuerySection(const unsigned char *query_start, int *data_offset, int query_count,
					 struct dns_query_section **query_section_location_pp,
					 struct allocated_pointers *pointers_head);
int fillAdditionalSection(const unsigned char *additional_start, int *data_offset,
						  int additional_count,
						  struct dns_response_section **additional_section_location_pp,
						  struct allocated_pointers *pointers_head);
int parseOptRecord(const unsigned char *additional_start, int *data_offset,
				   struct dns_response_section *opt_record_destination,
				   struct allocated_pointers *pointers_head);
int parseNormalRecord(const unsigned char *additional_start, int *data_offset,
					  struct dns_response_section *normal_record_destination,
					  struct allocated_pointers *pointers_head);
int getDomainName(const unsigned char *query_start_pointer, int *query_offset,
				  char **name_destination);
void printDnsQuery(struct dns_query *dns_query_packet, FILE *output_file_ptr);
int freeDnsQuery(struct dns_query *dns_query_packet);
