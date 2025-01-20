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

#include <string.h>
#include <pcap.h>

#include "otherFunctions.h"
#include "ethernet.h"
#include "ip.h"
#include "tcp.h"
#include "udp.h"
#include "dns.h"

bool get_dns_query(const unsigned char *header_start, struct dns_query** dns_query_pointer)
{
	struct allocated_pointers* head = NULL;
	head = (struct allocated_pointers*)malloc(sizeof(struct allocated_pointers));

	if(head == NULL)
		fatal("allocating memory for clean up head", "get_dns_query", NULL);

	head->next_pointer = NULL;

	*dns_query_pointer = (struct dns_query*)malloc(sizeof(struct dns_query));

	if(dns_query_pointer == NULL)
		return false;

	else
		add_new_pointer(head, NULL, dns_query_pointer);

	(*dns_query_pointer)->dns_queries_list = NULL;
	(*dns_query_pointer)->dns_additional_list = NULL;

	// add header
	struct dns_hdr query_header;

	query_header = *(struct dns_hdr*)header_start;

	// convert network byte order to host byte order
	query_header.dns_id = ntohs(query_header.dns_id);
	query_header.dns_flags = ntohs(query_header.dns_flags);
	query_header.dns_question_count = ntohs(query_header.dns_question_count);
	query_header.dns_answer_count = ntohs(query_header.dns_answer_count);
	query_header.dns_authority_count = ntohs(query_header.dns_authority_count);
	query_header.dns_additional_count = ntohs(query_header.dns_additional_count);

	if((query_header.dns_flags & DNS_QR) != 0)
		return false;

	if((query_header.dns_flags & DNS_ZERO) != 0)
		return false;

	if(query_header.dns_answer_count != 0)
		return false;

	if(query_header.dns_authority_count != 0)
		return false;

	(*dns_query_pointer)->dns_header = query_header;

	const unsigned char* query_start = header_start + DNS_HDR_LEN;
	unsigned char byte;
	unsigned short word;
	int query_offset = 0;
	int query_count = query_header.dns_question_count;

	// initialize query variables
	struct dns_query_section* queries = NULL;
	queries = (struct dns_query_section*)malloc(sizeof(struct dns_query_section) * query_count);

	if(queries == NULL)
		fatal("allocating memory for dns queries", "get_dns_query", NULL);

	else
		add_new_pointer(head, NULL, queries);

	char **domain_names = NULL;
	domain_names = (char**)malloc(sizeof(char*)*query_count);

	if(domain_names == NULL)
		fatal("allocating memory for domain names", "get_dns_query", NULL);

	else
	{
		add_new_pointer(head, NULL, domain_names);

		for(int i = 0; i < query_count; i++)
			domain_names[i] = NULL;
	}

	// fill query information
	for(int j = 0; j < query_count; j++)
	{
		domain_names[j] = get_domain_name(query_start, &query_offset);

		if(domain_names[j] == NULL)
		{
			free_all_pointers(head);
			return false;
		}

		else
			add_new_pointer(head, NULL, domain_names[j]);

		// get other information
		word = *(unsigned short*)(query_start + query_offset);
		queries[j].dns_type = ntohs(word);
		query_offset += 2;
		word = *(unsigned short*)(query_start + query_offset);
		queries[j].dns_class = ntohs(word);
		query_offset += 2;
		queries[j].dns_domain_name = domain_names[j];
	}

	(*dns_query_pointer)->dns_queries_list = queries;

	// prevent accidental use
	queries = NULL;

	for(int k = 0; k < query_count; k++)
		domain_names[k] = NULL;

	domain_names = NULL;

	int additional_count = query_header.dns_additional_count;

	if(additional_count == 0)
		return true;

	// initialize response variables
	struct dns_response_section* additional_records = NULL;
	additional_records = (struct dns_response_section*)malloc(sizeof(struct dns_response_section) * additional_count);

	if(additional_records == NULL)
		fatal("allocating memory for additional records", "get_dns_query", NULL);

	else
		add_new_pointer(head, NULL, additional_records);

	char** domain_names_additional = NULL;
	domain_names_additional = (char**)malloc(sizeof(char*)*additional_count);

	if(domain_names_additional == NULL)
		fatal("allocating memory for additional record domain names", "get_dns_query", NULL);

	else
	{
		add_new_pointer(head, NULL, domain_names_additional);

		for(int i = 0; i < additional_count; i++)
			domain_names_additional[i] = NULL;
	}

	// add additional section
	for(int additional_record_index = 0; additional_record_index < additional_count; additional_record_index++)
	{
		byte = *(query_start + query_offset);
		query_offset++;

		// OPT record
		if(byte == 0x00)
		{
			struct dns_opt_record opt_record;
			opt_record.dns_opt_name = 0;
			opt_record.padding = 0;
			opt_record.dns_type = ntohs(*(unsigned short*)(query_start + query_offset));
			query_offset += 2;

			if(opt_record.dns_type != 41)
			{
				free_all_pointers(head);
				return false;
			}

			opt_record.dns_udp_payload_size = ntohs(*(unsigned short*)(query_start + query_offset));
			query_offset += 2;
			opt_record.dns_rcode = *(unsigned char*)(query_start + query_offset);
			query_offset += 1;
			opt_record.dns_flags[0] = *(unsigned char*)(query_start + query_offset);
			query_offset += 1;
			opt_record.dns_flags[1] = *(unsigned char*)(query_start + query_offset);
			query_offset += 1;
			opt_record.dns_flags[2] = *(unsigned char*)(query_start + query_offset);
			query_offset += 1;
			short dataLength = ntohs(*(unsigned short*)(query_start + query_offset));
			query_offset += 2;
			opt_record.dns_data_length = dataLength;

			if(dataLength != 0)
			{
				unsigned char* resource_data = (unsigned char*)malloc(sizeof(unsigned char) * dataLength);

				if(resource_data == NULL)
					fatal("allocating memory for resource data", "get_dns_query", NULL);

				else
					add_new_pointer(head, NULL, resource_data);

				memcpy(resource_data, query_start + query_offset, dataLength);
				query_offset += dataLength;
				opt_record.dns_option_data = resource_data;
			}

			else
				opt_record.dns_option_data = NULL;

			opt_record.is_opt_record = true;

			additional_records[additional_record_index] = *(struct dns_response_section*)&opt_record;
		}

		// normal record
		else
		{
			// what was just read is part of the name
			query_offset--;

			domain_names_additional[additional_record_index] = get_domain_name(query_start, &query_offset);

			if(domain_names_additional[additional_record_index] == NULL)
			{
				free_all_pointers(head);
				return false;
			}

			else
				add_new_pointer(head, NULL, domain_names_additional[additional_record_index]);

			additional_records[additional_record_index].dns_domain_name = domain_names_additional[additional_record_index];
			additional_records[additional_record_index].dns_type = ntohs(*(unsigned short*)(query_start + query_offset));
			query_offset += 2;
			additional_records[additional_record_index].dns_class = ntohs(*(unsigned short*)(query_start + query_offset));
			query_offset += 2;
			additional_records[additional_record_index].dns_TTL = ntohl(*(unsigned int*)(query_start + query_offset));
			query_offset += 4;
			short dataLength = ntohs(*(unsigned short*)(query_start + query_offset));
			query_offset += 2;
			additional_records[additional_record_index].dns_data_length = dataLength;

			if(dataLength != 0)
			{
				unsigned char* resource_data = (unsigned char*)malloc(sizeof(unsigned char) * dataLength);

				if(resource_data == NULL)
					fatal("allocating memory for resource data", "get_dns_query", NULL);

				else
					add_new_pointer(head, NULL, resource_data);

				memcpy(resource_data, query_start + query_offset, dataLength);
				query_offset += dataLength;
				additional_records[additional_record_index].dns_resource_data = resource_data;
			}

			else
				additional_records[additional_record_index].dns_resource_data = NULL;

			additional_records[additional_record_index].is_opt_record = false;
		}
	}

	(*dns_query_pointer)->dns_additional_list = additional_records;
	return true;
}

bool get_dns_response(const unsigned char *header_start, struct dns_response* dns_response_pointer)
{
	return false;
}

char* get_domain_name(const unsigned char* query_start_pointer, int *query_offset)
{
	char name[256];
	int domain_name_length = 0;
	unsigned char byte;
	byte = *(query_start_pointer + *query_offset);
	(*query_offset)++;

	while(byte != 0x00)
	{
		// check for compression pointer
		if((byte & DNS_COMPRESSION_PTR) == DNS_COMPRESSION_PTR)
		{
			unsigned short offset = *(query_start_pointer + *query_offset - 1);
			(*query_offset)++;
			// use offset to get the rest of the name
			offset -= DNS_COMPRESSION_PTR;
			int temp_offset = offset;
			char* temp = get_domain_name(query_start_pointer, &temp_offset);

			if(domain_name_length + temp_offset - offset > 256)
				return NULL;

			strncpy(&name[domain_name_length], temp, temp_offset - offset);
			domain_name_length += temp_offset - offset;
			free(temp);

			char* name_pointer = (char*)malloc(sizeof(char) * domain_name_length);

			if(name_pointer == NULL)
				fatal("allocating memory for domain_names", "get_domain_name", NULL);

			strncpy((char*)name_pointer, name, domain_name_length);
			return name_pointer;
		}

		for(int label_bytes_left = 0; label_bytes_left < byte; label_bytes_left++)
		{
			if(domain_name_length > 255)
				return NULL;

			name[domain_name_length] = *(query_start_pointer + *query_offset);
			(*query_offset)++;
			domain_name_length++;
		}

		if(domain_name_length > 255)
			return NULL;

		name[domain_name_length] = '.';
		domain_name_length++;
		byte = *(query_start_pointer + *query_offset);
		(*query_offset)++;
	}

	name[domain_name_length - 1] = '\0';

	char* name_pointer = (char*)malloc(sizeof(char) * domain_name_length);

	if(name_pointer == NULL)
		fatal("allocating memory for domain_names", "get_domain_name", NULL);

	strncpy(name_pointer, name, domain_name_length);
	return name_pointer;
}

void print_dns_query(struct dns_query* dns_query_packet, FILE* outputFilePtr)
{
	// print header
	struct dns_hdr dns_header = dns_query_packet->dns_header;
	fprintf(outputFilePtr, "\t\t\t[[  DNS Header  ]]\n");
	fprintf(outputFilePtr, "\t\t\t[  ID: %hu(%x)  ]\n", dns_header.dns_id, dns_header.dns_id);
	fprintf(outputFilePtr, "\t\t\t[  Flags(%x):  ]\n", ntohs(dns_header.dns_flags));
	fprintf(outputFilePtr, "\t\t\t[  \t QR: %hu  \t]\n", (dns_header.dns_flags & DNS_QR)>>15);
	fprintf(outputFilePtr, "\t\t\t[  \t opcode: %d  ]\n", (dns_header.dns_flags & DNS_OPCODE)>>11);
	fprintf(outputFilePtr, "\t\t\t[  \t AA: %hu  ]\n", (dns_header.dns_flags & DNS_AA)>>10);
	fprintf(outputFilePtr, "\t\t\t[  \t TC: %hu  ]\n", (dns_header.dns_flags & DNS_TC)>>9);
	fprintf(outputFilePtr, "\t\t\t[  \t RD: %hu  ]\n", (dns_header.dns_flags & DNS_RD)>>8);
	fprintf(outputFilePtr, "\t\t\t[  \t RA: %hu  ]\n", (dns_header.dns_flags & DNS_RA)>>7);
	fprintf(outputFilePtr, "\t\t\t[  \t rcode: %hu  ]\n", dns_header.dns_flags & DNS_RCODE);
	fprintf(outputFilePtr, "\t\t\t[  Question #: %hu  ]\n", dns_header.dns_question_count);
	fprintf(outputFilePtr, "\t\t\t[  Answer #: %hu  ]\n", dns_header.dns_answer_count);
	fprintf(outputFilePtr, "\t\t\t[  Authority #: %hu  ]\n", dns_header.dns_authority_count);
	fprintf(outputFilePtr, "\t\t\t[  Additional #: %hu  ]\n", dns_header.dns_additional_count);

	// print queries
	struct dns_query_section query;
	fprintf(outputFilePtr, "\t\t\t[[  DNS Query Section  ]]\n");
	for(int i = 0;i<dns_header.dns_question_count;i++)
	{
		query = dns_query_packet->dns_queries_list[i];
		fprintf(outputFilePtr, "\t\t\t\t[[  DNS Query #%d  ]]\n", i + 1);
		fprintf(outputFilePtr, "\t\t\t\t[  Domain Name: %s  ]\n", query.dns_domain_name);
		fprintf(outputFilePtr, "\t\t\t\t[  Type: %hu(%x) (", query.dns_type, query.dns_type);
		if(query.dns_type == DNS_RECORD_A)
			fprintf(outputFilePtr, "Record A");
		else if(query.dns_type == DNS_RECORD_NS)
			fprintf(outputFilePtr, "Record NS");
		else if(query.dns_type == DNS_RECORD_CNAME)
			fprintf(outputFilePtr, "Record CNAME");
		else if(query.dns_type == DNS_RECORD_MX)
			fprintf(outputFilePtr, "Record MX");
		else if(query.dns_type == DNS_RECORD_PTR)
			fprintf(outputFilePtr, "Record PTR");
		else if(query.dns_type == DNS_RECORD_HINFO)
			fprintf(outputFilePtr, "Record HINFO");
		fprintf(outputFilePtr, ")  ]\n");
		fprintf(outputFilePtr, "\t\t\t\t[  Class: %hu(%x) (", query.dns_class, query.dns_class);
		if(query.dns_class == DNS_CLASS_IN)
			fprintf(outputFilePtr, "IN");
		fprintf(outputFilePtr, ")  ]\n");
	}

	// print additionals
	struct dns_response_section response;
	fprintf(outputFilePtr, "\t\t\t[[  DNS Additional Section  ]]\n");
	for(int i = 0;i<dns_header.dns_additional_count;i++)
	{
		response = dns_query_packet->dns_additional_list[i];
		if(response.is_opt_record)
		{
			fprintf(outputFilePtr, "\t\t\t\t[[  DNS Additional #%d (opt record)  ]]\n", i + 1);
			fprintf(outputFilePtr, "\t\t\t\t[  Domain Name: %d(root)  ]\n", ((struct dns_opt_record*)&response)->dns_opt_name);
			fprintf(outputFilePtr, "\t\t\t\t[  Type: %hu(%x)  ]\n", response.dns_type, response.dns_type);
			fprintf(outputFilePtr, "\t\t\t\t[  UDP payload size: %hu  ]\n", ((struct dns_opt_record*)&response)->dns_udp_payload_size);
			fprintf(outputFilePtr, "\t\t\t\t[  rcode: %x  ]\n", ((struct dns_opt_record*)&response)->dns_rcode);
			fprintf(outputFilePtr, "\t\t\t\t[  Flags: %x  ]\n", ntohl(*((int*)((struct dns_opt_record*)&response)->dns_flags)>>8));
			fprintf(outputFilePtr, "\t\t\t\t[  Data Length: %hu  ]\n", ((struct dns_opt_record*)&response)->dns_data_length);
			fprintf(outputFilePtr, "\t\t\t\t[  Option Data:  ]\n");
			pretty_dump(((struct dns_opt_record*)&response)->dns_option_data, ((struct dns_opt_record*)&response)->dns_data_length, outputFilePtr, "\t\t\t\t[  ", "  ]");
		}
		else
		{
			fprintf(outputFilePtr, "\t\t\t\t[[  DNS Additional #%d  ]]\n", i + 1);
			fprintf(outputFilePtr, "\t\t\t\t[  Domain Name: %s  ]\n", response.dns_domain_name);
			fprintf(outputFilePtr, "\t\t\t\t[  Type: %hu(%x) (  ]\n", response.dns_type, response.dns_type);
			// print response dns types
			fprintf(outputFilePtr, ")  ]\n");
			fprintf(outputFilePtr, "\t\t\t\t[  Class: %hu(%x) (  ]\n", response.dns_type, response.dns_type);
			// print response dns classes
			fprintf(outputFilePtr, ")  ]\n");
			fprintf(outputFilePtr, "\t\t\t\t[  TTL: %d  ]\n", response.dns_TTL);
			fprintf(outputFilePtr, "\t\t\t\t[  Data Length: %hu  ]\n", response.dns_data_length);
			fprintf(outputFilePtr, "\t\t\t\t[  Resource Data:  ]\n");
			pretty_dump(response.dns_resource_data, response.dns_data_length, outputFilePtr, "\t\t\t\t[  ", "  ]");
		}
	}
}
