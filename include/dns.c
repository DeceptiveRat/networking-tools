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

#include "dns.h"

int getDnsQuery(const unsigned char *payload_start, struct dns_query **query_location_pp)
{
	const char function_name[] = "getDnsQuery";
	int status;
	// create pointer structure
	struct allocated_pointers *pointers_head = NULL;
	pointers_head = (struct allocated_pointers *)malloc(sizeof(struct allocated_pointers));
	if(pointers_head == NULL)
	{
		perror(function_name);
		strcpy(error_message, "allocating memory");
		fatal(error_message, NULL, stdout);
	}
	pointers_head->next_pointer = NULL;

	// allocate space for query
	*query_location_pp = (struct dns_query *)malloc(sizeof(struct dns_query));
	if(*query_location_pp == NULL)
	{
		free_all_pointers(pointers_head);
		perror(function_name);
		strcpy(error_message, "allocating memory");
		fatal(error_message, NULL, stdout);
	}
	else
		add_new_pointer(pointers_head, NULL, *query_location_pp);

	(*query_location_pp)->dns_queries_list = NULL;
	(*query_location_pp)->dns_additional_list = NULL;

	// get header
	struct dns_hdr query_header;
	query_header = *(struct dns_hdr *)payload_start;
	query_header.dns_id = ntohs(query_header.dns_id);
	query_header.dns_flags = ntohs(query_header.dns_flags);
	query_header.dns_question_count = ntohs(query_header.dns_question_count);
	query_header.dns_answer_count = ntohs(query_header.dns_answer_count);
	query_header.dns_authority_count = ntohs(query_header.dns_authority_count);
	query_header.dns_additional_count = ntohs(query_header.dns_additional_count);
	if((query_header.dns_flags & DNS_QR) != 0 || (query_header.dns_flags & DNS_ZERO) != 0 || query_header.dns_answer_count != 0 || query_header.dns_authority_count != 0)
	{
		free_all_pointers(pointers_head);
		return 0;
	}
	(*query_location_pp)->dns_header = query_header;

	// get queries
	const unsigned char *query_start = payload_start + DNS_HDR_LEN;
	int data_offset = 0;
	int query_count = query_header.dns_question_count;
	status = fillQuerySection(query_start, &data_offset, query_count,
							  &((*query_location_pp)->dns_queries_list), pointers_head);
	if(status != 0)
	{
		free_all_pointers(pointers_head);
		return 0;
	}

	int additional_count = query_header.dns_additional_count;
	if(additional_count == 0)
	{
		remove_all_from_list(pointers_head);
		return true;
	}

	status = fillAdditionalSection(query_start + data_offset, &data_offset, additional_count,
								   &((*query_location_pp)->dns_additional_list), pointers_head);
	if(status != 0)
	{
		free_all_pointers(pointers_head);
		return -1;
	}

	remove_all_from_list(pointers_head);
	return true;
}

int fillQuerySection(const unsigned char *query_start, int *data_offset, int query_count,
					 struct dns_query_section **query_section_location_pp,
					 struct allocated_pointers *pointers_head)
{
	const char function_name[] = "fillQuerySection";
	// initialize query variables
	struct dns_query_section *queries = NULL;
	queries = (struct dns_query_section *)malloc(sizeof(struct dns_query_section) * query_count);
	if(queries == NULL)
	{
		perror(function_name);
		strcpy(error_message, "allocating memory");
		return -1;
	}

	else
		add_new_pointer(pointers_head, NULL, queries);

	char **domain_names = NULL;
	domain_names = (char **)malloc(sizeof(char *) * query_count);

	if(domain_names == NULL)
	{
		perror(function_name);
		strcpy(error_message, "allocating memory");
		return -1;
	}

	else
	{
		for(int i = 0; i < query_count; i++)
			domain_names[i] = NULL;
	}

	// fill query information
	for(int i = 0; i < query_count; i++)
	{
		int status = getDomainName(query_start, data_offset, &domain_names[i]);
		if(status == -1)
		{
			free(domain_names);
			perror(function_name);
			strcpy(error_message, "finding domain name");
			return -1;
		}
		else
			add_new_pointer(pointers_head, NULL, domain_names[i]);

		short word;
		// get other information
		word = *(unsigned short *)(query_start + *data_offset);
		queries[i].dns_type = ntohs(word);
		*data_offset += 2;
		word = *(unsigned short *)(query_start + *data_offset);
		queries[i].dns_class = ntohs(word);
		*data_offset += 2;
		queries[i].dns_domain_name = domain_names[i];
	}

	free(domain_names);
	*query_section_location_pp = queries;
	return 0;
}

int fillAdditionalSection(const unsigned char *additional_start, int *data_offset,
						  int additional_count,
						  struct dns_response_section **additional_section_location_pp,
						  struct allocated_pointers *pointers_head)
{
	const char function_name[] = "fillAdditionalSection";
	int status;

	struct dns_response_section *additional_records = NULL;
	additional_records = (struct dns_response_section *)malloc(sizeof(struct dns_response_section) *
															   additional_count);
	if(additional_records == NULL)
	{
		perror(function_name);
		strcpy(error_message, "allocating memory");
		return -1;
	}
	else
		add_new_pointer(pointers_head, NULL, additional_records);

	// add additional section
	for(int i = 0; i < additional_count; i++)
	{
		int byte = *(additional_start + *data_offset);
		*(data_offset)++;

		if(byte == 0x00)
		{
			status = parseOptRecord(additional_start, data_offset, additional_records + i,
									pointers_head);
			if(status != 0)
				return -1;
		}
		else
		{
			status = parseNormalRecord(additional_start, data_offset, additional_records + i,
									   pointers_head);
			if(status != 0)
				return -1;
		}
	}

	return 0;
}

bool get_dns_response(const unsigned char *header_start, struct dns_response *dns_response_pointer)
{
	return false;
}

int getDomainName(const unsigned char *query_start_pointer, int *query_offset,
				  char **name_destination)
{
	const char function_name[] = "getDomainName";
	int status;

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
			char *temp;
			status = getDomainName(query_start_pointer, &temp_offset, &temp);
			if(status != 0)
			{
				free(temp);
				return -1;
			}

			if(domain_name_length + temp_offset - offset > 256)
			{
				free(temp);
				perror(function_name);
				strcpy(error_message, "domain name too long");
				return -1;
			}

			strncpy(&name[domain_name_length], temp, temp_offset - offset);
			domain_name_length += temp_offset - offset;
			free(temp);

			char *name_pointer = (char *)malloc(sizeof(char) * domain_name_length);
			if(name_pointer == NULL)
			{
				perror(function_name);
				strcpy(error_message, "allocating memory");
				return -1;
			}

			strncpy(name_pointer, name, domain_name_length);
			*name_destination = name_pointer;
			return 0;
		}

		for(int i = 0; i < byte; i++)
		{
			if(domain_name_length > 255)
			{
				perror(function_name);
				strcpy(error_message, "domain name too long");
				return -1;
			}

			name[domain_name_length] = *(query_start_pointer + *query_offset);
			(*query_offset)++;
			domain_name_length++;
		}

		if(domain_name_length > 255)
		{
			perror(function_name);
			strcpy(error_message, "domain name too long");
			return -1;
		}

		name[domain_name_length] = '.';
		domain_name_length++;
		byte = *(query_start_pointer + *query_offset);
		(*query_offset)++;
	}

	name[domain_name_length - 1] = '\0';

	char *name_pointer = (char *)malloc(sizeof(char) * domain_name_length);
	if(name_pointer == NULL)
	{
		perror(function_name);
		strcpy(error_message, "allocating memory");
		return -1;
	}

	strncpy(name_pointer, name, domain_name_length);
	*name_destination = name_pointer;
	return 0;
}

void printDnsQuery(struct dns_query *dns_query_packet, FILE *output_file_ptr)
{
	// print header
	struct dns_hdr dns_header = dns_query_packet->dns_header;
	fprintf(output_file_ptr, "\t\t\t[[  DNS Header  ]]\n");
	fprintf(output_file_ptr, "\t\t\t[  ID: %hu(%x)  ]\n", dns_header.dns_id, dns_header.dns_id);
	fprintf(output_file_ptr, "\t\t\t[  Flags(%x):  ]\n", ntohs(dns_header.dns_flags));
	fprintf(output_file_ptr, "\t\t\t[  \t QR: %hu  \t]\n", (dns_header.dns_flags & DNS_QR) >> 15);
	fprintf(output_file_ptr, "\t\t\t[  \t opcode: %d  ]\n",
			(dns_header.dns_flags & DNS_OPCODE) >> 11);
	fprintf(output_file_ptr, "\t\t\t[  \t AA: %hu  ]\n", (dns_header.dns_flags & DNS_AA) >> 10);
	fprintf(output_file_ptr, "\t\t\t[  \t TC: %hu  ]\n", (dns_header.dns_flags & DNS_TC) >> 9);
	fprintf(output_file_ptr, "\t\t\t[  \t RD: %hu  ]\n", (dns_header.dns_flags & DNS_RD) >> 8);
	fprintf(output_file_ptr, "\t\t\t[  \t RA: %hu  ]\n", (dns_header.dns_flags & DNS_RA) >> 7);
	fprintf(output_file_ptr, "\t\t\t[  \t rcode: %hu  ]\n", dns_header.dns_flags & DNS_RCODE);
	fprintf(output_file_ptr, "\t\t\t[  Question #: %hu  ]\n", dns_header.dns_question_count);
	fprintf(output_file_ptr, "\t\t\t[  Answer #: %hu  ]\n", dns_header.dns_answer_count);
	fprintf(output_file_ptr, "\t\t\t[  Authority #: %hu  ]\n", dns_header.dns_authority_count);
	fprintf(output_file_ptr, "\t\t\t[  Additional #: %hu  ]\n", dns_header.dns_additional_count);

	// print queries
	struct dns_query_section query;
	fprintf(output_file_ptr, "\t\t\t[[  DNS Query Section  ]]\n");
	for(int i = 0; i < dns_header.dns_question_count; i++)
	{
		query = dns_query_packet->dns_queries_list[i];
		fprintf(output_file_ptr, "\t\t\t\t[[  DNS Query #%d  ]]\n", i + 1);
		fprintf(output_file_ptr, "\t\t\t\t[  Domain Name: %s  ]\n", query.dns_domain_name);
		fprintf(output_file_ptr, "\t\t\t\t[  Type: %hu(%x) (", query.dns_type, query.dns_type);
		if(query.dns_type == DNS_RECORD_A)
			fprintf(output_file_ptr, "Record A");
		else if(query.dns_type == DNS_RECORD_NS)
			fprintf(output_file_ptr, "Record NS");
		else if(query.dns_type == DNS_RECORD_CNAME)
			fprintf(output_file_ptr, "Record CNAME");
		else if(query.dns_type == DNS_RECORD_MX)
			fprintf(output_file_ptr, "Record MX");
		else if(query.dns_type == DNS_RECORD_PTR)
			fprintf(output_file_ptr, "Record PTR");
		else if(query.dns_type == DNS_RECORD_HINFO)
			fprintf(output_file_ptr, "Record HINFO");
		fprintf(output_file_ptr, ")  ]\n");
		fprintf(output_file_ptr, "\t\t\t\t[  Class: %hu(%x) (", query.dns_class, query.dns_class);
		if(query.dns_class == DNS_CLASS_IN)
			fprintf(output_file_ptr, "IN");
		fprintf(output_file_ptr, ")  ]\n");
	}

	// print additionals
	struct dns_response_section response;
	fprintf(output_file_ptr, "\t\t\t[[  DNS Additional Section  ]]\n");
	for(int i = 0; i < dns_header.dns_additional_count; i++)
	{
		response = dns_query_packet->dns_additional_list[i];
		if(response.is_opt_record)
		{
			fprintf(output_file_ptr, "\t\t\t\t[[  DNS Additional #%d (opt record)  ]]\n", i + 1);
			fprintf(output_file_ptr, "\t\t\t\t[  Domain Name: %d(root)  ]\n",
					((struct dns_opt_record *)&response)->dns_opt_name);
			fprintf(output_file_ptr, "\t\t\t\t[  Type: %hu(%x)  ]\n", response.dns_type,
					response.dns_type);
			fprintf(output_file_ptr, "\t\t\t\t[  UDP payload size: %hu  ]\n",
					((struct dns_opt_record *)&response)->dns_udp_payload_size);
			fprintf(output_file_ptr, "\t\t\t\t[  rcode: %x  ]\n",
					((struct dns_opt_record *)&response)->dns_rcode);
			fprintf(output_file_ptr, "\t\t\t\t[  Flags: %x  ]\n",
					ntohl(*((int *)((struct dns_opt_record *)&response)->dns_flags) >> 8));
			fprintf(output_file_ptr, "\t\t\t\t[  Data Length: %hu  ]\n",
					((struct dns_opt_record *)&response)->dns_data_length);
			fprintf(output_file_ptr, "\t\t\t\t[  Option Data:  ]\n");
			pretty_dump(((struct dns_opt_record *)&response)->dns_option_data,
						((struct dns_opt_record *)&response)->dns_data_length, output_file_ptr,
						"\t\t\t\t[  ", "  ]");
		}
		else
		{
			fprintf(output_file_ptr, "\t\t\t\t[[  DNS Additional #%d  ]]\n", i + 1);
			fprintf(output_file_ptr, "\t\t\t\t[  Domain Name: %s  ]\n", response.dns_domain_name);
			fprintf(output_file_ptr, "\t\t\t\t[  Type: %hu(%x) (  ]\n", response.dns_type,
					response.dns_type);
			// print response dns types
			fprintf(output_file_ptr, ")  ]\n");
			fprintf(output_file_ptr, "\t\t\t\t[  Class: %hu(%x) (  ]\n", response.dns_type,
					response.dns_type);
			// print response dns classes
			fprintf(output_file_ptr, ")  ]\n");
			fprintf(output_file_ptr, "\t\t\t\t[  TTL: %d  ]\n", response.dns_TTL);
			fprintf(output_file_ptr, "\t\t\t\t[  Data Length: %hu  ]\n", response.dns_data_length);
			fprintf(output_file_ptr, "\t\t\t\t[  Resource Data:  ]\n");
			pretty_dump(response.dns_resource_data, response.dns_data_length, output_file_ptr,
						"\t\t\t\t[  ", "  ]");
		}
	}
}

int freeDnsQuery(struct dns_query *dns_query_packet)
{
	free(dns_query_packet->dns_queries_list);
	free(dns_query_packet->dns_additional_list);
	free(dns_query_packet);
	return 0;
}

int parseOptRecord(const unsigned char *additional_start, int *data_offset,
				   struct dns_response_section *opt_record_destination,
				   struct allocated_pointers *pointers_head)
{
	char function_name[] = "parseOptRecord";
	struct dns_opt_record opt_record;
	opt_record.dns_opt_name = 0;
	opt_record.padding = 0;
	opt_record.dns_type = ntohs(*(unsigned short *)(additional_start + *data_offset));
	*data_offset += 2;

	if(opt_record.dns_type != 41)
	{
		perror(function_name);
		strcpy(error_message, "Not DNS query");
		return -1;
	}

	opt_record.dns_udp_payload_size = ntohs(*(unsigned short *)(additional_start + *data_offset));
	*data_offset += 2;
	opt_record.dns_rcode = *(unsigned char *)(additional_start + *data_offset);
	*data_offset += 1;
	opt_record.dns_flags[0] = *(unsigned char *)(additional_start + *data_offset);
	*data_offset += 1;
	opt_record.dns_flags[1] = *(unsigned char *)(additional_start + *data_offset);
	*data_offset += 1;
	opt_record.dns_flags[2] = *(unsigned char *)(additional_start + *data_offset);
	*data_offset += 1;
	short dataLength = ntohs(*(unsigned short *)(additional_start + *data_offset));
	*data_offset += 2;
	opt_record.dns_data_length = dataLength;

	if(dataLength != 0)
	{
		unsigned char *resource_data = (unsigned char *)malloc(sizeof(unsigned char) * dataLength);

		if(resource_data == NULL)
		{
			perror(function_name);
			strcpy(error_message, "allocating space");
			return -1;
		}

		else
			add_new_pointer(pointers_head, NULL, resource_data);

		memcpy(resource_data, additional_start + *data_offset, dataLength);
		*data_offset += dataLength;
		opt_record.dns_option_data = resource_data;
	}

	else
		opt_record.dns_option_data = NULL;

	opt_record.is_opt_record = true;
	*opt_record_destination = *(struct dns_response_section *)&opt_record;
	return 0;
}

int parseNormalRecord(const unsigned char *additional_start, int *data_offset,
					  struct dns_response_section *normal_record_destination,
					  struct allocated_pointers *pointers_head)
{
	char function_name[] = "parseNormalRecord";
	int status;
	struct dns_response_section additional_record;

	// byte used to check if OPT record is part of the name
	(*data_offset)--;
	status = getDomainName(additional_start, data_offset, &(additional_record.dns_domain_name));
	if(status == -1)
		return -1;

	if(additional_record.dns_domain_name == NULL)
	{
		perror(function_name);
		strcpy(error_message, "finding domain name");
	}

	else
		add_new_pointer(pointers_head, NULL, additional_record.dns_domain_name);

	additional_record.dns_type = ntohs(*(unsigned short *)(additional_start + *data_offset));
	*data_offset += 2;
	additional_record.dns_class = ntohs(*(unsigned short *)(additional_start + *data_offset));
	*data_offset += 2;
	additional_record.dns_TTL = ntohl(*(unsigned int *)(additional_start + *data_offset));
	*data_offset += 4;
	short dataLength = ntohs(*(unsigned short *)(additional_start + *data_offset));
	*data_offset += 2;
	additional_record.dns_data_length = dataLength;

	if(dataLength != 0)
	{
		unsigned char *resource_data = (unsigned char *)malloc(sizeof(unsigned char) * dataLength);

		if(resource_data == NULL)
		{
			perror(function_name);
			strcpy(error_message, "allocating memory");
			return -1;
		}
		else
			add_new_pointer(pointers_head, NULL, resource_data);

		memcpy(resource_data, additional_start + *data_offset, dataLength);
		*data_offset += dataLength;
		additional_record.dns_resource_data = resource_data;
	}
	else
		additional_record.dns_resource_data = NULL;
	additional_record.is_opt_record = false;

	*normal_record_destination = additional_record;
	return 0;
}
