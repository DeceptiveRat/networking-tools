# Functions

---

## 1. getDnsQuery

### Synopsis
_int getDnsQuery(const unsigned char *payload_start, struct dns_query **query_location_pp)_

### Description
From *payload_start*, which is the start of the udp payload, check if payload is a DNS query.

If it is a DNS query, allocate a *dns_query*, the appropriate number of *dns_query_section*s and *dns_response_section*s and save the DNS query inside it. *query_location_pp* is set to contain a pointer to the newly allocated *dns_query*.

If it is not a DNS query, no memory is allocated and *query_location_pp* is set to contain a null pointer.

### Return Value
-  1: Is a DNS query. DNS query saved to *dns_query_pointer*.
-  0: Is not a DNS query.
- -1: Error while processing query.

---

## 2. fillQuerySection, fillAdditionalSection

### Synopsis
_int fillQuerySection(const unsigned char *query_start, int *data_offset, int query_count, struct dns_query_section **query_section_location_pp, struct allocated_pointers *pointers_head);_

_int fillAdditionalSection(const unsigned char *additional_start, int *data_offset, int additional_count, struct dns_response_section **additional_section_location_pp, struct allocated_pointers *pointers_head);_

### Description
*fillQuerySection* allocates memory for *query_count* of *dns_query_section*s and parses *query_start* to fill it. *fillAdditionalSection* allocates memory for *additional_count* of *dns_response_section*s and parses *additional_start* to fill it. 

 *data_offset* is incremented to the offset of the start of the next section in both functions.

### Return Value
- 0: The section has been filled in and each newly allocated memory was added to *pointers_head*.
- -1: Error. Error message can be found in *error_message*. Value of *data_offset* is undefined.

### Notes
- Does not free *pointers_head* even when returning with error. This must be freed at the calling function that allocated *pointers_head*.
- In *fillQuerySection*, *domain_names* is not added to the list and thus must be freed manually before returning.

---

## 3. parseOptRecord, parseNormalRecord

### Synopsis
_int parseOptRecord(const unsigned char *additional_start, int *data_offset, struct dns_response_section *opt_record_destination, struct allocated_pointers *pointers_head);_

_int parseNormalRecord(const unsigned char *additional_start, int *data_offset, struct dns_response_section *normal_record_destination, struct allocated_pointers *pointers_head);_

### Description
*parseOptRecord* parses the opt record at *additional_start* + *data_offset* and fills in *opt_record_destination*. *parseNormalRecord* parses the normal record at *additional_start* + *data_offset* and fills in *normal_record_destination*.

*data_offset* is incremented to the start of unparsed data.

### Return Value
- 0: Record has been parsed and put inside the destination.
- -1: Error. Error message can be found in *error_message*. The value of *data_offset* is undefined.

---

## 4. getDomainName

### Synopsis
_int getDomainName(const unsigned char *query_start_pointer, int *query_offset, char **name_destination)_

### Description
Parses *query_start_pointer* + *query_offset* to extract the domain name. The extracted name is put into a newly allocated memory space which *name_destination* points to. 

*query_offset* is modified to point to the next unparsed data. 

DNS compression pointers are parsed as well.

### Return Value
- 0: Name was parsed and put into the destination.
- -1: Error. Error message can be found in *error_message*. The value of *data_offset* is undefined.
---

## 5. printDnsQuery

### Synopsis
_void printDnsQuery(struct dns_query *dns_query_packet, FILE *output_file_ptr)_

### Description
Prints *dns_query_packet* to *output_file_ptr* in a pretty way.

---

# Structures
