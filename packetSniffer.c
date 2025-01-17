/* 
 * This file is part of BPS.
 *
 * BPS is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * BPS is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with BPS.  If not, see <https://www.gnu.org/licenses/>.
 */

#include <pcap.h>
#include <stdlib.h>
#include <stdio.h>
#include <unistd.h>

#include "packetFunctions.h"
#include "otherFunctions.h"

#define CAPTURECOUNT 10
#define OUTPUT_FILE "capture.log"
#define RAW_OUTPUT_FILE "raw.log"

int main()
{
	char errbuf[PCAP_ERRBUF_SIZE];
	pcap_if_t *interface_list;
	pcap_t *pcap_handle;

	if(pcap_findalldevs(&interface_list, errbuf) == PCAP_ERROR)
		fatal("finding all devs", NULL, stdout);
	
	// choose first interface
	pcap_if_t interface;
	interface = *interface_list;
	printf("Sniffing on device %s (%s)\n", interface.name, interface.description);
	pcap_handle = pcap_open_live(interface.name, 16384, 1, 100, errbuf);
	if(pcap_handle == NULL)
		fatal("opening handle", NULL, stdout);

	// open output files
	FILE* outputFilePtr;
	outputFilePtr = fopen(OUTPUT_FILE, "w");
	if(outputFilePtr == NULL)
		fatal("opening file", NULL, NULL);
	FILE* rawOutputFilePtr;
	rawOutputFilePtr = fopen(RAW_OUTPUT_FILE, "w");
	if(rawOutputFilePtr == NULL)
		fatal("opening file", NULL, NULL);

	// allocate head for packet list
	struct packet_structure* head_ptr;
	head_ptr = (struct packet_structure*)malloc(sizeof(struct packet_structure));
	if(head_ptr == NULL)
		fatal("allocating space for head_ptr", "main", NULL);
	head_ptr->next_packet = NULL;

	// arguments for handler function
	struct pcap_handler_arguments args;
	args.outputFilePtr = outputFilePtr;
	args.rawOutputFilePtr = rawOutputFilePtr;
	args.packet_list_head = head_ptr;
	args.packet_list_tail = head_ptr;
	args.captured_count = 0;
	struct pcap_handler_arguments* arg_ptr = &args;
	
	pcap_loop(pcap_handle, CAPTURECOUNT, analyze_caught_packet, (unsigned char*)&arg_ptr);

	pcap_freealldevs(interface_list);
	printf("Successfully caught all packets\n");

	printf("Printing packets...\n");
	struct packet_structure* current = head_ptr->next_packet;
	while(current != NULL)
	{
		print_packet(current, outputFilePtr);
		current = current->next_packet;
	}

	fclose(outputFilePtr);
	return 0;
}
