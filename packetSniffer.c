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

#define CAPTURECOUNT 30

void pcap_fatal(const char *, const char *);

int main()
{
	char errbuf[PCAP_ERRBUF_SIZE];
	pcap_if_t *interface_list;
	pcap_t *pcap_handle;

	if(pcap_findalldevs(&interface_list, errbuf) == PCAP_ERROR)
		pcap_fatal("At findalldevs", errbuf);
	
	// choose first interface
	pcap_if_t interface;
	interface = *interface_list;
	
	printf("Sniffing on device %s (%s)\n", interface.name, interface.description);

	FILE* outputFilePtr;
	outputFilePtr = fopen("capture.log", "w");
	if(outputFilePtr == NULL)
		fatal("opening file", NULL, NULL);

	pcap_handle = pcap_open_live(interface.name, 16384, 1, 100, errbuf);
	if(pcap_handle == NULL)
	{
		pcap_freealldevs(interface_list);
		pcap_fatal("At handle", errbuf);
	}

	struct ethernet_packet* head_ptr;
	head_ptr = (struct ethernet_packet*)malloc(sizeof(struct ethernet_packet));
	if(head_ptr == NULL)
		fatal("allocating space for head_ptr", "main", NULL);
	head_ptr->next_packet = NULL;

	struct pcap_handler_arguments args;
	args.outputFilePtr = outputFilePtr;
	args.packet_list_head = head_ptr;
	args.packet_list_tail = head_ptr;

	struct pcap_handler_arguments* arg_ptr = &args;
	
	pcap_loop(pcap_handle, CAPTURECOUNT, analyze_caught_packet, (unsigned char*)&arg_ptr);

	pcap_freealldevs(interface_list);
	printf("Successfully caught all packets\n");

	printf("Printing packets...\n");
	struct ethernet_packet* current = head_ptr->next_packet;
	while(current != NULL)
	{
		print_packet(current, outputFilePtr);
		current = current->next_packet;
	}

	fclose(outputFilePtr);
	return 0;
}

void pcap_fatal(const char *failed_in, const char *errbuf)
{
	printf("Fatal Error in %s: %s\n", failed_in, errbuf);
	exit(1);
}
