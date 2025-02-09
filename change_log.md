# Version #
## summary:

## cleanups:

## new:

## rename:

## remove:

## change:

# Version 1.0
1. separated each layer function into separate header and c files.
	1.1 new files: ethernet.c, ethernet.h, ip.c, ip.h, tcp.c, tcp.h, udp.c, udp.h, dns.c, dns.h
2. added functions to print each layer.
	2.1 removed the now redundant decode functions for each layer
3. added function to remove a certain pointer in the allocated pointer list, file: otherFunctions.h.
4. now "pcap_handler_arguments", file: packetFunctions.h, is passed to "analyze_caught_packet", file: packetFunctions.h, instead of the previous FILE pointer. It contains a list of pointers to previously caught packets and the output FILE pointer.
5. "add_new_pointer", file: otherFunctions.h, now takes pointer to a pointer as the tail argument and sets it to point to the new tail if not null.
6. added function to remove all pointers in the allocated pointer list, file:otherFunctions.h.
7. all layer headers are now stored in host order, not just DNS
	7.1 ip source and destination address is stored in network byte order so "inet_ntop" can be used

# Version 1.1
1. removed "pcap_fatal" function, file: packetSniffer.c.
2. added more elements to "pcap_handler_arguments", file: packetFunctions.h.
	2.1 rawOutputFilePtr: to print raw bytes of the function
3. when a packet is dropped because the checksum doesn't match, print the expected (calculated) checksum and the actual checksum for comparison.
	3.1 to do this, the "tcp/udp_checksum_matches" functions, file: tcp.h/udp.h, now take an additional argument to save the checksum to.
4. removed "dump" function, file: otherFunctions.h, and renamed "dump_to_file", file: otherFunctions.h, function to "dump".
5. removed "debug_dns_packet" function, file: dns.h, because it is now redundant.
6. removed all other structure for packets except "ethernet_packet" and renamed it to "packet_structure", file: packetFunctions.h.
7. the raw bytes of a packet is dumped to a different file now.

# Version 2.0
1. added a C proxy server
	1.1 changed some things to make it compatible with code from the packet sniffer
2. created separate directories for each tool
	2.1 the include directory contains common code files

# Version 2.1
1. removed caching feature from
	1.1 file: /include/socketFunctions.c
	1.2 file: /include/socketFunctions.h
2. added .man files for each header file in /include
3. fixed license headers on all files
4. bulk_print function added, file: /include/otherFunctions.h, but not used yet due to: less flexibility, no way to print integers
5. packets are no longer dumped to the standard output for more readability
6. logs are now saved to path: /Internet Simulator/logs/
7. added "itoa" function, file:/include/otherFunctions.h
8. added "compile.sh", path: /Internet Simulator/ path: /Packet Sniffer/, for easy compiling

# Version 2.1.1
1. corrected README.md
2. removed binary iSim

# Version 3.1

## summary:
- different behaviors for black/whitelisted hosts
- specific connection files now only contain exchange logs
- connections.dbg(previous: all exchanges.log) contains only debugging information for connections
- no more HTTPS handling
- iSim responds to HTTP html requests by compressing the *default.html* file to *default.html.gz* and sending it
- *change_log.txt* is now *change_log.md*. It has different formatting as well

## cleanups:
- m: moved some macro definitions to start of functions that use them
- f: handleConnection
	- removed redundant parentheses
- f: setupMutexes
	- /include/socketFunctions.h => /include/otherFunctions.h
- f: cleanMutexes
	- /include/socketFunctions.h => /include/otherFunctions.h

## new:

### /include/socketFunctions.h
- f: setupWhitelist
- s: whitelistStructure
- f: sendResponse
- f: blacklistedThreadFunction
- f: getHTTPRequestType
- f: getRequestedObject
- f: setupResponse
- s: header
- s: HTTPResponse

### /include/otherFunctions.h
- f: gzipCompress

## rename:

### /include/socketFunctions.h
- f: threadFunction => whitelistedThreadFunction
- m: PORT => LISTENING\_PORT
- s\_v: threadParameters.globalOutputFilePtr => debugFilePtr
- s\_v: threadParameters.localOutputFilePtr => outputFilePtr
- fl: all exchanges.log => connections.dbg

### /
- fl: change\_log.txt => change\_log.md

## remove:

### /include/socketFunctions.h
- m: DOMAIN\_NAME\_FILE\_NAME
- ft: timeout for listening socket
- ft: HTTPS related code
- f: getDestinationPort

## change:

# Version 4.1

## summary:
- *dnsProxy* added
	- currently captures all dns requests and prints them. Does not respond to them yet
- in *dnsHandling.h/dnsHandling.c*, instead of *fatal()* being used, functions now return -1 when an error occurs and saves the error message to *error_message*
- */Internet Simulator/compile.sh* modified to compile *dnsProxy.c* to *dnsProxy* and *httpProxy.c* to *httpProxy*

## cleanups:
- f: isNumber
	- /include/socketFunctions.h => /include/otherFunctions.h

## new:

### /Internet Simulator
- fl: dnsProxy.c

### /include/otherFunctions.h
- f: setExitFlag
- f: exitFlagSet
- f: SIGINTSetsExitFlag
- f: SIGINTDefault
- gv: exit\_flag
- gv: error\_message

### /include/dnsHandling.h
- f: initializeDNSProxy
- f: handleDNSConnection
- f: returnUDPListeningSocket
- f: returnEpollInstance

### /include/dns.h
- f: freeDnsQuery

### /include
- fl: dnsHandling.h
- fl: dnsHandling.c
- fl: dnsHandling.md

## rename:
- /include/socketFunctions.h => /include/httpHandling.h
- /include/socketFunctions.c => /include/httpHandling.c
- /include/Internet Simulator/http\_proxy.c => /include/Internet Simulator/httpProxy.c

### /include/httpHandling.h
- f: handleConnection => handleHTTPConnection

## remove:

### /include/httpHandling.h
- m: CONNECTION\_ESTABLISHED\_MESSAGE\_LENGTH

## change:

### /include/otherFunctions.h
- m: ERROR\_MESSAGE\_SIZE
	- now will only be defined if there isn't already a definition for it

# Version 5.1

## summary:
- file */include/dns.h* has been formatted to fit the new code style
	- variables and structures use _
	- functions use CamelCase
	- each line does not exceed 100 characters
	- all functions return 0 on success and -1 on error
	- functions now do not use *fatal* to exit. All errors will be handled at an appropriate higher level function	
- file */include/ethernet.h* has been formatted
- file */include/ip.h* has been formatted
- file */include/tcp.h* has been formatted
- file */include/udp.h* has been formatted

## cleanups:

## new:

### /include/dns.h
- f: *fillQuerySection*
- f: *fillAdditionalSection*
- f: *parseOptRecord*
- f: *parseNormalRecord*

### /include/packetFunctions.h
- f: *getLinkLayerHeader*
- f: *getNetworkLayerHeader*
- f: *getTransportLayerHeader*

## rename:

### /include/dns.h
- v: *head => pointers_head*
- f: *get_dns_query => getDnsQuery*
	- v: *dns_query_pointer => query_location_pp*
	- v: *header_start => payload_start*
- f: *get_dns_response => getDnsResponse*
	- v: *dns_response_pointer => response_location_pp*
- f: *get_domain_name => getDomainName*
- f: *print_dns_query => printDnsQuery*
	- v: *outputFilePtr => output_file_ptr*
	
### /include/ethernet.h
- f: *get_ethernet_header => getEthernetHeader*
- f: *print_ethernet_header => printEthernetHeader*

### /include/ip.h
- f: *get_ip_header => getIPHeader*
- f: *print_ip_header => printIPHeader*

### /include/tcp.h
- f: *tcp_checksum_matches => tcpChecksumMatches*
- f: *get_tcp_header => getTCPHeader*
- f: *print_tcp_header => printTCPHeader*

### /include/udp.h
- f: *udp_checksum_matches => udpChecksumMatches*
- f: *get_udp_header => getUDPHeader*
- f: *print_udp_header => printUDPHeader*

### /include/packetFunctions.h
- v: *outputFilePtr => output_file_ptr*
- v: *rawOutputFilePtr => raw_output_file_ptr*
- f: *analyze_caught_packets => saveCaughtPackets*
	- v: *head => pointers_head*
	- v: *tail => pointers_tail*
	- v: *saved_packet => structured_packet*
- f: *save_remaining_bytes => saveRemainingBytes*
- f: *print_packet => printPacket*
	- v: *packet => structured_packet*
- s: *packet_structure*
	- v: *ethernet_header => link_layer_header*
	- v: *network_layer_structure => network_layer_header*
	- v: *transport_layer_structure => transport_layer_header*
	- v: *application_layer_structure => application_layer_header*

### /Packet Sniffer/packetSniffer.c
- f: *main*
	- v: *outputFilePtr => output_file_ptr*
	- v: *rawOutputFilePtr => raw_output_file_ptr*

## remove:

## change:

### /include/dns.h
- f: *getDnsQuery*
	- return type bool => int
	- no longer calls *fatal* to terminate. Error message is saved and -1 is returned instead
- f: *getDnsResponse*
	- return type bool => int
- f: *getDomainName*
	- return type char* => int 
	- added argument of type char**
	
### /include/ethernet.h
- f: *getEthernetHeader*
	- return type bool => int

### /include/ip.h
- f: *getIPHeader*
	- return type bool => int
	
### /include/tcp.h
- f: *tcpChecksumMatches*
	- return type char => int
	
- f: *getTCPHeader*
	- return type bool => int
	
### /include/udp.h
- f: *udpChecksumMatches*
	- return type char => int
	
- f: *getUDPHeader*
	- return type bool => int
	
### /include/packetFunctions.h
- f: *analyzeCaughtPacket*
	- instead of *fatal*, when error occurs, print error message and either terminate or start working on the next packet
	
- f: *saveRemainingBytes*
	- return type void => int
	
- f: *printPacket*
	- return type void => int
	
- s: *packet_structure*
	- *link_layer_header* type _struct ether_hdr*_ => void*
