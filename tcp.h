#pragma once

#include <stdio.h>
#include <sys/socket.h>
#include <stdlib.h>
#include <stdbool.h>

#define TCP_HDR_LEN 20
struct tcp_hdr
{
    unsigned short tcp_src_port;
    unsigned short tcp_dest_port;
    unsigned int tcp_seq;
    unsigned int tcp_ack;
    // assuming little endian
    unsigned char tcp_reserved_4: 4;
    unsigned char tcp_offset: 4;
    unsigned char tcp_flags;	// the first 2 bits are reserved
#define TCP_FIN 0x01
#define TCP_SYN 0x02
#define TCP_RST 0x04
#define TCP_PUSH 0x08
#define TCP_ACK 0x10
#define TCP_URG 0x20
    unsigned short tcp_window;
    unsigned short tcp_checksum;
    unsigned short tcp_urgent;
};

struct tcp_hdr_options
{
	// work in progress
};

struct tcp_hdr decode_tcp(const unsigned char *tcp_header_start, FILE* outputFilePtr, int *tcp_header_size);
bool get_tcp_header(const unsigned char *tcp_header_start, struct tcp_hdr* tcp_header, int *tcp_header_size);
char tcp_checksum_matches(const unsigned char *header_start);
void print_tcp_header(const struct tcp_hdr *tcp_header, FILE* outputFilePtr);
