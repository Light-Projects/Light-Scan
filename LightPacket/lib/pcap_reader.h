// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

#ifndef PCAP_READER_H
#define PCAP_READER_H

#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

#pragma pack(push, 1)

typedef struct {
    uint32_t magic_number;
    uint16_t version_major;
    uint16_t version_minor;
    int32_t  thiszone;
    uint32_t sigfigs;
    uint32_t snaplen;
    uint32_t network;
} pcap_global_header_t;

typedef struct {
    uint32_t ts_sec;
    uint32_t ts_usec;
    uint32_t incl_len;
    uint32_t orig_len;
} pcap_packet_header_t;

#pragma pack(pop)

typedef struct {
    pcap_packet_header_t header;
    uint8_t *data;
} packet_entry_t;

typedef struct {
    packet_entry_t *packets;
    long count;
    pcap_global_header_t global_header;
} pcap_result_t;

pcap_result_t read_pcap_file(const char *filename);

void free_pcap_result(pcap_result_t *result);

void print_packet_info(const pcap_result_t *result);

#ifdef __cplusplus
}
#endif

#endif
