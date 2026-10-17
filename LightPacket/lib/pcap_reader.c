// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.


#include "pcap_reader.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static uint32_t swap32(uint32_t v) {
    return ((v & 0x000000FFu) << 24) |
           ((v & 0x0000FF00u) << 8)  |
           ((v & 0x00FF0000u) >> 8)  |
           ((v & 0xFF000000u) >> 24);
}

static uint16_t swap16(uint16_t v) {
    return (uint16_t)((v << 8) | (v >> 8));
}

static void swap_global_header(pcap_global_header_t *h) {
    h->magic_number   = swap32(h->magic_number);
    h->version_major   = swap16(h->version_major);
    h->version_minor   = swap16(h->version_minor);
    h->thiszone        = (int32_t)swap32((uint32_t)h->thiszone);
    h->sigfigs          = swap32(h->sigfigs);
    h->snaplen          = swap32(h->snaplen);
    h->network          = swap32(h->network);
}

static void swap_packet_header(pcap_packet_header_t *h) {
    h->ts_sec    = swap32(h->ts_sec);
    h->ts_usec   = swap32(h->ts_usec);
    h->incl_len  = swap32(h->incl_len);
    h->orig_len  = swap32(h->orig_len);
}

#define PCAP_INITIAL_CAPACITY 64

pcap_result_t read_pcap_file(const char *filename) {
    pcap_result_t result = {NULL, 0, {0}};
    FILE *file = fopen(filename, "rb");
    int need_swap = 0;
    size_t capacity = 0;

    if (file == NULL) {
        return result;
    }

    if (fseek(file, 0, SEEK_END) != 0) {
        fclose(file);
        return result;
    }
    long file_size = ftell(file);
    if (file_size < 0 || fseek(file, 0, SEEK_SET) != 0) {
        fclose(file);
        return result;
    }

    if (fread(&result.global_header, sizeof(pcap_global_header_t), 1, file) != 1) {
        fclose(file);
        return result;
    }

    if (result.global_header.magic_number == 0xa1b2c3d4 ||
        result.global_header.magic_number == 0xa1b23c4d) {
        need_swap = 0;
    } else if (result.global_header.magic_number == 0xd4c3b2a1 ||
               result.global_header.magic_number == 0x4d3cb2a1) {
        need_swap = 1;
    } else {
        fclose(file);
        return result;
    }

    if (need_swap) {
        swap_global_header(&result.global_header);
    }

    pcap_packet_header_t pkt_header;

    while (fread(&pkt_header, sizeof(pcap_packet_header_t), 1, file) == 1) {
        if (need_swap) {
            swap_packet_header(&pkt_header);
        }

        long current_pos = ftell(file);
        if (current_pos < 0 ||
            (long)pkt_header.incl_len > file_size - current_pos) {
            break;
        }

        if ((size_t)result.count == capacity) {
            size_t new_capacity = capacity == 0 ? PCAP_INITIAL_CAPACITY : capacity * 2;

            if (new_capacity > SIZE_MAX / sizeof(packet_entry_t)) {
                free_pcap_result(&result);
                fclose(file);
                return result;
            }

            packet_entry_t *grown = realloc(result.packets, new_capacity * sizeof(packet_entry_t));
            if (grown == NULL) {
                free_pcap_result(&result);
                fclose(file);
                return result;
            }

            result.packets = grown;
            capacity = new_capacity;
        }

        size_t alloc_len = pkt_header.incl_len > 0 ? pkt_header.incl_len : 1;
        uint8_t *data = malloc(alloc_len);
        if (data == NULL) {
            free_pcap_result(&result);
            fclose(file);
            return result;
        }

        if (pkt_header.incl_len > 0 &&
            fread(data, 1, pkt_header.incl_len, file) != pkt_header.incl_len) {
            free(data);
            free_pcap_result(&result);
            fclose(file);
            return result;
        }

        result.packets[result.count].header = pkt_header;
        result.packets[result.count].data = data;
        result.count++;
    }

    if (capacity > (size_t)result.count) {
        packet_entry_t *shrunk = realloc(result.packets, (size_t)result.count * sizeof(packet_entry_t));
        if (shrunk != NULL) {
            result.packets = shrunk;
        }
    }

    fclose(file);
    return result;
}

void free_pcap_result(pcap_result_t *result) {
    if (result->packets != NULL) {
        for (long i = 0; i < result->count; i++) {
            free(result->packets[i].data);
        }
        free(result->packets);
        result->packets = NULL;
        result->count = 0;
    }
}

void print_packet_info(const pcap_result_t *result) {
    printf("Global Header Info:\n");
    printf("  Magic: 0x%08x\n", result->global_header.magic_number);
    printf("  Version: %u.%u\n", result->global_header.version_major, result->global_header.version_minor);
    printf("  Network: %u\n", result->global_header.network);
    printf("  SnapLen: %u\n", result->global_header.snaplen);
    printf("--------------------------------------------------\n");
    printf("Total packets: %ld\n", result->count);

    for (long i = 0; i < result->count && i < 10; i++) {
        printf("\nPacket %ld:\n", i + 1);
        printf("  Temps : %u.%06u s\n", result->packets[i].header.ts_sec, result->packets[i].header.ts_usec);
        printf("  Lenght : %u octets\n", result->packets[i].header.incl_len);
    }
}