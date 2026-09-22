// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

/*
 * pcapng_format.h - Internal, private constants describing the on-disk
 * PCAPNG block layout. Not installed/exposed to library users; this is
 * an implementation detail shared only between our own .c files.
 *
 * Every PCAPNG block, regardless of type, follows this shape on disk:
 *
 *   +---------------------------------------------------------+
 *   | Block Type (4 bytes)                                    |
 *   +---------------------------------------------------------+
 *   | Block Total Length (4 bytes)                             |
 *   +---------------------------------------------------------+
 *   | Block Body (variable length, specific to Block Type)     |
 *   +---------------------------------------------------------+
 *   | Block Total Length (4 bytes)  <-- repeated, for backward |
 *   |                                    seeking / validation  |
 *   +---------------------------------------------------------+
 *
 * "Block Total Length" includes the two 4-byte length fields themselves
 * and the block type field, so the minimum possible block is 12 bytes
 * (4 type + 4 length + 0 body + 4 length), though in practice every real
 * block type has a non-empty body.
 *
 * All multi-byte fields are stored in the byte order indicated by the
 * Section Header Block's BYTE_ORDER_MAGIC field. pcapng.c's reader
 * detects that byte order once per file (see read_and_validate_shb() in
 * pcapng.c) and byte-swaps every subsequent multi-byte field as needed
 * using the pcapng_bswap16/32/64() helpers defined below. The writer
 * always emits the host's native byte order and never needs to swap.
 */

#ifndef PCAPNG_FORMAT_H
#define PCAPNG_FORMAT_H

#include <stdint.h>

#define PCAPNG_ALIGN4_MAX 0xFFFFFFFCu

#define PCAPNG_MAX_PACKET 0x04000000u

#define BLOCK_TYPE_SHB   0x0A0D0D0Au   /* Section Header Block */
#define BLOCK_TYPE_IDB   0x00000001u   /* Interface Description Block */
#define BLOCK_TYPE_EPB   0x00000006u   /* Enhanced Packet Block */

#define BYTE_ORDER_MAGIC 0x1A2B3C4Du

#define PCAPNG_VERSION_MAJOR 1
#define PCAPNG_VERSION_MINOR 0

#define OPT_ENDOFOPT   0x0000u
#define OPT_IF_NAME    0x0002u  /* IDB option: interface name string */

typedef struct __attribute__((packed)) {
    uint32_t byte_order_magic;   /* must equal BYTE_ORDER_MAGIC on read   */
    uint16_t version_major;
    uint16_t version_minor;
    int64_t  section_length;     /* -1 (all bits set) = "unknown/unspecified" */

} shb_body_t;

typedef struct __attribute__((packed)) {
    uint16_t link_type;
    uint16_t reserved;
    uint32_t snaplen;
} idb_body_t;

typedef struct __attribute__((packed)) {
    uint32_t interface_id;
    uint32_t timestamp_high;
    uint32_t timestamp_low;
    uint32_t captured_len;
    uint32_t original_len;
} epb_header_t;

static inline uint32_t pcapng_align4(uint32_t n) {
    return (n + 3u) & ~3u;
}

static inline int pcapng_align4_safe(uint32_t n, uint32_t *out) {
    if (n > PCAPNG_ALIGN4_MAX) return 0;
    *out = (n + 3u) & ~3u;
    return 1;
}

static inline uint16_t pcapng_bswap16(uint16_t v) { return (v >> 8) | (v << 8); }

static inline uint32_t pcapng_bswap32(uint32_t v) {
    return ((v & 0xFF000000u) >> 24) |
           ((v & 0x00FF0000u) >>  8) |
           ((v & 0x0000FF00u) <<  8) |
           ((v & 0x000000FFu) << 24);
}

static inline uint64_t pcapng_bswap64(uint64_t v) {
    return ((uint64_t)pcapng_bswap32((uint32_t)(v & 0xFFFFFFFFu)) << 32) |
            (uint64_t)pcapng_bswap32((uint32_t)(v >> 32));
}

#endif