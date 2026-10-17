// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

/*
 * pcapng.c - Implementation of the PCAPNG reader/writer library.
 *
 * See pcapng.h for the public API and pcapng_format.h for on-disk layout
 * constants. This file is organized as:
 *   1. Internal struct definitions (the "real" contents of the opaque
 *      pcapng_writer_t / pcapng_reader_t handles declared in pcapng.h)
 *   2. Small internal I/O helper functions (endian-agnostic + endian-aware)
 *   3. Writer implementation (always writes host-native little/big endian
 *      as detected by BYTE_ORDER_MAGIC -- see note below)
 *   4. Reader implementation (accepts BOTH little-endian and big-endian
 *      pcapng files, transparently byte-swapping as it reads)
 *
 * -------------------------------------------------------------------------
 * ENDIANNESS SUPPORT (read side)
 * -------------------------------------------------------------------------
 * A pcapng file's Section Header Block (SHB) starts with a 4-byte
 * "byte order magic" field that is always written as the literal value
 * 0x1A2B3C4D, in whatever byte order the writer used for every other
 * multi-byte field in the file. A reader determines the file's byte order
 * by reading those 4 bytes AS-IS (no swapping) and checking which of the
 * two possible interpretations it matches:
 *
 *   - bytes read literally equal 0x1A2B3C4D  -> file matches our host's
 *     byte order already; no swapping needed anywhere in the file.
 *   - bytes byte-swapped equal 0x1A2B3C4D    -> file was written in the
 *     OPPOSITE byte order from our host; every multि-byte field in every
 *     block for the rest of the file must be byte-swapped after reading.
 *   - neither matches                         -> not a valid pcapng file.
 *
 * Once that's determined, we remember it in `pcapng_reader_t.swapped`
 * (1 = every multi-byte field read from here on must be swapped, 0 = read
 * as-is) and every subsequent multi-byte read in this file funnels through
 * read_u16_file()/read_u32_file()/read_u64_file(), which apply the swap
 * automatically based on that flag. This is why those helpers take a
 * `pcapng_reader_t *r` (to consult r->swapped) instead of a bare FILE *.
 *
 * We deliberately do NOT implement this on the WRITE side: this library
 * always writes files in the host's native byte order (i.e. the byte
 * order this code was compiled for), which is the common, simple, and
 * spec-compliant thing to do -- nothing requires a writer to support
 * emitting the non-native byte order, only that readers cope with
 * whichever byte order they're handed. That's exactly what we now do.
 */

#include "pcapng.h"
#include "pcapng_format.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>


struct pcapng_writer {
    FILE *fp;                /* underlying file stream                    */
    uint32_t next_if_id;     /* next interface_id to hand out              */
};

typedef struct {
    uint16_t link_type;
    uint32_t snaplen;
    char *name;
} reader_iface_t;

struct pcapng_reader {
    FILE *fp;                /* underlying file stream                     */
    uint8_t *packet_buf;     /* reusable heap buffer for the "current"      */

    int swapped;
    size_t packet_buf_cap;   /* current allocated size of packet_buf        */
    uint32_t next_if_id;     /* how many IDBs we've seen so far (bookkeeping)*/

    reader_iface_t *ifaces;  /* heap array of interfaces seen so far        */
    uint32_t iface_count;    /* number of valid entries in `ifaces`         */
    uint32_t iface_cap;      /* allocated capacity of `ifaces`              */
};

static int write_raw(FILE *fp, const void *buf, size_t len) {
    if (len == 0) return 1;             /* nothing to do, trivially fine */
    return fwrite(buf, 1, len, fp) == len;
}

static int write_u32(FILE *fp, uint32_t v) {
    return write_raw(fp, &v, sizeof(v));
}

static int read_raw(FILE *fp, void *buf, size_t len, int *out_eof) {
    if (out_eof) *out_eof = 0;
    if (len == 0) return 1;
    size_t got = fread(buf, 1, len, fp);
    if (got == len) return 1;
    if (got == 0 && feof(fp)) {
        if (out_eof) *out_eof = 1;
    }
    return 0;
}

static int read_u32(FILE *fp, uint32_t *v, int *out_eof) {
    return read_raw(fp, v, sizeof(*v), out_eof);
}

static int write_padding(FILE *fp, uint32_t count) {
    static const uint8_t zeros[4] = {0, 0, 0, 0};
    return write_raw(fp, zeros, count);
}

static int read_u16_file(pcapng_reader_t *r, uint16_t *v) {
    if (!read_raw(r->fp, v, sizeof(*v), NULL)) return 0;
    if (r->swapped) *v = pcapng_bswap16(*v);
    return 1;
}

static int read_u32_file(pcapng_reader_t *r, uint32_t *v) {
    if (!read_raw(r->fp, v, sizeof(*v), NULL)) return 0;
    if (r->swapped) *v = pcapng_bswap32(*v);
    return 1;
}

static int __attribute__((unused)) read_u64_file(pcapng_reader_t *r, uint64_t *v) {
    if (!read_raw(r->fp, v, sizeof(*v), NULL)) return 0;
    if (r->swapped) *v = pcapng_bswap64(*v);
    return 1;
}

static int write_shb(FILE *fp) {
    shb_body_t body;
    memset(&body, 0, sizeof(body));           /* zero every field first, then fill in */
    body.byte_order_magic = BYTE_ORDER_MAGIC;
    body.version_major = PCAPNG_VERSION_MAJOR;
    body.version_minor = PCAPNG_VERSION_MINOR;
    body.section_length = -1;                 /* -1 = "length not specified" per spec */

    uint32_t total_len = 4 + 4 + (uint32_t)sizeof(body) + 4;

    if (!write_u32(fp, BLOCK_TYPE_SHB)) return 0;
    if (!write_u32(fp, total_len))      return 0;
    if (!write_raw(fp, &body, sizeof(body))) return 0;
    if (!write_u32(fp, total_len))      return 0;  /* trailing length repeat */
    return 1;
}

pcapng_writer_t *pcapng_writer_open(const char *path) {
    if (!path) return NULL;                   /* defend against NULL argument */

    FILE *fp = fopen(path, "wb");
    if (!fp) return NULL;                     /* e.g. permission denied, bad path */

    pcapng_writer_t *w = (pcapng_writer_t *)malloc(sizeof(*w));
    if (!w) {                                 /* allocation failed */
        fclose(fp);
        return NULL;
    }

    w->fp = fp;
    w->next_if_id = 0;

    if (!write_shb(fp)) {                     /* every valid file starts with an SHB */
        fclose(fp);
        free(w);
        return NULL;
    }

    return w;
}

int pcapng_writer_add_interface(pcapng_writer_t *w,
                                 uint16_t link_type,
                                 uint32_t snaplen,
                                 const char *if_name) {
    if (!w) return PCAPNG_ERR_INVAL;

    idb_body_t body;
    body.link_type = link_type;
    body.reserved = 0;
    body.snaplen = snaplen;

    uint16_t name_len = 0;
    uint32_t name_padded = 0;
    if (if_name && if_name[0] != '\0') {
        size_t len = strlen(if_name);
        if (len > 0xFFFFu) len = 0xFFFFu;      /* option length field is only 16 bits */
        name_len = (uint16_t)len;
        name_padded = pcapng_align4(name_len);
    }

    uint32_t options_len = 0;
    if (name_len > 0) {
        /* 4 bytes for the option's own code+length header, plus the
         * padded value bytes, plus 4 bytes for the final endofopt marker. */
        options_len = 4 + name_padded + 4;
    }

    uint32_t total_len = 4 /*type*/ + 4 /*total_len*/ + (uint32_t)sizeof(body)
                        + options_len + 4 /*trailing total_len*/;

    FILE *fp = w->fp;
    if (!write_u32(fp, BLOCK_TYPE_IDB)) return PCAPNG_ERR_IO;
    if (!write_u32(fp, total_len))      return PCAPNG_ERR_IO;
    if (!write_raw(fp, &body, sizeof(body))) return PCAPNG_ERR_IO;

    if (name_len > 0) {
        uint16_t code = OPT_IF_NAME;
        if (!write_raw(fp, &code, sizeof(code)))     return PCAPNG_ERR_IO;
        if (!write_raw(fp, &name_len, sizeof(name_len))) return PCAPNG_ERR_IO;
        if (!write_raw(fp, if_name, name_len))       return PCAPNG_ERR_IO;
        if (!write_padding(fp, name_padded - name_len)) return PCAPNG_ERR_IO;

        uint16_t end_code = OPT_ENDOFOPT, end_len = 0;
        if (!write_raw(fp, &end_code, sizeof(end_code))) return PCAPNG_ERR_IO;
        if (!write_raw(fp, &end_len, sizeof(end_len)))   return PCAPNG_ERR_IO;
    }

    if (!write_u32(fp, total_len)) return PCAPNG_ERR_IO;

    /* Hand back this interface's id, then increment for the next caller. */
    return (int)(w->next_if_id++);
}

pcapng_status_t pcapng_writer_write_packet(pcapng_writer_t *w,
                                            uint32_t interface_id,
                                            uint64_t ts_usecs,
                                            const uint8_t *data,
                                            uint32_t length) {
    if (!w) return PCAPNG_ERR_INVAL;
    if (!data && length > 0) return PCAPNG_ERR_INVAL;
    if (interface_id >= w->next_if_id) return PCAPNG_ERR_INVAL; /* unknown interface */

    epb_header_t hdr;
    hdr.interface_id   = interface_id;
    hdr.timestamp_high = (uint32_t)(ts_usecs >> 32);   /* upper 32 bits */
    hdr.timestamp_low  = (uint32_t)(ts_usecs & 0xFFFFFFFFu); /* lower 32 bits */
    hdr.captured_len    = length;
    hdr.original_len    = length;   /* we always capture everything given to us */

    uint32_t padded_len = pcapng_align4(length);
    uint32_t pad_bytes = padded_len - length;

    uint32_t total_len = 4 + 4 + (uint32_t)sizeof(hdr) + padded_len + 4;

    FILE *fp = w->fp;
    if (!write_u32(fp, BLOCK_TYPE_EPB))       return PCAPNG_ERR_IO;
    if (!write_u32(fp, total_len))            return PCAPNG_ERR_IO;
    if (!write_raw(fp, &hdr, sizeof(hdr)))    return PCAPNG_ERR_IO;
    if (!write_raw(fp, data, length))         return PCAPNG_ERR_IO;
    if (!write_padding(fp, pad_bytes))        return PCAPNG_ERR_IO;
    if (!write_u32(fp, total_len))            return PCAPNG_ERR_IO;

    return PCAPNG_OK;
}

void pcapng_writer_close(pcapng_writer_t *w) {
    if (!w) return;                 /* closing NULL is a safe no-op, like free() */
    if (w->fp) fclose(w->fp);
    free(w);
}

static pcapng_status_t read_one_block(pcapng_reader_t *r,
                                       pcapng_packet_t *out_packet,
                                       int *out_got_packet);

static int ensure_packet_capacity(pcapng_reader_t *r, size_t needed) {
    if (needed <= r->packet_buf_cap) return 1;   /* already big enough */

    size_t new_cap = r->packet_buf_cap ? r->packet_buf_cap * 2 : 2048;
    if (new_cap < needed) new_cap = needed;

    uint8_t *new_buf = (uint8_t *)realloc(r->packet_buf, new_cap);
    if (!new_buf) return 0;                       /* OOM; leave old buffer untouched */

    r->packet_buf = new_buf;
    r->packet_buf_cap = new_cap;
    return 1;
}

static int reader_add_interface(pcapng_reader_t *r, uint16_t link_type,
                                 uint32_t snaplen, const char *name, size_t name_len) {
    if (r->iface_count == r->iface_cap) {
        uint32_t new_cap = r->iface_cap ? r->iface_cap * 2 : 4;
        reader_iface_t *new_arr = (reader_iface_t *)realloc(
            r->ifaces, new_cap * sizeof(*new_arr));
        if (!new_arr) return 0;
        r->ifaces = new_arr;
        r->iface_cap = new_cap;
    }

    char *name_copy = (char *)malloc(name_len + 1);   /* +1 for NUL terminator */
    if (!name_copy) return 0;
    if (name_len > 0) memcpy(name_copy, name, name_len);
    name_copy[name_len] = '\0';

    reader_iface_t *dst = &r->ifaces[r->iface_count];
    dst->link_type = link_type;
    dst->snaplen = snaplen;
    dst->name = name_copy;
    r->iface_count++;
    return 1;
}

static int read_and_validate_shb(pcapng_reader_t *r) {
    FILE *fp = r->fp;
    uint32_t block_type, total_len;
    int eof = 0;

    if (!read_u32(fp, &block_type, &eof)) return 0; /* covers EOF-at-file-start too */
    if (block_type != BLOCK_TYPE_SHB) return 0;      /* not a pcapng file at all */

    if (!read_u32(fp, &total_len, NULL)) return 0;


    shb_body_t body;
    if (!read_raw(fp, &body, sizeof(body), NULL)) return 0;

    if (body.byte_order_magic == BYTE_ORDER_MAGIC) {
        r->swapped = 0;
    } else if (pcapng_bswap32(body.byte_order_magic) == BYTE_ORDER_MAGIC) {
        r->swapped = 1;
    } else {
        return 0;   /* neither interpretation matches -> not a valid pcapng file */
    }

    if (r->swapped) {
        total_len = pcapng_bswap32(total_len);
    }

    long already_consumed = 4 + 4 + (long)sizeof(body);
    long remaining = (long)total_len - already_consumed - 4;
    if (remaining < 0) return 0;                 /* malformed: total_len too small */
    if (remaining > 0 && fseek(fp, remaining, SEEK_CUR) != 0) return 0;

    uint32_t trailing_len;
    if (!read_u32_file(r, &trailing_len)) return 0;
    if (trailing_len != total_len) return 0;

    return 1;
}

pcapng_reader_t *pcapng_reader_open(const char *path) {
    if (!path) return NULL;

    FILE *fp = fopen(path, "rb");   /* "rb" = read, binary mode */
    if (!fp) return NULL;

    pcapng_reader_t *r = (pcapng_reader_t *)malloc(sizeof(*r));
    if (!r) {
        fclose(fp);
        return NULL;
    }

    r->fp = fp;
    r->packet_buf = NULL;
    r->packet_buf_cap = 0;
    r->swapped = 0;          /* placeholder; read_and_validate_shb() sets the real value */
    r->next_if_id = 0;
    r->ifaces = NULL;
    r->iface_count = 0;
    r->iface_cap = 0;

    if (!read_and_validate_shb(r)) {
        fclose(fp);
        free(r);
        return NULL;
    }

    for (;;) {
        long pos = ftell(fp);
        if (pos < 0) break;   /* ftell failed; not fatal, just stop pre-scanning */

        uint32_t block_type;
        int eof = 0;
        if (!read_u32(fp, &block_type, &eof)) {
            fseek(fp, pos, SEEK_SET);   /* EOF or I/O hiccup: rewind, stop pre-scanning */
            break;
        }
        if (r->swapped) block_type = pcapng_bswap32(block_type);

        if (block_type != BLOCK_TYPE_IDB) {
            fseek(fp, pos, SEEK_SET);   /* first packet or other block: rewind, stop */
            break;
        }

        fseek(fp, pos, SEEK_SET);
        pcapng_packet_t unused_packet;
        int got_packet = 0;
        pcapng_status_t st = read_one_block(r, &unused_packet, &got_packet);
        if (st != PCAPNG_OK) {
            fclose(fp);
            for (uint32_t i = 0; i < r->iface_count; i++) free(r->ifaces[i].name);
            free(r->ifaces);
            free(r);
            return NULL;
        }
    }

    return r;
}

static pcapng_status_t read_one_block(pcapng_reader_t *r,
                                       pcapng_packet_t *out_packet,
                                       int *out_got_packet) {
    *out_got_packet = 0;

    uint32_t block_type, total_len;
    int eof = 0;

    if (!read_u32(r->fp, &block_type, &eof)) {
        return eof ? PCAPNG_ERR_EOF : PCAPNG_ERR_IO;
    }
    if (r->swapped) block_type = pcapng_bswap32(block_type);

    if (!read_u32_file(r, &total_len)) return PCAPNG_ERR_FORMAT;

    /* Every block must be at least 12 bytes (type+len+trailing len). */
    if (total_len < 12) return PCAPNG_ERR_FORMAT;

    uint32_t body_len = total_len - 12;

    if (block_type == BLOCK_TYPE_EPB) {
        epb_header_t hdr;
        uint32_t interface_id, timestamp_high, timestamp_low, captured_len, original_len;
        if (body_len < sizeof(hdr)) return PCAPNG_ERR_FORMAT;
        if (!read_u32_file(r, &interface_id))   return PCAPNG_ERR_FORMAT;
        if (!read_u32_file(r, &timestamp_high)) return PCAPNG_ERR_FORMAT;
        if (!read_u32_file(r, &timestamp_low))  return PCAPNG_ERR_FORMAT;
        if (!read_u32_file(r, &captured_len))   return PCAPNG_ERR_FORMAT;
        if (!read_u32_file(r, &original_len))   return PCAPNG_ERR_FORMAT;
        hdr.interface_id   = interface_id;
        hdr.timestamp_high = timestamp_high;
        hdr.timestamp_low  = timestamp_low;
        hdr.captured_len   = captured_len;
        hdr.original_len   = original_len;

        uint32_t padded_data_len;
        if (!pcapng_align4_safe(hdr.captured_len, &padded_data_len))
            return PCAPNG_ERR_FORMAT;

        if (padded_data_len > body_len - sizeof(hdr))
            return PCAPNG_ERR_FORMAT; /* captured_len inconsistent with total_len */

        if (hdr.captured_len > PCAPNG_MAX_PACKET)
            return PCAPNG_ERR_FORMAT; /* refuse implausibly large packets outright */

        if (!ensure_packet_capacity(r, hdr.captured_len)) return PCAPNG_ERR_NOMEM;
        if (!read_raw(r->fp, r->packet_buf, hdr.captured_len, NULL))
            return PCAPNG_ERR_FORMAT;

        /* Skip the alignment padding bytes after the packet data. */
        uint32_t pad = padded_data_len - hdr.captured_len;
        if (pad > 0 && fseek(r->fp, pad, SEEK_CUR) != 0) return PCAPNG_ERR_FORMAT;

        uint32_t options_len = body_len - (uint32_t)sizeof(hdr) - padded_data_len;
        if (options_len > 0 && fseek(r->fp, options_len, SEEK_CUR) != 0)
            return PCAPNG_ERR_FORMAT;

        /* Consume and validate the trailing repeated total_len. */
        uint32_t trailing_len;
        if (!read_u32_file(r, &trailing_len)) return PCAPNG_ERR_FORMAT;
        if (trailing_len != total_len) return PCAPNG_ERR_FORMAT;

        out_packet->interface_id   = hdr.interface_id;
        out_packet->timestamp_high = hdr.timestamp_high;
        out_packet->timestamp_low  = hdr.timestamp_low;
        out_packet->captured_len   = hdr.captured_len;
        out_packet->original_len   = hdr.original_len;
        out_packet->data           = r->packet_buf;
        *out_got_packet = 1;
        return PCAPNG_OK;
    }

    if (block_type == BLOCK_TYPE_IDB) {
        idb_body_t body;
        uint16_t link_type, reserved;
        uint32_t snaplen;
        if (body_len < sizeof(body)) return PCAPNG_ERR_FORMAT;
        if (!read_u16_file(r, &link_type)) return PCAPNG_ERR_FORMAT;
        if (!read_u16_file(r, &reserved))  return PCAPNG_ERR_FORMAT;
        if (!read_u32_file(r, &snaplen))   return PCAPNG_ERR_FORMAT;
        body.link_type = link_type;
        body.reserved  = reserved;
        body.snaplen   = snaplen;

        uint32_t options_len = body_len - (uint32_t)sizeof(body);
        char name_buf[256];  /* option_length is u16, but interface names are always short in practice */
        size_t name_len = 0;
        int have_name = 0;

        uint32_t remaining = options_len;
        while (remaining >= 4) {   /* need at least a code+length header to continue */
            uint16_t opt_code, opt_len;
            if (!read_u16_file(r, &opt_code)) return PCAPNG_ERR_FORMAT;
            if (!read_u16_file(r, &opt_len))  return PCAPNG_ERR_FORMAT;
            remaining -= 4;

            uint32_t opt_padded = pcapng_align4(opt_len);
            if (opt_padded > remaining) return PCAPNG_ERR_FORMAT; /* option overruns block */

            if (opt_code == OPT_ENDOFOPT) {
                if (opt_padded > 0 && fseek(r->fp, opt_padded, SEEK_CUR) != 0)
                    return PCAPNG_ERR_FORMAT;
                remaining -= opt_padded;
                break; /* end-of-options marker: stop scanning */
            } else if (opt_code == OPT_IF_NAME && !have_name) {
                size_t to_copy = opt_len;
                if (to_copy >= sizeof(name_buf)) to_copy = sizeof(name_buf) - 1;
                if (!read_raw(r->fp, name_buf, to_copy, NULL)) return PCAPNG_ERR_FORMAT;
                uint32_t skip = opt_padded - (uint32_t)to_copy;
                if (skip > 0 && fseek(r->fp, skip, SEEK_CUR) != 0) return PCAPNG_ERR_FORMAT;
                name_len = to_copy;
                have_name = 1;
            } else {
                /* Unknown/unneeded option: skip its (padded) value entirely. */
                if (opt_padded > 0 && fseek(r->fp, opt_padded, SEEK_CUR) != 0)
                    return PCAPNG_ERR_FORMAT;
            }
            remaining -= opt_padded;
        }

        if (remaining > 0 && fseek(r->fp, (long)remaining, SEEK_CUR) != 0)
            return PCAPNG_ERR_FORMAT;

        uint32_t trailing_len;
        if (!read_u32_file(r, &trailing_len)) return PCAPNG_ERR_FORMAT;
        if (trailing_len != total_len) return PCAPNG_ERR_FORMAT;

        if (!reader_add_interface(r, body.link_type, body.snaplen,
                                   have_name ? name_buf : NULL, name_len)) {
            return PCAPNG_ERR_NOMEM;
        }
        r->next_if_id++;
        return PCAPNG_OK;   /* consumed an IDB, not a packet */
    }

    if (body_len > 0 && fseek(r->fp, (long)body_len, SEEK_CUR) != 0)
        return PCAPNG_ERR_FORMAT;
    uint32_t trailing_len;
    if (!read_u32_file(r, &trailing_len)) return PCAPNG_ERR_FORMAT;
    if (trailing_len != total_len) return PCAPNG_ERR_FORMAT;
    return PCAPNG_OK;   /* consumed some other block type, not a packet */
}


pcapng_status_t pcapng_reader_next_packet(pcapng_reader_t *r,
                                           pcapng_packet_t *out_packet) {
    if (!r || !out_packet) return PCAPNG_ERR_INVAL;

    for (;;) {
        int got_packet = 0;
        pcapng_status_t st = read_one_block(r, out_packet, &got_packet);
        if (st != PCAPNG_OK) return st;      /* EOF or an error: stop here */
        if (got_packet) return PCAPNG_OK;    /* found a packet: hand it back */
        /* else: it was an IDB or other non-packet block; loop for more */
    }
}

void pcapng_reader_close(pcapng_reader_t *r) {
    if (!r) return;
    if (r->fp) fclose(r->fp);
    free(r->packet_buf);
    for (uint32_t i = 0; i < r->iface_count; i++) {
        free(r->ifaces[i].name);   /* each name was strdup'd/malloc'd individually */
    }
    free(r->ifaces);
    free(r);
}

uint32_t pcapng_reader_interface_count(const pcapng_reader_t *r) {
    if (!r) return 0;
    return r->iface_count;
}

pcapng_status_t pcapng_reader_get_interface(const pcapng_reader_t *r,
                                             uint32_t index,
                                             pcapng_interface_t *out_iface) {
    if (!r || !out_iface) return PCAPNG_ERR_INVAL;
    if (index >= r->iface_count) return PCAPNG_ERR_INVAL;

    const reader_iface_t *src = &r->ifaces[index];
    out_iface->link_type = src->link_type;
    out_iface->snaplen   = src->snaplen;
    out_iface->name      = src->name;   /* always non-NULL, possibly "" */
    return PCAPNG_OK;
}

const char *pcapng_strerror(pcapng_status_t status) {
    switch (status) {
        case PCAPNG_OK:              return "success";
        case PCAPNG_ERR_IO:          return "I/O error";
        case PCAPNG_ERR_FORMAT:      return "malformed pcapng data";
        case PCAPNG_ERR_EOF:         return "end of file";
        case PCAPNG_ERR_NOMEM:       return "out of memory";
        case PCAPNG_ERR_UNSUPPORTED: return "unsupported feature";
        case PCAPNG_ERR_INVAL:       return "invalid argument";
        default:                     return "unknown error";
    }
}