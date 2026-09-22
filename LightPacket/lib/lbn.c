// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.


#include "lbn.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <zlib.h>

#define LBN_MAGIC "LBN\x00"
#define LBN_VERSION 1
#define LBN_FLAG_COMPRESSED 0x01
#define LBN_FLAG_NONE       0x00

static inline void write_u32(uint8_t *buf, uint32_t val) {
    buf[0] = (val >> 0) & 0xFF;
    buf[1] = (val >> 8) & 0xFF;
    buf[2] = (val >> 16) & 0xFF;
    buf[3] = (val >> 24) & 0xFF;
}

static inline uint32_t read_u32(const uint8_t *buf) {
    return (uint32_t)buf[0] << 0 | (uint32_t)buf[1] << 8 |
           (uint32_t)buf[2] << 16 | (uint32_t)buf[3] << 24;
}

static uint32_t lbn_checksum(uint32_t version, uint32_t created,
                             uint32_t count, uint32_t flags) {
    uint8_t buf[16];
    write_u32(buf + 0, version);
    write_u32(buf + 4, created);
    write_u32(buf + 8, count);
    write_u32(buf + 12, flags);
    return crc32(0L, buf, 16);
}

LBN_API int lbn_save(const char *filename,
                     const unsigned char **packets,
                     const size_t *sizes,
                     size_t count,
                     int compress) {
    FILE *f = fopen(filename, "wb");
    if (!f) return -1;

    uint32_t created = (uint32_t)time(NULL);
    uint32_t flags = compress ? LBN_FLAG_COMPRESSED : LBN_FLAG_NONE;
    uint32_t packet_count = (uint32_t)count;
    uint32_t chksum = lbn_checksum(LBN_VERSION, created, packet_count, flags);

    fwrite(LBN_MAGIC, 1, 4, f);
    uint8_t hdr[20];
    write_u32(hdr + 0, LBN_VERSION);
    write_u32(hdr + 4, created);
    write_u32(hdr + 8, packet_count);
    write_u32(hdr + 12, flags);
    write_u32(hdr + 16, chksum);
    fwrite(hdr, 1, 20, f);

    for (size_t i = 0; i < count; i++) {
        double ts = (double)time(NULL);
        fwrite(&ts, sizeof(ts), 1, f);

        unsigned char *out_data = NULL;
        uint32_t out_len = 0;

        if (compress) {
            uLongf dest_len = compressBound((uLong)sizes[i]);
            out_data = malloc(dest_len);
            if (!out_data) { fclose(f); return -1; }
            if (compress2(out_data, &dest_len, packets[i], (uLong)sizes[i], 6) != Z_OK) {
                free(out_data); fclose(f); return -1;
            }
            out_len = (uint32_t)dest_len;
        } else {
            out_data = (unsigned char *)packets[i];
            out_len = (uint32_t)sizes[i];
        }

        uint8_t len_buf[4];
        write_u32(len_buf, out_len);
        fwrite(len_buf, 1, 4, f);
        fwrite(out_data, 1, out_len, f);

        if (compress) free(out_data);
    }

    fclose(f);
    return 0;
}

LBN_API int lbn_load(const char *filename,
                     unsigned char ***packets,
                     size_t **sizes,
                     size_t *packet_count) {
    FILE *f = fopen(filename, "rb");
    if (!f) return -1;

    char magic[4];
    if (fread(magic, 1, 4, f) != 4) { fclose(f); return -1; }
    if (memcmp(magic, LBN_MAGIC, 4) != 0) { fclose(f); return -1; }

    uint8_t hdr[20];
    if (fread(hdr, 1, 20, f) != 20) { fclose(f); return -1; }
    uint32_t version    = read_u32(hdr + 0);
    uint32_t created    = read_u32(hdr + 4);
    uint32_t count      = read_u32(hdr + 8);
    uint32_t flags      = read_u32(hdr + 12);
    uint32_t stored_crc = read_u32(hdr + 16);

    uint32_t calc_crc = lbn_checksum(version, created, count, flags);
    if (calc_crc != stored_crc) {
        fprintf(stderr, "LightBin: checksum mismatch\n");
        fclose(f);
        return -1;
    }

    int compressed = (flags & LBN_FLAG_COMPRESSED) != 0;

    unsigned char **pkt_arr = malloc(count * sizeof(unsigned char *));
    size_t *size_arr = malloc(count * sizeof(size_t));
    if (!pkt_arr || !size_arr) {
        free(pkt_arr); free(size_arr);
        fclose(f);
        return -1;
    }

    size_t loaded = 0;
    for (uint32_t i = 0; i < count; i++) {
        double ts;
        if (fread(&ts, sizeof(ts), 1, f) != 1) break;

        uint8_t len_buf[4];
        if (fread(len_buf, 1, 4, f) != 4) break;
        uint32_t data_len = read_u32(len_buf);

        unsigned char *data = malloc(data_len);
        if (!data) break;
        if (fread(data, 1, data_len, f) != data_len) {
            free(data);
            break;
        }

        if (compressed) {
            uLongf dest_len = data_len * 4;
            unsigned char *decomp = malloc(dest_len);
            if (!decomp) { free(data); break; }
            int ret = uncompress(decomp, &dest_len, data, data_len);
            free(data);
            if (ret != Z_OK) {
                free(decomp);
                fprintf(stderr, "LightBin: decompression error at packet %u\n", i);
                break;
            }
            pkt_arr[loaded] = decomp;
            size_arr[loaded] = (size_t)dest_len;
        } else {
            pkt_arr[loaded] = data;
            size_arr[loaded] = (size_t)data_len;
        }
        loaded++;
    }

    *packets = pkt_arr;
    *sizes = size_arr;
    *packet_count = loaded;

    fclose(f);
    return 0;
}

LBN_API void lbn_free_packets(unsigned char **packets,
                              size_t *sizes,
                              size_t count) {
    (void)sizes;
    for (size_t i = 0; i < count; i++) {
        if (packets[i]) free(packets[i]);
    }
    free(packets);
    free(sizes);
}