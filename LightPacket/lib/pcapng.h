// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

#ifndef PCAPNG_H
#define PCAPNG_H

#include <stdint.h>
#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

#if defined(_WIN32) || defined(__CYGWIN__)
  #ifdef PCAPNG_BUILD_DLL
    #define PCAPNG_API __declspec(dllexport)
  #else
    #define PCAPNG_API __declspec(dllimport)
  #endif
#else
  #define PCAPNG_API __attribute__((visibility("default")))
#endif


typedef enum {
    PCAPNG_OK               = 0,
    PCAPNG_ERR_IO           = -1,
    PCAPNG_ERR_FORMAT       = -2,
    PCAPNG_ERR_EOF          = -3,
    PCAPNG_ERR_NOMEM        = -4,
    PCAPNG_ERR_UNSUPPORTED  = -5,
    PCAPNG_ERR_INVAL        = -6
} pcapng_status_t;

typedef struct pcapng_writer pcapng_writer_t;
typedef struct pcapng_reader pcapng_reader_t;

typedef struct pcapng_packet {
    uint32_t interface_id;
    uint32_t timestamp_high;
    uint32_t timestamp_low;
    uint32_t captured_len;
    uint32_t original_len;
    const uint8_t *data;
} pcapng_packet_t;

typedef struct pcapng_interface {
    uint16_t link_type;
    uint32_t snaplen;
    const char *name;
} pcapng_interface_t;


PCAPNG_API pcapng_writer_t *pcapng_writer_open(const char *path);

PCAPNG_API int pcapng_writer_add_interface(pcapng_writer_t *w,
                                            uint16_t link_type,
                                            uint32_t snaplen,
                                            const char *if_name);

PCAPNG_API pcapng_status_t pcapng_writer_write_packet(pcapng_writer_t *w,
                                                       uint32_t interface_id,
                                                       uint64_t ts_usecs,
                                                       const uint8_t *data,
                                                       uint32_t length);

PCAPNG_API void pcapng_writer_close(pcapng_writer_t *w);

PCAPNG_API pcapng_reader_t *pcapng_reader_open(const char *path);

PCAPNG_API pcapng_status_t pcapng_reader_next_packet(pcapng_reader_t *r,
                                                      pcapng_packet_t *out_packet);

PCAPNG_API uint32_t pcapng_reader_interface_count(const pcapng_reader_t *r);

PCAPNG_API pcapng_status_t pcapng_reader_get_interface(const pcapng_reader_t *r,
                                                        uint32_t index,
                                                        pcapng_interface_t *out_iface);

PCAPNG_API void pcapng_reader_close(pcapng_reader_t *r);

PCAPNG_API const char *pcapng_strerror(pcapng_status_t status);

#ifdef __cplusplus
}
#endif

#endif /* PCAPNG_H */