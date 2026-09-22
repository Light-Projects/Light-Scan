// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.



#ifndef LBN_H
#define LBN_H

#include <stdint.h>
#include <stddef.h>

#ifdef _WIN32
    #ifdef LBN_EXPORT
        #define LBN_API __declspec(dllexport)
    #else
        #define LBN_API __declspec(dllimport)
    #endif
#else
    #define LBN_API __attribute__((visibility("default")))
#endif

#ifdef __cplusplus
extern "C" {
#endif

LBN_API int lbn_save(const char *filename,const unsigned char **packets,const size_t *sizes,size_t count,int compress);
LBN_API int lbn_load(const char *filename,unsigned char ***packets,size_t **sizes,size_t *packet_count);
LBN_API void lbn_free_packets(unsigned char **packets,size_t *sizes,size_t count);

#ifdef __cplusplus
}
#endif

#endif