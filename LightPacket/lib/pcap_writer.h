#ifndef PCAP_WRITER_H
#define PCAP_WRITER_H


#include <stdint.h>


#define PCAP_MAGIC_USEC 0xA1B2C3D4u
#define PCAP_MAGIC_NSEC 0xA1B23C4Du

#define PCAP_VERSION_MAJOR 2
#define PCAP_VERSION_MINOR 4

#define PCAP_SNAPLEN 65535u
#define PCAP_LINKTYPE_ETHERNET 1u

typedef struct {
    uint32_t magic;
    uint16_t majorversion;
    uint16_t minorversion;
    uint32_t reserved1;
    uint32_t reserved2;
    uint32_t snaplen;
    uint32_t linktype;
} PcapHeader;

typedef struct {
    uint32_t timestampS;
    uint32_t timestampNorM;
    uint32_t cpacketlen;
    uint32_t opacketlen;
} PcapPacketHeader;

typedef struct {
    uint32_t data_length;
    uint8_t *payload;
} PcapPacketData;


#if defined(__STDC_VERSION__) && __STDC_VERSION__ >= 201112L
_Static_assert(sizeof(PcapHeader) == 24, "PcapHeader must be exactly 24 bytes");
_Static_assert(sizeof(PcapPacketHeader) == 16, "PcapPacketHeader must be exactly 16 bytes");
#endif

int create_pcap_file(const char *filename, const PcapPacketData *packetarr, int totalpackets);

#endif
