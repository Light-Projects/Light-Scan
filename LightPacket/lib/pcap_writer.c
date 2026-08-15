#include <stdio.h>
#include <time.h>
#include "pcap_writer.h"

int create_pcap_file(const char *filename, const PcapPacketData *packetarr, int totalpackets) {
    if (filename == NULL || totalpackets < 0) return 1;
    if (totalpackets > 0 && packetarr == NULL) return 1;

    time_t current_time = time(NULL);
    if (current_time == (time_t)-1) return 1;

    PcapHeader header;
    header.magic = PCAP_MAGIC_NSEC;
    header.majorversion = PCAP_VERSION_MAJOR;
    header.minorversion = PCAP_VERSION_MINOR;
    header.reserved1 = 0;
    header.reserved2 = 0;
    header.snaplen = PCAP_SNAPLEN;
    header.linktype = PCAP_LINKTYPE_ETHERNET;

    FILE *filePtr = fopen(filename, "wb");
    if (filePtr == NULL) return 1;

    if (fwrite(&header, sizeof header, 1, filePtr) != 1) {
        fclose(filePtr);
        return 1;
    }

    for (int i = 0; i < totalpackets; i++) {
        uint32_t captured = packetarr[i].data_length;

        if (captured != 0 && packetarr[i].payload == NULL) {
            fclose(filePtr);
            return 1;
        }

        if (captured > PCAP_SNAPLEN) captured = PCAP_SNAPLEN;

        PcapPacketHeader pkt_header;
        pkt_header.timestampS = (uint32_t)(current_time);
        pkt_header.timestampNorM = 0;
        pkt_header.cpacketlen = captured;
        pkt_header.opacketlen = packetarr[i].data_length;

        if (fwrite(&pkt_header, sizeof pkt_header, 1, filePtr) != 1) {
            fclose(filePtr);
            return 1;
        }

        if (captured != 0 && fwrite(packetarr[i].payload, 1, captured, filePtr) != captured) {
            fclose(filePtr);
            return 1;
        }
    }


    if (fclose(filePtr) != 0) return 1;

    return 0;
}
