#ifndef __PCAP_TYPES_HPP__
#define __PCAP_TYPES_HPP__

#include <cinttypes>

#define ETHERNET_HEADER_SIZE 14

namespace domainSniffer::types
{

    struct IPHeader
    {
        std::uint8_t ver_ihl; // version and header length
        std::uint8_t tos;
        std::uint16_t tlen;
        std::uint16_t identification;
        std::uint16_t flags_fo;
        std::uint8_t ttl;
        std::uint8_t proto;
        std::uint16_t crc;
        std::uint8_t saddr[4]; // Source IP
        std::uint8_t daddr[4]; // Destination IP
    };

} // namespace domainSniffer::types

#endif // __PCAP_TYPES_HPP__