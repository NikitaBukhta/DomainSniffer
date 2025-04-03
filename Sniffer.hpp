#ifndef __PCAP_SNIFFER_HPP__
#define __PCAP_SNIFFER_HPP__

#include <types.hpp>

#include <pcap.h>

#include <iostream>
#include <string>
#include <vector>

namespace domainSniffer
{

    class Sniffer
    {
    public:
        Sniffer(pcap_if_t &device);
        Sniffer(const Sniffer &) = delete;
        ~Sniffer();

        Sniffer &operator=(const Sniffer &) = delete;

        bool init();
        void deinit();
        void run();

    private:
        void setUpFilter();

        static void packetHandler(u_char *param, const struct pcap_pkthdr *header, const u_char *pkt_data);
        static bool isIPBelongToDomain(const std::string &ipAddress, const std::string &domainName);

    private:
        pcap_if_t &_device;
        pcap_t *_deviceHandler;
        static const std::vector<std::string> _allowedDomains;

    }; // class Sniffer

} // namespace domainSniffer

#endif // __PCAP_SNIFFER_HPP__