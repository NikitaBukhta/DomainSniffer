#include "Sniffer.hpp"

namespace domainSniffer
{
    const std::vector<std::string> Sniffer::_allowedDomains = {"youtube.com"};

    Sniffer::Sniffer(pcap_if_t &device) : _device{device}
    {
        printf("Using adapter: %s\n", device.name);
        if (device.description)
            printf("Description: %s\n", device.description);
    }

    Sniffer::~Sniffer()
    {
        deinit();
    }

    bool Sniffer::init()
    {
        char errbuf[PCAP_ERRBUF_SIZE];

        _deviceHandler = pcap_open(_device.name, USHRT_MAX, PCAP_OPENFLAG_PROMISCUOUS, 1000, NULL, errbuf);
        if (!_deviceHandler)
        {
            std::cerr << "Unable to open the adapter. " << _device.name << ". Error: " << errbuf << std::endl;
            return false;
        }

        setUpFilter();

        return true;
    }

    void Sniffer::deinit()
    {
        if (_deviceHandler)
        {
            pcap_close(_deviceHandler);
            _deviceHandler = nullptr;
        }
    }

    void Sniffer::run()
    {
        std::cout << "Listening for TCP/UDP packets..." << std::endl
                  << std::endl;

        pcap_loop(_deviceHandler, 0, Sniffer::packetHandler, NULL);
    }

    void Sniffer::setUpFilter()
    {
        // Filter for TCOP or UDP packets
        struct bpf_program fcode;
        if (pcap_compile(_deviceHandler, &fcode, "tcp or udp", 1, PCAP_NETMASK_UNKNOWN) >= 0)
        {
            if (pcap_setfilter(_deviceHandler, &fcode) < 0)
            {
                std::cerr << "Error setting the filter" << std::endl;
                deinit();
                return;
            }
        }
        else
        {
            std::cerr << "Unable to compile filter\n";
            deinit();
        }
    }

    void Sniffer::packetHandler(u_char *param, const struct pcap_pkthdr *header, const u_char *pkt_data)
    {
        // Проверка: это ли IP-пакет?
        if (pkt_data[12] != 0x08 || pkt_data[13] != 0x00)
            return; // не IPv4

        struct types::IPHeader *ih = (struct types::IPHeader *)(pkt_data + ETHERNET_HEADER_SIZE);

        in_addr addr;
        std::memcpy(&addr, ih->saddr, sizeof(in_addr));
        char *ip_str = inet_ntoa(addr);

        for (const auto &domainName : _allowedDomains)
        {
            if (isIPBelongToDomain(ip_str, domainName))
            {
                std::cout << "Detected IP: " << ip_str << std::endl;
                std::cout << "Domain: " << domainName << std::endl;
                std::cout << "Protocol: " << ((ih->proto == 6) ? "TCP" : "UDP") << std::endl;

                break;
            }
        }
    }

    bool Sniffer::isIPBelongToDomain(const std::string &ipAddress, const std::string &domainName)
    {
        WSADATA wsaData;
        if (WSAStartup(MAKEWORD(2, 2), &wsaData) != 0)
        {
            std::cerr << "WSAStartup failed.\n";
            return false;
        }

        addrinfo hints = {}, *res = nullptr;
        hints.ai_family = AF_INET; // IPv4
        hints.ai_socktype = SOCK_STREAM;

        if (getaddrinfo(domainName.c_str(), nullptr, &hints, &res) != 0)
        {
            std::cerr << "Failed to resolve domain: " << domainName << "\n";
            WSACleanup();
            return false;
        }

        sockaddr_in input_ip;
        inet_pton(AF_INET, ipAddress.c_str(), &(input_ip.sin_addr));

        bool found = false;
        for (addrinfo *ptr = res; ptr != nullptr; ptr = ptr->ai_next)
        {
            sockaddr_in *addr = reinterpret_cast<sockaddr_in *>(ptr->ai_addr);
            if (addr->sin_addr.S_un.S_addr == input_ip.sin_addr.S_un.S_addr)
            {
                found = true;
                break;
            }
        }

        freeaddrinfo(res);
        WSACleanup();
        return found;
    }

} // namespace domainSniffer"