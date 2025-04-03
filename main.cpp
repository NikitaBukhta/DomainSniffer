#include <pcap.h>
#include <winsock2.h>
#include <ws2tcpip.h>

#include <stdio.h>
#include <stdlib.h>

#include <algorithm>
#include <climits>
#include <iostream>
#include <string>
#include <thread>
#include <vector>

#pragma comment(lib, "Ws2_32.lib")

#define ETHERNET_HEADER_SIZE 14

struct ip_header
{
    u_char ver_ihl; // version and header length
    u_char tos;
    u_short tlen;
    u_short identification;
    u_short flags_fo;
    u_char ttl;
    u_char proto;
    u_short crc;
    u_char saddr[4]; // Source IP
    u_char daddr[4]; // Destination IP
};

class Sniffer
{
public:
    Sniffer(pcap_if_t &device) : _device{device}
    {
        printf("Using adapter: %s\n", device.name);
        if (device.description)
            printf("Description: %s\n", device.description);
    }

    Sniffer(const Sniffer &) = delete;
    Sniffer &operator=(const Sniffer &) = delete;

    ~Sniffer()
    {
        deinit();
    }

    bool init()
    {
        char errbuf[PCAP_ERRBUF_SIZE];

        _deviceHandler = pcap_open(_device.name, USHRT_MAX, PCAP_OPENFLAG_PROMISCUOUS, 1000, NULL, errbuf);
        if (!_deviceHandler)
        {
            std::cerr << "Unable to open the adapter. " << _device.name << ". Error: " << errbuf << std::endl;
            return false;
        }

        setUpFilter();
    }

    void deinit()
    {
        if (_deviceHandler)
        {
            pcap_close(_deviceHandler);
            _deviceHandler = nullptr;
        }
    }

    void run()
    {
        std::cout << "Listening for TCP/UDP packets..." << std::endl
                  << std::endl;

        pcap_loop(_deviceHandler, 0, Sniffer::packetHandler, NULL);
    }

private:
    void setUpFilter()
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

    static void packetHandler(u_char *param, const struct pcap_pkthdr *header, const u_char *pkt_data)
    {
        // Проверка: это ли IP-пакет?
        if (pkt_data[12] != 0x08 || pkt_data[13] != 0x00)
            return; // не IPv4

        struct ip_header *ih = (struct ip_header *)(pkt_data + ETHERNET_HEADER_SIZE);

        in_addr addr;
        memcpy(&addr, ih->saddr, sizeof(in_addr));
        char *ip_str = inet_ntoa(addr);

        for (const auto &domainName : _allowedDomains)
        {
            if (isIPBelongToDomain(ip_str, "music.youtube.com"))
            {
                std::cout << "Detected IP: " << ip_str << std::endl;
                std::cout << "Domain: " << domainName << std::endl;
                std::cout << "Protocol: " << ((ih->proto == 6) ? "TCP" : "UDP") << std::endl;

                break;
            }
        }
    }

    static bool isIPBelongToDomain(const std::string &ipAddress, const std::string &domainName)
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

private:
    pcap_if_t &_device;
    pcap_t *_deviceHandler;
    static const std::vector<std::string> _allowedDomains;
}; // class Sniffer

const std::vector<std::string> Sniffer::_allowedDomains = {"youtube.com"};

class NetworkManager
{
public:
    NetworkManager()
    {
        char errbuf[PCAP_ERRBUF_SIZE];
        if (pcap_findalldevs(&_alldevs, errbuf) == -1)
        {
            fprintf(stderr, "Error in pcap_findalldevs: %s\n", errbuf);
            return;
        }
    }

    NetworkManager(const NetworkManager &) = delete;
    NetworkManager(NetworkManager &&) = delete;

    NetworkManager &operator=(const NetworkManager &) = delete;
    NetworkManager &operator=(NetworkManager &&) = delete;

    ~NetworkManager()
    {
        for (auto &t : _threads)
        {
            if (t.joinable())
                t.join();
        }

        if (_alldevs)
        {
            pcap_freealldevs(_alldevs);
            _alldevs = nullptr;
        }
    }

public:
    void run()
    {
        if (_alldevs)
        {
            for (auto dev = _alldevs; dev != NULL; dev = dev->next)
            {
                try_sniff_device(*dev);
            }
        }
    };

private:
    bool isAllowedDevice(const std::string &deviceName)
    {
        std::string deviceNameLower;
        deviceNameLower.resize(deviceName.size());
        std::transform(deviceName.begin(), deviceName.end(), deviceNameLower.begin(),
                       [](unsigned char c)
                       { return std::tolower(c); });

        bool isVirtual = deviceNameLower.find("miniport") != std::string::npos ||
                         deviceNameLower.find("virtual") != std::string::npos ||
                         deviceNameLower.find("vmware") != std::string::npos ||
                         deviceNameLower.find("hyper-v") != std::string::npos ||
                         deviceNameLower.find("virtualbox") != std::string::npos ||
                         deviceNameLower.find("parallels") != std::string::npos;

        return !isVirtual && (deviceNameLower.find("ethernet") != std::string::npos ||
                              deviceNameLower.find("wi-fi") != std::string::npos ||
                              deviceNameLower.find("wireless") != std::string::npos ||
                              deviceNameLower.find("802.11") != std::string::npos ||
                              deviceNameLower.find("lan") != std::string::npos);
    }

    void try_sniff_device(pcap_if_t &dev)
    {
        std::cout << "Try description: " << dev.description << std::endl;
        if (isAllowedDevice(dev.description))
        {
            _sniffers.push_back(std::make_shared<Sniffer>(dev));
            if (_sniffers.back()->init())
            {
                _threads.push_back(std::thread(&Sniffer::run, _sniffers.back().get()));
            }
            else
            {
                std::cerr << "Failed to initialize sniffer for device: " << dev.name << std::endl;
            }
        }
    }

private:
    std::vector<std::shared_ptr<Sniffer>> _sniffers;
    std::vector<std::thread> _threads;
    pcap_if_t *_alldevs;
};

int main()
{
    NetworkManager networkManager;
    networkManager.run();
    // runPcap();

    return 0;
}
