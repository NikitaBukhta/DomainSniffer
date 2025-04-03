#include "NetworkManager.hpp"

#include <algorithm>

namespace domainSniffer
{

    NetworkManager::NetworkManager()
    {
        char errbuf[PCAP_ERRBUF_SIZE];
        if (pcap_findalldevs(&_alldevs, errbuf) == -1)
        {
            fprintf(stderr, "Error in pcap_findalldevs: %s\n", errbuf);
            return;
        }
    }

    NetworkManager::~NetworkManager()
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

    void NetworkManager::run()
    {
        if (_alldevs)
        {
            for (auto dev = _alldevs; dev != NULL; dev = dev->next)
            {
                try_sniff_device(*dev);
            }
        }
    };

    bool NetworkManager::isAllowedDevice(const std::string &deviceName)
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

    void NetworkManager::try_sniff_device(pcap_if_t &dev)
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

} // namespace domainSniffer"