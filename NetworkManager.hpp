#ifndef __PCAP_NETWORKMANAGER_HPP__
#define __PCAP_NETWORKMANAGER_HPP__

#include "Sniffer.hpp"

#include <memory>
#include <string>
#include <thread>
#include <vector>

namespace domainSniffer
{

    class NetworkManager
    {
    public:
        NetworkManager();
        NetworkManager(const NetworkManager &) = delete;
        NetworkManager(NetworkManager &&) = delete;
        ~NetworkManager();

        NetworkManager &operator=(const NetworkManager &) = delete;
        NetworkManager &operator=(NetworkManager &&) = delete;

    public:
        void run();

    private:
        bool isAllowedDevice(const std::string &deviceName);

        void try_sniff_device(pcap_if_t &dev);

    private:
        std::vector<std::shared_ptr<Sniffer>> _sniffers;
        std::vector<std::thread> _threads;
        pcap_if_t *_alldevs;
    };

} // namespace domainSniffer

#endif // __PCAP_NETWORKMANAGER_HPP__