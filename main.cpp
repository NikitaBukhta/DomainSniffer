#include "NetworkManager.hpp"

int main()
{
    domainSniffer::NetworkManager networkManager;
    networkManager.run();
    // runPcap();

    return 0;
}
