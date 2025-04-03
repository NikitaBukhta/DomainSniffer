// #include <pcap.h>
// #include <winsock2.h>
// #include <ws2tcpip.h>

// #include <stdio.h>
// #include <stdlib.h>

// #include <algorithm>
// #include <climits>
// #include <iostream>
// #include <string>
// #include <thread>
// #include <vector>

#include "NetworkManager.hpp"

#pragma comment(lib, "Ws2_32.lib")

int main()
{
    domainSniffer::NetworkManager networkManager;
    networkManager.run();
    // runPcap();

    return 0;
}
