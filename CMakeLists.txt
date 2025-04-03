#--------------------------- MAIN CONFIGURATION ---------------------------#

cmake_minimum_required(VERSION 3.16.0)
set(PROJECT_NAME pcap_test)
project(${PROJECT_NAME})

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED 17)

set(
    ADDITIONAL_SOURCES
    NetworkManager.cpp
    Sniffer.cpp
)

add_executable(
    ${PROJECT_NAME}
    main.cpp
    ${ADDITIONAL_SOURCES}
)

target_include_directories(
    ${PROJECT_NAME}
    PRIVATE
    ${CMAKE_CURRENT_SOURCE_DIR}
)

#----------------------------- LINK LIBRARIES -----------------------------#

add_subdirectory(npcap)

set(
    ALL_LIBS
    libnpcap
)

target_link_libraries(
    ${PROJECT_NAME}
    ${ALL_LIBS}
)