#----------------------------- CREATE LIBRARY -----------------------------#

cmake_minimum_required(VERSION 3.16.0)
set(LIB_NAME libnpcap)

add_library(
    ${LIB_NAME}
    INTERFACE
)

target_include_directories(
    ${LIB_NAME}
    INTERFACE
    include
)

set(NPCAP_LIB_DIR ${CMAKE_CURRENT_SOURCE_DIR}/Lib)

# Приводим к нижнему регистру
string(TOLOWER "${CMAKE_SYSTEM_PROCESSOR}" ARCH_LOWER)

# Проверка архитектуры
if(ARCH_LOWER MATCHES "^(x86|i[3-6]86)$") 
    message(STATUS "32-bit architecture detected (x86)")
elseif(ARCH_LOWER MATCHES "^(x86_64|amd64)$")
    message(STATUS "64-bit architecture detected (x64)")
    set(NPCAP_LIB_DIR "${NPCAP_LIB_DIR}/x64")
elseif(ARCH_LOWER MATCHES "^aarch64$")
    message(STATUS "ARM64 architecture detected")
    set(NPCAP_LIB_DIR "${NPCAP_LIB_DIR}/ARM64")
else()
    message(WARNING "Unknown architecture: ${CMAKE_SYSTEM_PROCESSOR}")
endif()

target_link_libraries(
	${LIB_NAME} 
	INTERFACE 
	${NPCAP_LIB_DIR}/Packet.lib
    ${NPCAP_LIB_DIR}/wpcap.lib
)