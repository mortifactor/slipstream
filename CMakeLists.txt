cmake_minimum_required(VERSION 3.13)
project(slipstream C)

set(CMAKE_C_STANDARD 23)

set(PICOQUIC_FETCH_PTLS ON)

set(DISABLE_DEBUG_PRINTF OFF)
set(ENABLE_ASAN OFF)
set(ENABLE_UBSAN OFF)
set(BUILD_DEMO OFF)
set(BUILD_HTTP OFF)
set(BUILD_LOGREADER OFF)

set(BUILD_TESTING OFF)

set(PICOQUIC_ADDITIONAL_C_FLAGS "" CACHE STRING "Additional C flags for picoquic")

if(NOT CMAKE_BUILD_TYPE)
    set(CMAKE_BUILD_TYPE "Release" CACHE STRING "Choose the type of build." FORCE)
endif()
if(${CMAKE_BUILD_TYPE} STREQUAL "Debug")
    list(APPEND PICOQUIC_ADDITIONAL_C_FLAGS -Og)
    list(APPEND PICOQUIC_ADDITIONAL_CXX_FLAGS -Og)
    list(APPEND PICOQUIC_COMPILE_DEFINITIONS BUILD_LOGLIB)
    set(BUILD_LOGLIB ON)
else()
    list(APPEND PICOQUIC_ADDITIONAL_C_FLAGS -O3)
    list(APPEND PICOQUIC_ADDITIONAL_CXX_FLAGS -O3)
    set(BUILD_LOGLIB OFF)
endif()

if(POLICY CMP0048)
    cmake_policy(SET CMP0048 NEW)
endif()
add_subdirectory(extern/picoquic)

add_executable(slipstream
        src/slipstream.c
        src/slipstream_client.c
        src/slipstream_inline_dots.c
        src/slipstream_resolver_addresses.c
        src/slipstream_server.c
        src/slipstream_server_cc.c
        src/slipstream_sockloop.c
        src/slipstream_utils.c
        include/slipstream.h
        include/slipstream_inline_dots.h
        include/slipstream_resolver_addresses.h
        include/slipstream_server_cc.h
        include/slipstream_slot.h
        include/slipstream_sockloop.h
        include/slipstream_utils.h

        extern/lua-resty-base-encoding/b32_data.h
        extern/lua-resty-base-encoding/base32.c
        extern/lua-resty-base-encoding/modp_stdint.h
        include/lua-resty-base-encoding-base32.h

        extern/SPCDNS/src/dns.h
        extern/SPCDNS/src/codec.c
        extern/SPCDNS/src/mappings.c
        extern/SPCDNS/src/mappings.h
        extern/SPCDNS/src/netsimple.c
        extern/SPCDNS/src/netsimple.h
        extern/SPCDNS/src/output.c
        extern/SPCDNS/src/output.h
)
target_link_libraries(slipstream PRIVATE m)
target_link_libraries(slipstream PRIVATE picoquic-core)
if (BUILD_LOGLIB)
    target_link_libraries(slipstream PRIVATE picoquic-log)
endif ()

target_include_directories(slipstream PRIVATE include)
target_include_directories(slipstream PRIVATE extern)

set_picoquic_compile_settings(slipstream)
