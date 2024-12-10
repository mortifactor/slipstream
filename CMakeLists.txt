cmake_minimum_required(VERSION 3.30)
project(slipstream C)

set(CMAKE_C_STANDARD 23)

find_package(Git QUIET)
if(GIT_FOUND AND EXISTS "${PROJECT_SOURCE_DIR}/.git")
    option(GIT_SUBMODULE "Check submodules during build" ON)
    if(GIT_SUBMODULE)
        execute_process(COMMAND ${GIT_EXECUTABLE} submodule update --init --recursive
                WORKING_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}
                RESULT_VARIABLE GIT_SUBMOD_RESULT)
        if(NOT GIT_SUBMOD_RESULT EQUAL "0")
            message(FATAL_ERROR "git submodule update --init --recursive failed")
        endif()
    endif()
endif()

set(PICOQUIC_FETCH_PTLS Y)
add_subdirectory(extern/picoquic)

if(CMAKE_BUILD_TYPE STREQUAL "Debug")
    list(APPEND PICOQUIC_ADDITIONAL_C_FLAGS -g -Og)
else()
    list(APPEND PICOQUIC_ADDITIONAL_C_FLAGS -O3)
endif ()

add_executable(slipstream
        src/slipstream.c
        src/slipstream_client.c
        src/slipstream_server.c
        src/slipstream_server_circular_query_buffer.c
        src/slipstream_inline_dots.c
        include/slipstream.h
        include/slipstream_server_circular_query_buffer.h
        include/slipstream_inline_dots.h

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
target_link_libraries(slipstream PRIVATE picoquic-log picoquic-core)

target_include_directories(slipstream PRIVATE include)
target_include_directories(slipstream PRIVATE extern)

set_picoquic_compile_settings(slipstream)
