cmake_minimum_required(VERSION 3.21)
project(tau5_discovery)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_POSITION_INDEPENDENT_CODE ON)

# Find ASIO headers
find_path(ASIO_INCLUDE_DIR
    NAMES asio.hpp
    PATHS
        /usr/include
        /usr/local/include
        ${CMAKE_CURRENT_SOURCE_DIR}/external_libs/asio-standalone/asio/include
    NO_DEFAULT_PATH
)

if(NOT ASIO_INCLUDE_DIR)
    message(FATAL_ERROR "ASIO not found. Please install ASIO or check external_libs/asio-standalone/asio/include")
endif()

# Create ASIO target (following Ableton Link pattern)
add_library(AsioStandalone::AsioStandalone IMPORTED INTERFACE)
set_property(TARGET AsioStandalone::AsioStandalone APPEND PROPERTY
    INTERFACE_INCLUDE_DIRECTORIES ${ASIO_INCLUDE_DIR}
)
set_property(TARGET AsioStandalone::AsioStandalone APPEND PROPERTY
    INTERFACE_COMPILE_DEFINITIONS
    ASIO_STANDALONE
    ASIO_HAS_STD_CHRONO
    ASIO_HAS_STD_THREAD
    ASIO_HAS_STD_MUTEX
    ASIO_HAS_STD_CONDITION_VARIABLE
)

# Include directories
include_directories(${CMAKE_SOURCE_DIR}/include)

# Source files
set(SOURCES
    src/tau5_discovery.cpp
    src/tau5_discovery_impl.cpp
)

# Platform-specific configurations
if(WIN32)
    set(ERLANG_INCLUDE_PATH ${CMAKE_CURRENT_SOURCE_DIR}/external_libs/erlang_headers/win_x86_64 CACHE STRING "Erlang headers for Windows")
    include_directories(${ERLANG_INCLUDE_PATH})
    # Windows socket libraries + IP Helper API for interface scanning
    set(PLATFORM_LIBS ws2_32 iphlpapi)
    # Additional Windows defines for ASIO
    add_definitions(-D_WIN32_WINNT=0x0601)

elseif(APPLE)
    if(CMAKE_SYSTEM_PROCESSOR STREQUAL "arm64")
        set(ERLANG_INCLUDE_PATH ${CMAKE_CURRENT_SOURCE_DIR}/external_libs/erlang_headers/mac_arm64 CACHE STRING "Erlang headers for Apple Silicon")
    else()
        set(ERLANG_INCLUDE_PATH ${CMAKE_CURRENT_SOURCE_DIR}/external_libs/erlang_headers/mac_x86_64 CACHE STRING "Erlang headers for Intel Macs")
    endif()
    include_directories(${ERLANG_INCLUDE_PATH})

    # Better macOS linker flags for NIF - avoid flat_namespace
    set(CMAKE_SHARED_LINKER_FLAGS "${CMAKE_SHARED_LINKER_FLAGS} -undefined dynamic_lookup")
    # No additional libraries needed for BSD sockets on macOS
    set(PLATFORM_LIBS "")

elseif(UNIX)
    set(ERLANG_INCLUDE_PATH ${CMAKE_CURRENT_SOURCE_DIR}/external_libs/erlang_headers/linux_x86_64 CACHE STRING "Erlang headers for Linux")
    include_directories(${ERLANG_INCLUDE_PATH})
    # No additional libraries needed for BSD sockets on Linux
    set(PLATFORM_LIBS "")
endif()

# Create the shared library
add_library(libtau5_discovery SHARED ${SOURCES})
set_target_properties(libtau5_discovery PROPERTIES PREFIX "")

# Link ASIO and platform-specific libraries
target_link_libraries(libtau5_discovery AsioStandalone::AsioStandalone ${PLATFORM_LIBS})

# Threading support (required for std::thread)
find_package(Threads REQUIRED)
target_link_libraries(libtau5_discovery Threads::Threads)

# Installation
if(APPLE)
    install(PROGRAMS ${CMAKE_CURRENT_BINARY_DIR}/libtau5_discovery.dylib
            DESTINATION ${CMAKE_INSTALL_PREFIX}
            RENAME libtau5_discovery.so)
elseif(MSVC)
    install(TARGETS libtau5_discovery
            RUNTIME DESTINATION ${CMAKE_INSTALL_PREFIX})
else()
    install(TARGETS libtau5_discovery
            LIBRARY DESTINATION ${CMAKE_INSTALL_PREFIX})
endif()

# Optional: Add compiler-specific optimizations and warnings
if(CMAKE_CXX_COMPILER_ID STREQUAL "GNU" OR CMAKE_CXX_COMPILER_ID STREQUAL "Clang")
    target_compile_options(libtau5_discovery PRIVATE
        -Wall -Wextra -Wpedantic
    )
    # Add optimization for Release builds only
    if(CMAKE_BUILD_TYPE STREQUAL "Release")
        target_compile_options(libtau5_discovery PRIVATE -O2)
    endif()
elseif(MSVC)
    target_compile_options(libtau5_discovery PRIVATE
        /W4
    )
    # Add optimization for Release builds only
    if(CMAKE_BUILD_TYPE STREQUAL "Release")
        target_compile_options(libtau5_discovery PRIVATE /O2)
    endif()
endif()

# Debug configuration
if(CMAKE_BUILD_TYPE STREQUAL "Debug")
    target_compile_definitions(libtau5_discovery PRIVATE DEBUG=1)
    if(CMAKE_CXX_COMPILER_ID STREQUAL "GNU" OR CMAKE_CXX_COMPILER_ID STREQUAL "Clang")
        target_compile_options(libtau5_discovery PRIVATE -g -O0)
    elseif(MSVC)
        target_compile_options(libtau5_discovery PRIVATE /Od /Zi)
    endif()
endif()

# Print configuration
message(STATUS "TAU5 Discovery Configuration:")
message(STATUS "  ASIO Include: ${ASIO_INCLUDE_DIR}")
message(STATUS "  Erlang Path:  ${ERLANG_INCLUDE_PATH}")
message(STATUS "  Build Type:   ${CMAKE_BUILD_TYPE}")
message(STATUS "  Platform Libs: ${PLATFORM_LIBS}")