cmake_minimum_required(VERSION 3.14)
project(FoC_TSS VERSION 1.0.0 LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

# Compiler flags for safety, correctness, and security
if(CMAKE_CXX_COMPILER_ID MATCHES "GNU|Clang")
    add_compile_options(-Wall -Wextra -Wpedantic -Wconversion -Wsign-conversion -O2)
endif()

# Find OpenSSL (libssl and libcrypto)
find_package(OpenSSL REQUIRED)

# Include nlohmann_json via FetchContent
include(FetchContent)
FetchContent_Declare(
    nlohmann_json
    GIT_REPOSITORY https://github.com/nlohmann/json.git
    GIT_TAG        v3.11.3
)
FetchContent_MakeAvailable(nlohmann_json)

# Include directory
include_directories(${CMAKE_CURRENT_SOURCE_DIR}/include)

# Common unit test executable for verifying Phase 2 utilities
add_executable(test_common test/test_common.cpp)
target_link_libraries(test_common PRIVATE OpenSSL::SSL OpenSSL::Crypto nlohmann_json::nlohmann_json)

# Placeholder targets for upcoming phases (will be built as files are created)
if(EXISTS "${CMAKE_CURRENT_SOURCE_DIR}/verify/tss_verify.cpp")
    add_executable(tss_verify verify/tss_verify.cpp)
    target_link_libraries(tss_verify PRIVATE OpenSSL::Crypto nlohmann_json::nlohmann_json)
endif()

if(EXISTS "${CMAKE_CURRENT_SOURCE_DIR}/server/tss_server.cpp")
    add_executable(tss_server server/tss_server.cpp)
    target_link_libraries(tss_server PRIVATE OpenSSL::SSL OpenSSL::Crypto nlohmann_json::nlohmann_json pthread)
endif()

if(EXISTS "${CMAKE_CURRENT_SOURCE_DIR}/client/tss_client.cpp")
    add_executable(tss_client client/tss_client.cpp)
    target_link_libraries(tss_client PRIVATE OpenSSL::SSL OpenSSL::Crypto nlohmann_json::nlohmann_json)
endif()
