cmake_minimum_required(VERSION 3.24)
project(vehicle_network_security_lab VERSION 0.1.0 LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)
set(CMAKE_EXPORT_COMPILE_COMMANDS ON)

option(VNSL_BUILD_TESTS "Build unit tests" ON)
option(VNSL_SANITIZE "Build with AddressSanitizer and UndefinedBehaviorSanitizer" OFF)
option(VNSL_BUILD_FUZZERS "Build libFuzzer targets (requires Clang)" OFF)
option(VNSL_WARNINGS_AS_ERRORS "Treat compiler warnings as errors" OFF)

include(FetchContent)

add_library(vnsl_warnings INTERFACE)
target_compile_options(vnsl_warnings INTERFACE
  -Wall -Wextra -Wpedantic -Wshadow -Wconversion -Wsign-conversion -Wnon-virtual-dtor
  $<$<BOOL:${VNSL_WARNINGS_AS_ERRORS}>:-Werror>)

if(VNSL_SANITIZE)
  add_compile_options(-fsanitize=address,undefined -fno-omit-frame-pointer -fno-sanitize-recover=all)
  add_link_options(-fsanitize=address,undefined)
endif()

if(VNSL_BUILD_FUZZERS)
  # Coverage instrumentation for everything; the fuzzer main is linked only into the fuzz targets.
  add_compile_options(-fsanitize=fuzzer-no-link,address,undefined)
  add_link_options(-fsanitize=address,undefined)
endif()

add_library(vnsl
  src/can/frame.cpp
  src/can/bit_timing.cpp
  src/j1939/transport.cpp
  src/j1939/signals.cpp
  src/sim/simulator.cpp
  src/sim/j1939_node.cpp
  src/sim/vehicle.cpp
  src/sim/truck.cpp
  src/ids/baseline.cpp
  src/ids/detector.cpp
  src/ids/attack.cpp
  src/crypto/hmac_sha256.cpp
  src/secoc/secoc.cpp
  src/gateway/policy.cpp
  src/gateway/gateway.cpp)
target_include_directories(vnsl PUBLIC include)
target_link_libraries(vnsl PRIVATE vnsl_warnings)

add_executable(vn-decode apps/vn-decode/main.cpp)
target_link_libraries(vn-decode PRIVATE vnsl vnsl_warnings)

add_executable(vn-sim apps/vn-sim/main.cpp)
target_link_libraries(vn-sim PRIVATE vnsl vnsl_warnings)

add_executable(vn-ids apps/vn-ids/main.cpp)
target_link_libraries(vn-ids PRIVATE vnsl vnsl_warnings)

add_executable(vn-secoc apps/vn-secoc/main.cpp)
target_link_libraries(vn-secoc PRIVATE vnsl vnsl_warnings)

add_executable(vn-mac apps/vn-mac/main.cpp)
target_link_libraries(vn-mac PRIVATE vnsl vnsl_warnings)

add_executable(vn-gateway apps/vn-gateway/main.cpp)
target_link_libraries(vn-gateway PRIVATE vnsl vnsl_warnings)

add_executable(vn-attack apps/vn-attack/main.cpp)
target_link_libraries(vn-attack PRIVATE vnsl vnsl_warnings)

# SocketCAN exists only on Linux; everything else builds anywhere (macOS included).
if(CMAKE_SYSTEM_NAME STREQUAL "Linux")
  target_sources(vnsl PRIVATE src/can/socketcan.cpp)
  add_executable(vn-record apps/vn-record/main.cpp)
  target_link_libraries(vn-record PRIVATE vnsl vnsl_warnings)
  add_executable(vn-replay apps/vn-replay/main.cpp)
  target_link_libraries(vn-replay PRIVATE vnsl vnsl_warnings)
endif()

if(VNSL_BUILD_TESTS)
  FetchContent_Declare(googletest
    URL https://github.com/google/googletest/releases/download/v1.17.0/googletest-1.17.0.tar.gz
    DOWNLOAD_EXTRACT_TIMESTAMP ON)
  set(INSTALL_GTEST OFF CACHE BOOL "" FORCE)
  FetchContent_MakeAvailable(googletest)

  enable_testing()
  add_executable(vnsl_tests
    tests/frame_test.cpp
    tests/id_test.cpp
    tests/transport_test.cpp
    tests/signals_test.cpp
    tests/capture_test.cpp
    tests/bit_timing_test.cpp
    tests/simulator_test.cpp
    tests/j1939_node_test.cpp
    tests/ids_test.cpp
    tests/crypto_test.cpp
    tests/secoc_test.cpp
    tests/gateway_test.cpp)
  target_link_libraries(vnsl_tests PRIVATE vnsl GTest::gtest_main)
  target_compile_definitions(vnsl_tests PRIVATE VNSL_TESTDATA_DIR="${CMAKE_CURRENT_SOURCE_DIR}/testdata")
  include(GoogleTest)
  gtest_discover_tests(vnsl_tests)
endif()

if(VNSL_BUILD_FUZZERS)
  foreach(target fuzz_log_line fuzz_transport fuzz_signals fuzz_truck fuzz_ids fuzz_secoc fuzz_gateway)
    add_executable(${target} fuzz/${target}.cpp)
    target_compile_options(${target} PRIVATE -fsanitize=fuzzer)
    target_link_options(${target} PRIVATE -fsanitize=fuzzer)
    target_link_libraries(${target} PRIVATE vnsl)
  endforeach()
endif()
