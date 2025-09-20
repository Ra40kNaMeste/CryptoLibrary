cmake_minimum_required(VERSION 3.10.0)
set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)


if(NOT DEFINED BUILD_TESTING)
    option(BUILD_TESTING "Build the testing tree" ON)
endif()

add_library(crypto_lib 
  src/symmetrics/feistel_network.cpp
  src/encryption_modes/ecb.cpp
    )
    
    target_include_directories(crypto_lib PUBLIC 
                            ${CMAKE_CURRENT_SOURCE_DIR}/src/symmetrics
                            ${CMAKE_CURRENT_SOURCE_DIR}/src/encryption_modes
                           )

if(BUILD_TESTING)
  include(FetchContent)
  FetchContent_Declare(
    googletest
    URL https://github.com/google/googletest/archive/03597a01ee50ed33e9dfd640b249b4be3799d395.zip
  )

  # For Windows: Prevent overriding the parent project's compiler/linker settings
  set(gtest_force_shared_crt ON CACHE BOOL "" FORCE)
  FetchContent_MakeAvailable(googletest)
  enable_testing()
  add_executable(
    tests
    tests/symmetrics/feistel_network_tests.cc
    tests/encryption_modes/ecbtests.cc
    tests/encryption_modes/cbctests.cc
    tests/encryption_modes/cfbtests.cc
  )
  target_include_directories(tests PRIVATE tests/commons)
  target_link_libraries(
    tests
    GTest::gtest_main
    GTest::gmock
    crypto_lib
  )

  include(GoogleTest)
  gtest_discover_tests(tests)
endif()
