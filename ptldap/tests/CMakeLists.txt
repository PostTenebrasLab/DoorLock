cmake_minimum_required(VERSION 3.12)
project(ptldap_tests)

add_library(ptldap INTERFACE)
target_include_directories(ptldap INTERFACE ..)
target_compile_features(ptldap INTERFACE cxx_std_20)
target_compile_options(ptldap INTERFACE -fconcepts)

add_executable(tests ber.cpp ldap.cpp test_main.cpp catch.hpp)
target_link_libraries(tests ptldap)

enable_testing()
add_test(tests tests)
