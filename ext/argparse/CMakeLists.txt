cmake_minimum_required(VERSION 3.8)

project(argparse VERSION 1.0.0 LANGUAGES CXX)
set("PROJECT_DESCRIPTION" "A single header argument parser for C++17")
set("PROJECT_HOMEPAGE_URL" "https://github.com/p-ranav/argparse")

option(ARGPARSE_BUILD_TESTS OFF)
option(ARGPARSE_LONG_VERSION_ARG_ONLY OFF)

include(GNUInstallDirs)
include(CMakePackageConfigHelpers)
string(REPLACE "/${CMAKE_LIBRARY_ARCHITECTURE}" "" CMAKE_INSTALL_LIBDIR_ARCHIND "${CMAKE_INSTALL_LIBDIR}")


add_library(argparse INTERFACE)
add_library(argparse::argparse ALIAS argparse)


if (ARGPARSE_LONG_VERSION_ARG_ONLY)
	target_compile_definitions(argparse INTERFACE ARGPARSE_LONG_VERSION_ARG_ONLY=true)
endif ()

target_compile_features(argparse INTERFACE cxx_std_17)
target_include_directories(argparse INTERFACE
  $<INSTALL_INTERFACE:${CMAKE_INSTALL_INCLUDEDIR}>
  $<BUILD_INTERFACE:${CMAKE_CURRENT_LIST_DIR}/include>)


if(ARGPARSE_BUILD_TESTS)
  add_subdirectory(test)
endif()

install(TARGETS argparse EXPORT argparseConfig)
install(EXPORT argparseConfig
        NAMESPACE argparse::
        DESTINATION ${CMAKE_INSTALL_LIBDIR_ARCHIND}/cmake/${PROJECT_NAME})
install(FILES ${CMAKE_CURRENT_LIST_DIR}/include/argparse/argparse.hpp
        DESTINATION ${CMAKE_INSTALL_INCLUDEDIR}/argparse)


set(CONFIG_FILE_NAME_WITHOUT_EXT "${PROJECT_NAME}Config")
set(CMAKE_CONFIG_FILE_BASENAME "${CMAKE_CURRENT_BINARY_DIR}/${CONFIG_FILE_NAME_WITHOUT_EXT}")
set(CMAKE_CONFIG_VERSION_FILE_NAME "${CMAKE_CONFIG_FILE_BASENAME}-version.cmake")
set(CMAKE_CONFIG_FILE_NAME "${CMAKE_CONFIG_FILE_BASENAME}.cmake")

if(${CMAKE_VERSION} VERSION_GREATER "3.14")
	set(OPTIONAL_ARCH_INDEPENDENT "ARCH_INDEPENDENT")
endif()

write_basic_package_version_file("${CMAKE_CONFIG_VERSION_FILE_NAME}"
    COMPATIBILITY ExactVersion
    ${OPTIONAL_ARCH_INDEPENDENT}
)

export(EXPORT argparseConfig
       NAMESPACE argparse::)
