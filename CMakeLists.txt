cmake_minimum_required(VERSION 3.10)
project(xiloader CXX)

set_property(GLOBAL PROPERTY CXX_STANDARD 17)
set_property(GLOBAL PROPERTY CXX_STANDARD_REQUIRED ON)
set_property(GLOBAL PROPERTY CXX_EXTENSIONS ON)
set_property(GLOBAL PROPERTY LINKER_LANGUAGE CXX)
set_property(GLOBAL PROPERTY USE_FOLDERS ON)

# CMake adds "/W3" by default on MSVC, remove it.
# Fixed with CMake 3.15
if(MSVC)
    string(REGEX REPLACE "/W3[ ]" "" CMAKE_CXX_FLAGS ${CMAKE_CXX_FLAGS})
endif()

set(CMAKE_POSITION_INDEPENDENT_CODE ON)

add_subdirectory(ext)

# xiloader
add_executable(xiloader
    xiloader/console.cpp
    xiloader/console.h
    xiloader/defines.h
    xiloader/FFXi.h
    xiloader/FFXiMain.h
    xiloader/functions.cpp
    xiloader/functions.h
    xiloader/main.cpp
    xiloader/network.cpp
    xiloader/network.h
    xiloader/polcore.h)

target_include_directories(xiloader PUBLIC ${PROJECT_SOURCE_DIR}/xiloader)
target_link_libraries(xiloader PUBLIC detours argparse)
