cmake_minimum_required(VERSION 3.15)

# C is enabled here so the flag fix below reaches the C dependencies
project(xiloader C CXX)

# Parallel compiles behind sccache or ccache cannot share one PDB (/Zi), so embed the debug info in the objects (/Z7)
if(MSVC AND (CMAKE_C_COMPILER_LAUNCHER OR CMAKE_CXX_COMPILER_LAUNCHER))
    foreach(flags CMAKE_C_FLAGS_DEBUG CMAKE_CXX_FLAGS_DEBUG CMAKE_C_FLAGS_RELWITHDEBINFO CMAKE_CXX_FLAGS_RELWITHDEBINFO)
        string(REPLACE "/Zi" "/Z7" ${flags} "${${flags}}")
    endforeach()
endif()

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS ON)
set(LINKER_LANGUAGE CXX)
set(USE_FOLDERS ON)

set(CMAKE_POSITION_INDEPENDENT_CODE ON)

if(CMAKE_SIZEOF_VOID_P EQUAL 8)
    message(STATUS "CMAKE_SIZEOF_VOID_P == 8: 64-bit build")
    message(FATAL_ERROR "64-bit build is not supported. Please clean your build directory and reconfigure with: cmake .. -A Win32")
elseif(CMAKE_SIZEOF_VOID_P EQUAL 4)
    message(STATUS "CMAKE_SIZEOF_VOID_P == 4: 32-bit build")
endif()

include(cmake/CPM.cmake)

include(cmake/argparse.cmake)
include(cmake/detours.cmake)
include(cmake/ftxui.cmake)
include(cmake/json.cmake)
include(cmake/mbedtls.cmake)
include(cmake/qr-code-generator.cmake)

configure_file(
	src/xiloader.rc.in
	src/xiloader.rc
)

# xiloader
add_executable(xiloader
    src/client/game.cpp
    src/client/game.h
    src/client/registry.cpp
    src/client/registry.h
    src/client/sdk/ffxi.h
    src/client/sdk/polcore.h
    src/config.cpp
    src/config.h
    src/console.cpp
    src/console.h
    src/enums/console_color.h
    src/enums/lobby_command.h
    src/enums/lobby_data.h
    src/enums/login_command.h
    src/enums/login_outcome.h
    src/enums/login_result.h
    src/enums/menu_selection.h
    src/enums/pol_function.h
    src/enums/pol_language.h
    src/enums/polcon_state.h
    src/enums/reconnect.h
    src/enums/relay_phase.h
    src/guards.h
    src/hooks/hairpin_fix.cpp
    src/hooks/hairpin_fix.h
    src/hooks/socket_hooks.cpp
    src/hooks/socket_hooks.h
    src/lobby/data_connection.cpp
    src/lobby/data_connection.h
    src/login/auth_connection.cpp
    src/login/auth_connection.h
    src/login/login.cpp
    src/login/login.h
    src/login/session.h
    src/main.cpp
    src/net/resolve.cpp
    src/net/resolve.h
    src/net/tls_client_config.cpp
    src/net/tls_client_config.h
    src/otp/qr_code.cpp
    src/otp/qr_code.h
    src/otp/trust_token_manager.cpp
    src/otp/trust_token_manager.h
    src/client/pattern_scan.cpp
    src/client/pattern_scan.h
    src/client/playonline.cpp
    src/client/playonline.h
    src/client/polcore_ids.h
    src/client/polrelay.cpp
    src/client/polrelay.h
    src/ui/ftxui_menu.cpp
    src/ui/menu.cpp
    src/ui/menu.h
    src/ui/plain_menu.cpp
    src/ui/prompts.cpp
    src/ui/prompts.h
    ${CMAKE_CURRENT_BINARY_DIR}/src/xiloader.rc
    xiloader.manifest
)

set_target_properties(xiloader PROPERTIES LINK_FLAGS "/LARGEADDRESSAWARE")

# Keeps windows.h from defining min/max and from pulling in winsock.h, so include order does not matter
target_compile_definitions(xiloader PRIVATE NOMINMAX WIN32_LEAN_AND_MEAN)

target_include_directories(xiloader PRIVATE ${PROJECT_SOURCE_DIR}/src)

target_link_libraries(xiloader PUBLIC
    detours
    argparse
    crypt32
    psapi
    ws2_32
    MbedTLS::mbedtls
    MbedTLS::mbedcrypto
    MbedTLS::mbedx509    
    nlohmann_json::nlohmann_json
    ftxui::screen
    ftxui::dom
    ftxui::component
    qr-code-generator)

# Assert-based checks for the parts that run without the game
add_executable(xiloader_check
    src/config.cpp
    src/console.cpp
    src/lobby/data_connection.cpp
    src/ui/plain_menu.cpp
    tests/check.cpp
)

target_include_directories(xiloader_check PRIVATE ${PROJECT_SOURCE_DIR}/src)
target_compile_definitions(xiloader_check PRIVATE NOMINMAX WIN32_LEAN_AND_MEAN)
target_link_libraries(xiloader_check PRIVATE argparse nlohmann_json::nlohmann_json ws2_32)

message(STATUS "CMAKE_VERSION: ${CMAKE_VERSION}")
message(STATUS "CMAKE_BUILD_TYPE: ${CMAKE_BUILD_TYPE}")
message(STATUS "CMAKE_C_COMPILER: ${CMAKE_C_COMPILER}")
message(STATUS "CMAKE_CXX_COMPILER: ${CMAKE_CXX_COMPILER}")
message(STATUS "CMAKE_CXX_COMPILER_ID: ${CMAKE_CXX_COMPILER_ID}")
message(STATUS "CMAKE_CXX_COMPILER_VERSION: ${CMAKE_CXX_COMPILER_VERSION}")
message(STATUS "CMAKE_CXX_FLAGS: ${CMAKE_CXX_FLAGS}")
message(STATUS "CMAKE_GENERATOR: ${CMAKE_GENERATOR}")
message(STATUS "CMAKE_GENERATOR_PLATFORM: ${CMAKE_GENERATOR_PLATFORM}")

message(STATUS "Setting output directory for xiloader to ${CMAKE_SOURCE_DIR}")
set_target_properties(xiloader PROPERTIES
    VS_DEBUGGER_WORKING_DIRECTORY "${CMAKE_SOURCE_DIR}"
    RUNTIME_OUTPUT_DIRECTORY_DEBUG "${CMAKE_SOURCE_DIR}"
    RUNTIME_OUTPUT_DIRECTORY_RELEASE "${CMAKE_SOURCE_DIR}"
    RUNTIME_OUTPUT_DIRECTORY_RELWITHDEBINFO "${CMAKE_SOURCE_DIR}"
    RUNTIME_OUTPUT_DIRECTORY_MINSIZEREL "${CMAKE_SOURCE_DIR}"
)
