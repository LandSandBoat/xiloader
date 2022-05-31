CPMAddPackage(
    NAME detours
    GITHUB_REPOSITORY microsoft/Detours
    GIT_TAG 66d6f2d34aba564d373083621cacf66ec51199b2
    DOWNLOAD_ONLY YES
)
if (detours_ADDED)
  # Detours has no CMake support, so we create our own target
  # https://github.com/0xeb/detours-cmake

    # Copy from <detours>/src to <detours>/detours
    file(COPY ${detours_SOURCE_DIR}/src/ DESTINATION ${detours_SOURCE_DIR}/detours/)

    file(GLOB detours_sources ${detours_SOURCE_DIR}/detours/*.cpp)

    # This file is included and not compiled on its own
    list(REMOVE_ITEM detours_sources "${detours_SOURCE_DIR}/detours/uimports.cpp")

    add_library(detours STATIC ${detours_sources})

    target_compile_options(detours PRIVATE /W4 /WX /Zi /MT /Gy /Gm- /Zl /Od)
    target_include_directories(detours
      PUBLIC
        $<BUILD_INTERFACE:${detours_SOURCE_DIR}>
    )
endif()
