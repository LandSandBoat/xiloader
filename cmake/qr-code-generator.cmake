CPMAddPackage(
  NAME qr-code-generator
  GITHUB_REPOSITORY nayuki/QR-Code-generator
  GIT_TAG 720f62bddb7226106071d4728c292cb1df519ceb
  LANGUAGES CXX
  DOWNLOAD_ONLY
)

if(qr-code-generator_ADDED)
    add_library(qr-code-generator
        STATIC
            ${qr-code-generator_SOURCE_DIR}/cpp/qrcodegen.cpp
            ${qr-code-generator_SOURCE_DIR}/cpp/qrcodegen.hpp
    )
    target_include_directories(qr-code-generator
        SYSTEM INTERFACE
            ${qr-code-generator_SOURCE_DIR}/cpp
    )
endif()
