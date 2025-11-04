cmake_minimum_required(VERSION 3.10)
project(lib60870-C)

# Find OpenSSL
find_package(OpenSSL REQUIRED)

# Include directories
include_directories(
    src/inc
    src/inc/internal
    src/hal
    ${OPENSSL_INCLUDE_DIR}
)

# Add source files
add_subdirectory(src)
add_subdirectory(examples)
add_subdirectory(tests)
