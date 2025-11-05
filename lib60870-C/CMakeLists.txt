cmake_minimum_required(VERSION 3.10)
project(lib60870-C)

# Find OpenSSL
#find_package(OpenSSL REQUIRED)
option(WITH_MBEDTLS "Use mbedTLS instead of OpenSSL" ON)
if(WITH_MBEDTLS)
    add_subdirectory(dependencies/mbedtls-2.28.8)
    set(OPENSSL_LIBRARIES mbedtls_static)
    include_directories(dependencies/mbedtls-2.28.8/include)
endif()
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
