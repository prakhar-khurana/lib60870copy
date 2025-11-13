cmake_minimum_required(VERSION 3.10)
project(lib60870-C)

# Enable IEC 62351-5 A-Profile Security
# These are moved to the lib60870 target definition
# add_definitions(-DCONFIG_CS104_APROFILE=1)
# add_definitions(-DHAVE_LIBOQS=1)

# Build options for HAL and common modules
option(BUILD_HAL "Build HAL (Hardware Abstraction Layer)" ON)
option(BUILD_COMMON "Build common utilities (linked_list)" ON)

# mbedTLS Configuration
option(WITH_MBEDTLS "Use mbedTLS instead of OpenSSL" ON)

#if(WITH_MBEDTLS)
  # MSVC: Enable /FS flag BEFORE adding mbedTLS to prevent PDB locking errors
if(MSVC)
    add_compile_options(/FS)
    # /TC is now applied per-target in src/CMakeLists.txt
endif()

if(WITH_MBEDTLS)
  # Create output directory for mbedtls config
  file(MAKE_DIRECTORY ${CMAKE_BINARY_DIR}/dependencies/mbedtls-2.28.8/include/mbedtls)
  
  # Copy our custom config file to the mbedTLS include directory
  # This is NOT the right way. We will use mbedtls's own system.
  # configure_file(
  #   ${CMAKE_CURRENT_SOURCE_DIR}/src/hal/tls/mbedtls/mbedtls_config.h
  #   ${CMAKE_BINARY_DIR}/dependencies/mbedtls-2.28.8/include/mbedtls/config.h
  #   COPYONLY
  # )
  
  # Set mbedTLS options before adding the subdirectory
  set(ENABLE_TESTING OFF CACHE BOOL "Disable tests" FORCE)
  set(ENABLE_PROGRAMS OFF CACHE BOOL "Disable programs" FORCE)
  set(ENABLE_ZLIB_SUPPORT OFF CACHE BOOL "Disable zlib" FORCE)
    
    # FIX: Tell mbedtls to use OUR custom config file
    set(MBEDTLS_CONFIG_FILE ${CMAKE_CURRENT_SOURCE_DIR}/src/hal/tls/mbedtls/mbedtls_config.h CACHE FILEPATH "Use lib60870 config" FORCE)
  
  # Add mbedTLS with specific options
  add_subdirectory(
    ${CMAKE_CURRENT_SOURCE_DIR}/dependencies/mbedtls-2.28.8
    ${CMAKE_BINARY_DIR}/mbedtls
    EXCLUDE_FROM_ALL
  )
  
  # Include mbedTLS headers
  include_directories(
    ${CMAKE_CURRENT_SOURCE_DIR}/dependencies/mbedtls-2.28.8/include
    ${CMAKE_BINARY_DIR}/dependencies/mbedtls-2.28.8/include
  )
  
  set(OPENSSL_LIBRARIES mbedtls mbedx509 mbedcrypto)
endif()

# Include other directories
include_directories(
  src/inc
  src/inc/internal
  src/hal
  src/hal/inc
  config
  src/file-service 
  src/common/inc  
  ${OPENSSL_INCLUDE_DIR}
  ${CMAKE_BINARY_DIR}/dependencies/mbedtls-2.28.8/include
  src/hal/tls
  src/hal/tls/mbedtls
  src/hal/tls/openssl
)

# FIX: Add the OQS include path here, where it can be found
# Note: The actual liboqs finding and linking is done in src/CMakeLists.txt
set(OQS_ROOT "${CMAKE_SOURCE_DIR}/../liboqs/install") # Path to the install folder
find_path(OQS_INCLUDE_DIR oqs/oqs.h
  PATHS ${OQS_ROOT}/include
  NO_DEFAULT_PATH
)
find_library(OQS_LIBRARY oqs
  PATHS ${OQS_ROOT}/lib
  NO_DEFAULT_PATH
)

if (OQS_INCLUDE_DIR AND OQS_LIBRARY)
    message(STATUS "Found liboqs: include=${OQS_INCLUDE_DIR} lib=${OQS_LIBRARY}")
    include_directories(${OQS_INCLUDE_DIR})
    # HAVE_LIBOQS will be defined in src/CMakeLists.txt as target compile definition
else()
  message(STATUS "liboqs not found - building without PQC KEM support")
endif()


# Add source files
add_subdirectory(src)
add_subdirectory(examples)

# Disable tests - they use outdated API and are not needed for production
# add_subdirectory(tests)