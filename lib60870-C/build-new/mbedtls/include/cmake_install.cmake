# Install script for directory: C:/Users/z005653n/Desktop/lib60870/lib60870-C/dependencies/mbedtls-2.28.8/include

# Set the install prefix
if(NOT DEFINED CMAKE_INSTALL_PREFIX)
  set(CMAKE_INSTALL_PREFIX "C:/Program Files (x86)/lib60870-C")
endif()
string(REGEX REPLACE "/$" "" CMAKE_INSTALL_PREFIX "${CMAKE_INSTALL_PREFIX}")

# Set the install configuration name.
if(NOT DEFINED CMAKE_INSTALL_CONFIG_NAME)
  if(BUILD_TYPE)
    string(REGEX REPLACE "^[^A-Za-z0-9_]+" ""
           CMAKE_INSTALL_CONFIG_NAME "${BUILD_TYPE}")
  else()
    set(CMAKE_INSTALL_CONFIG_NAME "Release")
  endif()
  message(STATUS "Install configuration: \"${CMAKE_INSTALL_CONFIG_NAME}\"")
endif()

# Set the component getting installed.
if(NOT CMAKE_INSTALL_COMPONENT)
  if(COMPONENT)
    message(STATUS "Install component: \"${COMPONENT}\"")
    set(CMAKE_INSTALL_COMPONENT "${COMPONENT}")
  else()
    set(CMAKE_INSTALL_COMPONENT)
  endif()
endif()

# Is this installation the result of a crosscompile?
if(NOT DEFINED CMAKE_CROSSCOMPILING)
  set(CMAKE_CROSSCOMPILING "FALSE")
endif()

if(CMAKE_INSTALL_COMPONENT STREQUAL "Unspecified" OR NOT CMAKE_INSTALL_COMPONENT)
  file(INSTALL DESTINATION "${CMAKE_INSTALL_PREFIX}/include/mbedtls" TYPE FILE PERMISSIONS OWNER_READ OWNER_WRITE GROUP_READ WORLD_READ FILES
    "C:/Users/z005653n/Desktop/lib60870/lib60870-C/dependencies/mbedtls-2.28.8/include/mbedtls/aes.h"
    "C:/Users/z005653n/Desktop/lib60870/lib60870-C/dependencies/mbedtls-2.28.8/include/mbedtls/aesni.h"
    "C:/Users/z005653n/Desktop/lib60870/lib60870-C/dependencies/mbedtls-2.28.8/include/mbedtls/arc4.h"
    "C:/Users/z005653n/Desktop/lib60870/lib60870-C/dependencies/mbedtls-2.28.8/include/mbedtls/aria.h"
    "C:/Users/z005653n/Desktop/lib60870/lib60870-C/dependencies/mbedtls-2.28.8/include/mbedtls/asn1.h"
    "C:/Users/z005653n/Desktop/lib60870/lib60870-C/dependencies/mbedtls-2.28.8/include/mbedtls/asn1write.h"
    "C:/Users/z005653n/Desktop/lib60870/lib60870-C/dependencies/mbedtls-2.28.8/include/mbedtls/base64.h"
    "C:/Users/z005653n/Desktop/lib60870/lib60870-C/dependencies/mbedtls-2.28.8/include/mbedtls/bignum.h"
    "C:/Users/z005653n/Desktop/lib60870/lib60870-C/dependencies/mbedtls-2.28.8/include/mbedtls/blowfish.h"
    "C:/Users/z005653n/Desktop/lib60870/lib60870-C/dependencies/mbedtls-2.28.8/include/mbedtls/bn_mul.h"
    "C:/Users/z005653n/Desktop/lib60870/lib60870-C/dependencies/mbedtls-2.28.8/include/mbedtls/camellia.h"
    "C:/Users/z005653n/Desktop/lib60870/lib60870-C/dependencies/mbedtls-2.28.8/include/mbedtls/ccm.h"
    "C:/Users/z005653n/Desktop/lib60870/lib60870-C/dependencies/mbedtls-2.28.8/include/mbedtls/certs.h"
    "C:/Users/z005653n/Desktop/lib60870/lib60870-C/dependencies/mbedtls-2.28.8/include/mbedtls/chacha20.h"
    "C:/Users/z005653n/Desktop/lib60870/lib60870-C/dependencies/mbedtls-2.28.8/include/mbedtls/chachapoly.h"
    "C:/Users/z005653n/Desktop/lib60870/lib60870-C/dependencies/mbedtls-2.28.8/include/mbedtls/check_config.h"
    "C:/Users/z005653n/Desktop/lib60870/lib60870-C/dependencies/mbedtls-2.28.8/include/mbedtls/cipher.h"
    "C:/Users/z005653n/Desktop/lib60870/lib60870-C/dependencies/mbedtls-2.28.8/include/mbedtls/cipher_internal.h"
    "C:/Users/z005653n/Desktop/lib60870/lib60870-C/dependencies/mbedtls-2.28.8/include/mbedtls/cmac.h"
    "C:/Users/z005653n/Desktop/lib60870/lib60870-C/dependencies/mbedtls-2.28.8/include/mbedtls/compat-1.3.h"
    "C:/Users/z005653n/Desktop/lib60870/lib60870-C/dependencies/mbedtls-2.28.8/include/mbedtls/config.h"
    "C:/Users/z005653n/Desktop/lib60870/lib60870-C/dependencies/mbedtls-2.28.8/include/mbedtls/config_psa.h"
    "C:/Users/z005653n/Desktop/lib60870/lib60870-C/dependencies/mbedtls-2.28.8/include/mbedtls/constant_time.h"
    "C:/Users/z005653n/Desktop/lib60870/lib60870-C/dependencies/mbedtls-2.28.8/include/mbedtls/ctr_drbg.h"
    "C:/Users/z005653n/Desktop/lib60870/lib60870-C/dependencies/mbedtls-2.28.8/include/mbedtls/debug.h"
    "C:/Users/z005653n/Desktop/lib60870/lib60870-C/dependencies/mbedtls-2.28.8/include/mbedtls/des.h"
    "C:/Users/z005653n/Desktop/lib60870/lib60870-C/dependencies/mbedtls-2.28.8/include/mbedtls/dhm.h"
    "C:/Users/z005653n/Desktop/lib60870/lib60870-C/dependencies/mbedtls-2.28.8/include/mbedtls/ecdh.h"
    "C:/Users/z005653n/Desktop/lib60870/lib60870-C/dependencies/mbedtls-2.28.8/include/mbedtls/ecdsa.h"
    "C:/Users/z005653n/Desktop/lib60870/lib60870-C/dependencies/mbedtls-2.28.8/include/mbedtls/ecjpake.h"
    "C:/Users/z005653n/Desktop/lib60870/lib60870-C/dependencies/mbedtls-2.28.8/include/mbedtls/ecp.h"
    "C:/Users/z005653n/Desktop/lib60870/lib60870-C/dependencies/mbedtls-2.28.8/include/mbedtls/ecp_internal.h"
    "C:/Users/z005653n/Desktop/lib60870/lib60870-C/dependencies/mbedtls-2.28.8/include/mbedtls/entropy.h"
    "C:/Users/z005653n/Desktop/lib60870/lib60870-C/dependencies/mbedtls-2.28.8/include/mbedtls/entropy_poll.h"
    "C:/Users/z005653n/Desktop/lib60870/lib60870-C/dependencies/mbedtls-2.28.8/include/mbedtls/error.h"
    "C:/Users/z005653n/Desktop/lib60870/lib60870-C/dependencies/mbedtls-2.28.8/include/mbedtls/gcm.h"
    "C:/Users/z005653n/Desktop/lib60870/lib60870-C/dependencies/mbedtls-2.28.8/include/mbedtls/havege.h"
    "C:/Users/z005653n/Desktop/lib60870/lib60870-C/dependencies/mbedtls-2.28.8/include/mbedtls/hkdf.h"
    "C:/Users/z005653n/Desktop/lib60870/lib60870-C/dependencies/mbedtls-2.28.8/include/mbedtls/hmac_drbg.h"
    "C:/Users/z005653n/Desktop/lib60870/lib60870-C/dependencies/mbedtls-2.28.8/include/mbedtls/md.h"
    "C:/Users/z005653n/Desktop/lib60870/lib60870-C/dependencies/mbedtls-2.28.8/include/mbedtls/md2.h"
    "C:/Users/z005653n/Desktop/lib60870/lib60870-C/dependencies/mbedtls-2.28.8/include/mbedtls/md4.h"
    "C:/Users/z005653n/Desktop/lib60870/lib60870-C/dependencies/mbedtls-2.28.8/include/mbedtls/md5.h"
    "C:/Users/z005653n/Desktop/lib60870/lib60870-C/dependencies/mbedtls-2.28.8/include/mbedtls/md_internal.h"
    "C:/Users/z005653n/Desktop/lib60870/lib60870-C/dependencies/mbedtls-2.28.8/include/mbedtls/memory_buffer_alloc.h"
    "C:/Users/z005653n/Desktop/lib60870/lib60870-C/dependencies/mbedtls-2.28.8/include/mbedtls/net.h"
    "C:/Users/z005653n/Desktop/lib60870/lib60870-C/dependencies/mbedtls-2.28.8/include/mbedtls/net_sockets.h"
    "C:/Users/z005653n/Desktop/lib60870/lib60870-C/dependencies/mbedtls-2.28.8/include/mbedtls/nist_kw.h"
    "C:/Users/z005653n/Desktop/lib60870/lib60870-C/dependencies/mbedtls-2.28.8/include/mbedtls/oid.h"
    "C:/Users/z005653n/Desktop/lib60870/lib60870-C/dependencies/mbedtls-2.28.8/include/mbedtls/padlock.h"
    "C:/Users/z005653n/Desktop/lib60870/lib60870-C/dependencies/mbedtls-2.28.8/include/mbedtls/pem.h"
    "C:/Users/z005653n/Desktop/lib60870/lib60870-C/dependencies/mbedtls-2.28.8/include/mbedtls/pk.h"
    "C:/Users/z005653n/Desktop/lib60870/lib60870-C/dependencies/mbedtls-2.28.8/include/mbedtls/pk_internal.h"
    "C:/Users/z005653n/Desktop/lib60870/lib60870-C/dependencies/mbedtls-2.28.8/include/mbedtls/pkcs11.h"
    "C:/Users/z005653n/Desktop/lib60870/lib60870-C/dependencies/mbedtls-2.28.8/include/mbedtls/pkcs12.h"
    "C:/Users/z005653n/Desktop/lib60870/lib60870-C/dependencies/mbedtls-2.28.8/include/mbedtls/pkcs5.h"
    "C:/Users/z005653n/Desktop/lib60870/lib60870-C/dependencies/mbedtls-2.28.8/include/mbedtls/platform.h"
    "C:/Users/z005653n/Desktop/lib60870/lib60870-C/dependencies/mbedtls-2.28.8/include/mbedtls/platform_time.h"
    "C:/Users/z005653n/Desktop/lib60870/lib60870-C/dependencies/mbedtls-2.28.8/include/mbedtls/platform_util.h"
    "C:/Users/z005653n/Desktop/lib60870/lib60870-C/dependencies/mbedtls-2.28.8/include/mbedtls/poly1305.h"
    "C:/Users/z005653n/Desktop/lib60870/lib60870-C/dependencies/mbedtls-2.28.8/include/mbedtls/psa_util.h"
    "C:/Users/z005653n/Desktop/lib60870/lib60870-C/dependencies/mbedtls-2.28.8/include/mbedtls/ripemd160.h"
    "C:/Users/z005653n/Desktop/lib60870/lib60870-C/dependencies/mbedtls-2.28.8/include/mbedtls/rsa.h"
    "C:/Users/z005653n/Desktop/lib60870/lib60870-C/dependencies/mbedtls-2.28.8/include/mbedtls/rsa_internal.h"
    "C:/Users/z005653n/Desktop/lib60870/lib60870-C/dependencies/mbedtls-2.28.8/include/mbedtls/sha1.h"
    "C:/Users/z005653n/Desktop/lib60870/lib60870-C/dependencies/mbedtls-2.28.8/include/mbedtls/sha256.h"
    "C:/Users/z005653n/Desktop/lib60870/lib60870-C/dependencies/mbedtls-2.28.8/include/mbedtls/sha512.h"
    "C:/Users/z005653n/Desktop/lib60870/lib60870-C/dependencies/mbedtls-2.28.8/include/mbedtls/ssl.h"
    "C:/Users/z005653n/Desktop/lib60870/lib60870-C/dependencies/mbedtls-2.28.8/include/mbedtls/ssl_cache.h"
    "C:/Users/z005653n/Desktop/lib60870/lib60870-C/dependencies/mbedtls-2.28.8/include/mbedtls/ssl_ciphersuites.h"
    "C:/Users/z005653n/Desktop/lib60870/lib60870-C/dependencies/mbedtls-2.28.8/include/mbedtls/ssl_cookie.h"
    "C:/Users/z005653n/Desktop/lib60870/lib60870-C/dependencies/mbedtls-2.28.8/include/mbedtls/ssl_internal.h"
    "C:/Users/z005653n/Desktop/lib60870/lib60870-C/dependencies/mbedtls-2.28.8/include/mbedtls/ssl_ticket.h"
    "C:/Users/z005653n/Desktop/lib60870/lib60870-C/dependencies/mbedtls-2.28.8/include/mbedtls/threading.h"
    "C:/Users/z005653n/Desktop/lib60870/lib60870-C/dependencies/mbedtls-2.28.8/include/mbedtls/timing.h"
    "C:/Users/z005653n/Desktop/lib60870/lib60870-C/dependencies/mbedtls-2.28.8/include/mbedtls/version.h"
    "C:/Users/z005653n/Desktop/lib60870/lib60870-C/dependencies/mbedtls-2.28.8/include/mbedtls/x509.h"
    "C:/Users/z005653n/Desktop/lib60870/lib60870-C/dependencies/mbedtls-2.28.8/include/mbedtls/x509_crl.h"
    "C:/Users/z005653n/Desktop/lib60870/lib60870-C/dependencies/mbedtls-2.28.8/include/mbedtls/x509_crt.h"
    "C:/Users/z005653n/Desktop/lib60870/lib60870-C/dependencies/mbedtls-2.28.8/include/mbedtls/x509_csr.h"
    "C:/Users/z005653n/Desktop/lib60870/lib60870-C/dependencies/mbedtls-2.28.8/include/mbedtls/xtea.h"
    )
endif()

if(CMAKE_INSTALL_COMPONENT STREQUAL "Unspecified" OR NOT CMAKE_INSTALL_COMPONENT)
  file(INSTALL DESTINATION "${CMAKE_INSTALL_PREFIX}/include/psa" TYPE FILE PERMISSIONS OWNER_READ OWNER_WRITE GROUP_READ WORLD_READ FILES
    "C:/Users/z005653n/Desktop/lib60870/lib60870-C/dependencies/mbedtls-2.28.8/include/psa/crypto.h"
    "C:/Users/z005653n/Desktop/lib60870/lib60870-C/dependencies/mbedtls-2.28.8/include/psa/crypto_builtin_composites.h"
    "C:/Users/z005653n/Desktop/lib60870/lib60870-C/dependencies/mbedtls-2.28.8/include/psa/crypto_builtin_primitives.h"
    "C:/Users/z005653n/Desktop/lib60870/lib60870-C/dependencies/mbedtls-2.28.8/include/psa/crypto_compat.h"
    "C:/Users/z005653n/Desktop/lib60870/lib60870-C/dependencies/mbedtls-2.28.8/include/psa/crypto_config.h"
    "C:/Users/z005653n/Desktop/lib60870/lib60870-C/dependencies/mbedtls-2.28.8/include/psa/crypto_driver_common.h"
    "C:/Users/z005653n/Desktop/lib60870/lib60870-C/dependencies/mbedtls-2.28.8/include/psa/crypto_driver_contexts_composites.h"
    "C:/Users/z005653n/Desktop/lib60870/lib60870-C/dependencies/mbedtls-2.28.8/include/psa/crypto_driver_contexts_primitives.h"
    "C:/Users/z005653n/Desktop/lib60870/lib60870-C/dependencies/mbedtls-2.28.8/include/psa/crypto_extra.h"
    "C:/Users/z005653n/Desktop/lib60870/lib60870-C/dependencies/mbedtls-2.28.8/include/psa/crypto_platform.h"
    "C:/Users/z005653n/Desktop/lib60870/lib60870-C/dependencies/mbedtls-2.28.8/include/psa/crypto_se_driver.h"
    "C:/Users/z005653n/Desktop/lib60870/lib60870-C/dependencies/mbedtls-2.28.8/include/psa/crypto_sizes.h"
    "C:/Users/z005653n/Desktop/lib60870/lib60870-C/dependencies/mbedtls-2.28.8/include/psa/crypto_struct.h"
    "C:/Users/z005653n/Desktop/lib60870/lib60870-C/dependencies/mbedtls-2.28.8/include/psa/crypto_types.h"
    "C:/Users/z005653n/Desktop/lib60870/lib60870-C/dependencies/mbedtls-2.28.8/include/psa/crypto_values.h"
    )
endif()

string(REPLACE ";" "\n" CMAKE_INSTALL_MANIFEST_CONTENT
       "${CMAKE_INSTALL_MANIFEST_FILES}")
if(CMAKE_INSTALL_LOCAL_ONLY)
  file(WRITE "C:/Users/z005653n/Desktop/lib60870/lib60870-C/build-new/mbedtls/include/install_local_manifest.txt"
     "${CMAKE_INSTALL_MANIFEST_CONTENT}")
endif()
