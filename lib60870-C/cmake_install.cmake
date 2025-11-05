# Install script for directory: C:/Users/z005653n/Desktop/lib60870

# Set the install prefix
if(NOT DEFINED CMAKE_INSTALL_PREFIX)
  set(CMAKE_INSTALL_PREFIX "C:/Program Files/lib60870-C")
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
  if(CMAKE_INSTALL_CONFIG_NAME MATCHES "^([Dd][Ee][Bb][Uu][Gg])$")
    file(INSTALL DESTINATION "${CMAKE_INSTALL_PREFIX}/lib" TYPE STATIC_LIBRARY FILES "C:/Users/z005653n/Desktop/lib60870/lib60870-C/Debug/lib60870.lib")
  elseif(CMAKE_INSTALL_CONFIG_NAME MATCHES "^([Rr][Ee][Ll][Ee][Aa][Ss][Ee])$")
    file(INSTALL DESTINATION "${CMAKE_INSTALL_PREFIX}/lib" TYPE STATIC_LIBRARY FILES "C:/Users/z005653n/Desktop/lib60870/lib60870-C/Release/lib60870.lib")
  elseif(CMAKE_INSTALL_CONFIG_NAME MATCHES "^([Mm][Ii][Nn][Ss][Ii][Zz][Ee][Rr][Ee][Ll])$")
    file(INSTALL DESTINATION "${CMAKE_INSTALL_PREFIX}/lib" TYPE STATIC_LIBRARY FILES "C:/Users/z005653n/Desktop/lib60870/lib60870-C/MinSizeRel/lib60870.lib")
  elseif(CMAKE_INSTALL_CONFIG_NAME MATCHES "^([Rr][Ee][Ll][Ww][Ii][Tt][Hh][Dd][Ee][Bb][Ii][Nn][Ff][Oo])$")
    file(INSTALL DESTINATION "${CMAKE_INSTALL_PREFIX}/lib" TYPE STATIC_LIBRARY FILES "C:/Users/z005653n/Desktop/lib60870/lib60870-C/RelWithDebInfo/lib60870.lib")
  endif()
endif()

if(CMAKE_INSTALL_COMPONENT STREQUAL "Unspecified" OR NOT CMAKE_INSTALL_COMPONENT)
  file(INSTALL DESTINATION "${CMAKE_INSTALL_PREFIX}/include/lib60870" TYPE FILE FILES
    "C:/Users/z005653n/Desktop/lib60870/lib60870-C/src/hal/inc/hal_time.h"
    "C:/Users/z005653n/Desktop/lib60870/lib60870-C/src/hal/inc/hal_thread.h"
    "C:/Users/z005653n/Desktop/lib60870/lib60870-C/src/hal/inc/hal_socket.h"
    "C:/Users/z005653n/Desktop/lib60870/lib60870-C/src/hal/inc/hal_serial.h"
    "C:/Users/z005653n/Desktop/lib60870/lib60870-C/src/hal/inc/hal_base.h"
    "C:/Users/z005653n/Desktop/lib60870/lib60870-C/src/hal/inc/tls_config.h"
    "C:/Users/z005653n/Desktop/lib60870/lib60870-C/src/hal/inc/tls_ciphers.h"
    "C:/Users/z005653n/Desktop/lib60870/lib60870-C/src/common/inc/linked_list.h"
    "C:/Users/z005653n/Desktop/lib60870/lib60870-C/src/hal/memory/lib_memory.c"
    "C:/Users/z005653n/Desktop/lib60870/lib60870-C/src/inc/api/cs101_master.h"
    "C:/Users/z005653n/Desktop/lib60870/lib60870-C/src/inc/api/cs101_slave.h"
    "C:/Users/z005653n/Desktop/lib60870/lib60870-C/src/inc/api/cs104_slave.h"
    "C:/Users/z005653n/Desktop/lib60870/lib60870-C/src/inc/api/iec60870_master.h"
    "C:/Users/z005653n/Desktop/lib60870/lib60870-C/src/inc/api/iec60870_slave.h"
    "C:/Users/z005653n/Desktop/lib60870/lib60870-C/src/inc/api/iec60870_common.h"
    "C:/Users/z005653n/Desktop/lib60870/lib60870-C/src/inc/api/cs101_information_objects.h"
    "C:/Users/z005653n/Desktop/lib60870/lib60870-C/src/inc/api/cs104_connection.h"
    "C:/Users/z005653n/Desktop/lib60870/lib60870-C/src/inc/api/cs104_security.h"
    "C:/Users/z005653n/Desktop/lib60870/lib60870-C/src/inc/api/link_layer_parameters.h"
    "C:/Users/z005653n/Desktop/lib60870/lib60870-C/src/file-service/cs101_file_service.h"
    )
endif()

if(CMAKE_INSTALL_COMPONENT STREQUAL "Unspecified" OR NOT CMAKE_INSTALL_COMPONENT)
  file(INSTALL DESTINATION "${CMAKE_INSTALL_PREFIX}/bin" TYPE PROGRAM FILES
    "C:/Program Files (x86)/Microsoft Visual Studio/2022/BuildTools/VC/Redist/MSVC/14.42.34433/x64/Microsoft.VC143.CRT/msvcp140.dll"
    "C:/Program Files (x86)/Microsoft Visual Studio/2022/BuildTools/VC/Redist/MSVC/14.42.34433/x64/Microsoft.VC143.CRT/msvcp140_1.dll"
    "C:/Program Files (x86)/Microsoft Visual Studio/2022/BuildTools/VC/Redist/MSVC/14.42.34433/x64/Microsoft.VC143.CRT/msvcp140_2.dll"
    "C:/Program Files (x86)/Microsoft Visual Studio/2022/BuildTools/VC/Redist/MSVC/14.42.34433/x64/Microsoft.VC143.CRT/msvcp140_atomic_wait.dll"
    "C:/Program Files (x86)/Microsoft Visual Studio/2022/BuildTools/VC/Redist/MSVC/14.42.34433/x64/Microsoft.VC143.CRT/msvcp140_codecvt_ids.dll"
    "C:/Program Files (x86)/Microsoft Visual Studio/2022/BuildTools/VC/Redist/MSVC/14.42.34433/x64/Microsoft.VC143.CRT/vcruntime140_1.dll"
    "C:/Program Files (x86)/Microsoft Visual Studio/2022/BuildTools/VC/Redist/MSVC/14.42.34433/x64/Microsoft.VC143.CRT/vcruntime140.dll"
    "C:/Program Files (x86)/Microsoft Visual Studio/2022/BuildTools/VC/Redist/MSVC/14.42.34433/x64/Microsoft.VC143.CRT/concrt140.dll"
    )
endif()

if(CMAKE_INSTALL_COMPONENT STREQUAL "Unspecified" OR NOT CMAKE_INSTALL_COMPONENT)
  file(INSTALL DESTINATION "${CMAKE_INSTALL_PREFIX}/bin" TYPE DIRECTORY FILES "")
endif()

if(NOT CMAKE_INSTALL_LOCAL_ONLY)
  # Include the install script for each subdirectory.
  include("C:/Users/z005653n/Desktop/lib60870/lib60870-C/lib60870-C/examples/cmake_install.cmake")

endif()

string(REPLACE ";" "\n" CMAKE_INSTALL_MANIFEST_CONTENT
       "${CMAKE_INSTALL_MANIFEST_FILES}")
if(CMAKE_INSTALL_LOCAL_ONLY)
  file(WRITE "C:/Users/z005653n/Desktop/lib60870/lib60870-C/install_local_manifest.txt"
     "${CMAKE_INSTALL_MANIFEST_CONTENT}")
endif()
if(CMAKE_INSTALL_COMPONENT)
  if(CMAKE_INSTALL_COMPONENT MATCHES "^[a-zA-Z0-9_.+-]+$")
    set(CMAKE_INSTALL_MANIFEST "install_manifest_${CMAKE_INSTALL_COMPONENT}.txt")
  else()
    string(MD5 CMAKE_INST_COMP_HASH "${CMAKE_INSTALL_COMPONENT}")
    set(CMAKE_INSTALL_MANIFEST "install_manifest_${CMAKE_INST_COMP_HASH}.txt")
    unset(CMAKE_INST_COMP_HASH)
  endif()
else()
  set(CMAKE_INSTALL_MANIFEST "install_manifest.txt")
endif()

if(NOT CMAKE_INSTALL_LOCAL_ONLY)
  file(WRITE "C:/Users/z005653n/Desktop/lib60870/lib60870-C/${CMAKE_INSTALL_MANIFEST}"
     "${CMAKE_INSTALL_MANIFEST_CONTENT}")
endif()
