include_directories(
    ./inc/api
    ./inc/internal
    ./hal
    ./common
)

set (lib_common_SRCS
./file-service/file_server.c
./iec60870/apl/cpXXtime2a.c
./iec60870/cs101/cs101_asdu.c
./iec60870/cs101/cs101_bcr.c
./iec60870/cs101/cs101_information_objects.c
./iec60870/cs101/cs101_master_connection.c
./iec60870/cs101/cs101_master.c
./iec60870/cs101/cs101_queue.c
./iec60870/cs101/cs101_slave.c
./iec60870/cs104/cs104_connection.c
./iec60870/cs104/cs104_frame.c
./iec60870/cs104/cs104_slave.c
./iec60870/security/62351-5/aprofile.c
./iec60870/security/62351-5/aprofile_62351_5.c
./iec60870/security/62351-5/aprofile_62351_5_handlers.c
./iec60870/security/62351-5/aprofile_codec.c
./iec60870/security/62351-5/aprofile_integration.c
./common/security_public_key.c
./iec60870/link_layer/buffer_frame.c
./iec60870/link_layer/link_layer.c
./iec60870/link_layer/serial_transceiver_ft_1_2.c
./iec60870/frame.c
./iec60870/lib60870_common.c
)

if (BUILD_COMMON)
list (APPEND lib_common_SRCS ./common/linked_list.c)
endif (BUILD_COMMON)

if (BUILD_HAL)

set (lib_linux_SRCS
./hal/serial/linux/serial_port_linux.c
./hal/socket/linux/socket_linux.c
./hal/thread/linux/thread_linux.c
./hal/time/unix/time.c
./hal/memory/lib_memory.c
)

set (lib_windows_SRCS
./hal/serial/win32/serial_port_win32.c
./hal/socket/win32/socket_win32.c
./hal/thread/win32/thread_win32.c
./hal/time/win32/time.c
./hal/memory/lib_memory.c
)

set (lib_bsd_SRCS
./hal/serial/linux/serial_port_linux.c
./hal/socket/bsd/socket_bsd.c
./hal/thread/bsd/thread_bsd.c
./hal/time/unix/time.c
./hal/memory/lib_memory.c
)

set (lib_macos_SRCS
./hal/serial/linux/serial_port_linux.c
./hal/socket/bsd/socket_bsd.c
./hal/thread/macos/thread_macos.c
./hal/time/unix/time.c
./hal/memory/lib_memory.c
)

endif (BUILD_HAL)

IF(WIN32)

IF(MSVC)
# /TC flag is now applied per-target using target_compile_options
# Removed LANGUAGE CXX property - compile as C instead
# set_source_files_properties(${lib_common_SRCS} ${lib_windows_SRCS}
#                                        PROPERTIES LANGUAGE CXX)
ENDIF()

set (library_SRCS
    ${lib_common_SRCS}
    ${lib_windows_SRCS}
)

set (CMAKE_MODULE_LINKER_FLAGS "${CMAKE_MODULE_LINKER_FLAGS}\"/DEF:${CMAKE_CURRENT_SOURCE_DIR}/vs/lib60870.def\"") 

ELSEIF(UNIX)
IF(APPLE)
set (library_SRCS
    ${lib_common_SRCS}
    ${lib_macos_SRCS}
)
ELSEIF(${CMAKE_SYSTEM_NAME} MATCHES "FreeBSD")
set (library_SRCS
    ${lib_common_SRCS}
    ${lib_bsd_SRCS}
)
ELSE()
set (library_SRCS
    ${lib_common_SRCS}
    ${lib_linux_SRCS}	
)
ENDIF(APPLE)
ENDIF(WIN32)

IF(WITH_MBEDTLS)

list (APPEND library_SRCS ${tls_SRCS})
list (APPEND library_SRCS ./hal/tls/mbedtls/tls_mbedtls.c)

add_definitions(-DLIB60870_HAS_TLS_SUPPORT=1)

ENDIF(WITH_MBEDTLS)

IF(WITH_MBEDTLS3)

list (APPEND library_SRCS ${tls_SRCS})
list (APPEND library_SRCS ./hal/tls/mbedtls3/tls_mbedtls.c)

add_definitions(-DLIB60870_HAS_TLS_SUPPORT=1)

ENDIF(WITH_MBEDTLS3)

include (GenerateExportHeader)

set(LIB_VERSION_MAJOR 2)
set(LIB_VERSION_MINOR 3)
set(LIB_VERSION_PATCH 6)

set(RES_FILES "")
if ( WIN32 )
	# Adding RC resource file for adding information to the archive
	set(RES_FILES "${CMAKE_CURRENT_BINARY_DIR}/version.rc")
	message(STATUS "Generating RC file : ${RES_FILES}")
	configure_file(
			${CMAKE_CURRENT_SOURCE_DIR}/version.rc.in
			${RES_FILES}
			@ONLY)
	if( MINGW )
		set(CMAKE_RC_COMPILER_INIT windres)
		ENABLE_LANGUAGE(RC)
		SET(CMAKE_RC_COMPILE_OBJECT
		"<CMAKE_RC_COMPILER> <FLAGS> -O coff <DEFINES> -i <SOURCE> -o <OBJECT>")
	endif(MINGW)
	set(library_SRCS ${library_SRCS} ${RES_FILES})
endif( WIN32 )

add_library (lib60870-shared SHARED ${library_SRCS} )

set_target_properties(lib60870-shared PROPERTIES
           OUTPUT_NAME lib60870
           SOVERSION "${LIB_VERSION_MAJOR}.${LIB_VERSION_MINOR}.${LIB_VERSION_PATCH}"
	   WINDOWS_EXPORT_ALL_SYMBOLS true
           LINKER_LANGUAGE C
)

# Force C compilation mode for MSVC
if(MSVC)
    target_compile_options(lib60870-shared PRIVATE /TC)
endif()


GENERATE_EXPORT_HEADER(lib60870-shared
			BASE_NAME lib60870-shared
			EXPORT_MACRO_NAME lib60870-shared_EXPORT
			EXPORT_FILE_NAME lib60870-shared_export.h
			STATIC_DEFINE lib60870-shared_BUILT_AS_STATIC
)

add_library (lib60870 STATIC ${library_SRCS})

set_target_properties(lib60870 PROPERTIES
           LINKER_LANGUAGE C
)

# Force C compilation mode for MSVC
if(MSVC)
    target_compile_options(lib60870 PRIVATE /TC)
endif()

# Define CONFIG_CS104_APROFILE for both library targets (from lib60870_config.h)
target_compile_definitions(lib60870-shared PRIVATE CONFIG_CS104_APROFILE=1)
target_compile_definitions(lib60870 PRIVATE CONFIG_CS104_APROFILE=1)

# Add include directories for both library targets
target_include_directories(lib60870-shared PUBLIC
    ${CMAKE_CURRENT_SOURCE_DIR}/inc/api
    ${CMAKE_CURRENT_SOURCE_DIR}/inc/internal
    ${CMAKE_CURRENT_SOURCE_DIR}/hal/inc
    ${CMAKE_CURRENT_SOURCE_DIR}
    ${PROJECT_BINARY_DIR}
    ${CMAKE_BINARY_DIR}/dependencies/mbedtls-2.28.8/include
    ${CMAKE_CURRENT_SOURCE_DIR}/../liboqs/install/include
)

target_include_directories(lib60870 PUBLIC
    ${CMAKE_CURRENT_SOURCE_DIR}/inc/api
    ${CMAKE_CURRENT_SOURCE_DIR}/inc/internal
    ${CMAKE_CURRENT_SOURCE_DIR}/hal/inc
    ${CMAKE_CURRENT_SOURCE_DIR}
    ${PROJECT_BINARY_DIR}
    ${CMAKE_BINARY_DIR}/dependencies/mbedtls-2.28.8/include
    ${CMAKE_CURRENT_SOURCE_DIR}/../liboqs/install/include
)

include_directories(
    ${PROJECT_SOURCE_DIR}/src/inc
    ${PROJECT_SOURCE_DIR}/src/inc/internal
    ${PROJECT_SOURCE_DIR}/src/iec60870/security/62351-5
    ${MBEDTLS_INCLUDE_DIR}
)

IF(UNIX)
    target_link_libraries (lib60870
        -lpthread
        -lm
        -lrt
        ${OPENSSL_LIBRARIES}
    )

  configure_file(
    ${CMAKE_CURRENT_LIST_DIR}/lib60870.pc.in
    ${CMAKE_CURRENT_BINARY_DIR}/lib60870.pc @ONLY
  )
  install(FILES "${CMAKE_CURRENT_BINARY_DIR}/lib60870.pc" DESTINATION "${CMAKE_INSTALL_PREFIX}/share/pkgconfig")
ENDIF(UNIX)
IF(MINGW)
  target_link_libraries(lib60870-shared ws2_32 iphlpapi bcrypt mbedtls mbedx509 mbedcrypto)
  target_link_libraries(lib60870 ws2_32 iphlpapi bcrypt mbedtls mbedx509 mbedcrypto)
ENDIF(MINGW)
IF(MSVC)
  # Link mbedTLS libraries - order matters: mbedcrypto contains mbedtls_strerror
  target_link_libraries(lib60870-shared PRIVATE ws2_32 iphlpapi bcrypt)
  target_link_libraries(lib60870-shared PRIVATE mbedcrypto mbedx509 mbedtls)
  
  target_link_libraries(lib60870 PRIVATE ws2_32 iphlpapi bcrypt)
  target_link_libraries(lib60870 PRIVATE mbedcrypto mbedx509 mbedtls)
ENDIF(MSVC)

# Optional: link liboqs for PQC KEM (Kyber)
# # Use the OQS paths found in the root CMakeLists.txt
# if (OQS_INCLUDE_DIR AND OQS_LIBRARY)
#   message(STATUS "Linking liboqs to lib60870 targets: include=${OQS_INCLUDE_DIR} lib=${OQS_LIBRARY}")
#   target_compile_definitions(lib60870-shared PRIVATE HAVE_LIBOQS=1)
#   target_compile_definitions(lib60870 PRIVATE HAVE_LIBOQS=1)
#   target_link_libraries(lib60870-shared ${OQS_LIBRARY})
#   target_link_libraries(lib60870 ${OQS_LIBRARY})
# else()
#   message(STATUS "liboqs not available - building without PQC KEM support")
# endif()

install (TARGETS lib60870 lib60870-shared
	RUNTIME DESTINATION bin COMPONENT Applications
	ARCHIVE DESTINATION lib COMPONENT Libraries
    LIBRARY DESTINATION lib COMPONENT Libraries
)
