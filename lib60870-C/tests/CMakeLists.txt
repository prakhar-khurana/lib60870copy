# include_directories(
#    ./unity
# )

# target_compile_definitions(tests PRIVATE UNITY_INCLUDE_CONFIG_H)

# set(tests_SRCS
#    "${CMAKE_CURRENT_LIST_DIR}/all_tests.c"
#    "${CMAKE_CURRENT_LIST_DIR}/unity/unity.c"
# )

# IF(WIN32)
# set_source_files_properties(${tests_SRCS}
#                                        PROPERTIES LANGUAGE CXX)
# ENDIF(WIN32)

# configure_file(server-key.pem server-key.pem COPYONLY)
# configure_file(client1-key.pem client1-key.pem COPYONLY)
# configure_file(client1.cer client1.cer COPYONLY)
# configure_file(client2.cer client2.cer COPYONLY)
# configure_file(root.cer root.cer COPYONLY)
# configure_file(server.cer server.cer COPYONLY)

# configure_file(certs/server_CA1_1.key server_CA1_1.key COPYONLY)
# configure_file(certs/server_CA1_1.pem server_CA1_1.pem COPYONLY)
# configure_file(certs/root_CA1.pem root_CA1.pem COPYONLY)

# configure_file(certs/client_CA1_1.key client_CA1_1.key COPYONLY)
# configure_file(certs/client_CA1_1.pem client_CA1_1.pem COPYONLY)

# configure_file(certs/client_CA1_2.key client_CA1_2.key COPYONLY)
# configure_file(certs/client_CA1_2.pem client_CA1_2.pem COPYONLY)

# configure_file(certs/client_CA1_3.key client_CA1_3.key COPYONLY)
# configure_file(certs/client_CA1_3.pem client_CA1_3.pem COPYONLY)

# configure_file(certs/client_CA1_4.key client_CA1_4.key COPYONLY)
# configure_file(certs/client_CA1_4.pem client_CA1_4.pem COPYONLY)

# configure_file(certs/server_CA1_1_chain.pem server_CA1_1_chain.pem)

# configure_file(certs/test.crl test.crl COPYONLY)

# add_executable(tests
#   ${tests_SRCS}
# )

# target_link_libraries(tests
#     lib60870
#     ${OPENSSL_LIBRARIES}
# )

# if(WIN32)
# add_custom_command(TARGET tests POST_BUILD
#     COMMAND ${CMAKE_COMMAND} -E copy_if_different
#     $<TARGET_FILE:lib60870-shared>
#     $<TARGET_FILE_DIR:tests>
# )
# endif()

# enable_testing()
# add_test(NAME all_tests COMMAND tests)
include_directories(
    ${CMAKE_CURRENT_SOURCE_DIR}/unity
    ${CMAKE_SOURCE_DIR}/src/inc
    ${CMAKE_SOURCE_DIR}/src/inc/api
    ${CMAKE_SOURCE_DIR}/src/inc/internal
    ${CMAKE_SOURCE_DIR}/src/hal
    ${CMAKE_SOURCE_DIR}/src/iec60870/security
    ${CMAKE_SOURCE_DIR}/src/iec60870/security/62351-5
)

# Add test source files
set(tests_SRCS
    ${CMAKE_CURRENT_SOURCE_DIR}/all_tests.c
    ${CMAKE_CURRENT_SOURCE_DIR}/test_ap_security.c
    ${CMAKE_CURRENT_SOURCE_DIR}/test_iec62351_5_compliance.c
    ${CMAKE_CURRENT_SOURCE_DIR}/test_iec62351_5_full.c
    ${CMAKE_CURRENT_SOURCE_DIR}/unity/unity.c
)

# Set source file properties for Windows
if(WIN32)
    set_source_files_properties(${tests_SRCS} PROPERTIES LANGUAGE CXX)
    add_definitions(-D_CRT_SECURE_NO_WARNINGS)
    add_definitions(-D_WINSOCK_DEPRECATED_NO_WARNINGS)
endif()

# Configure certificate and key files
file(GLOB CERT_FILES "${CMAKE_CURRENT_SOURCE_DIR}/certs/*")
foreach(cert_file ${CERT_FILES})
    get_filename_component(filename ${cert_file} NAME)
    configure_file(
        ${cert_file}
        ${CMAKE_CURRENT_BINARY_DIR}/${filename}
        COPYONLY
    )
endforeach()

# Create test executable
add_executable(tests ${tests_SRCS})

# Link libraries
target_link_libraries(tests
    lib60870
    ${OPENSSL_LIBRARIES}
)

# Copy required DLLs on Windows
if(WIN32)
    add_custom_command(TARGET tests POST_BUILD
        COMMAND ${CMAKE_COMMAND} -E copy_if_different
        $<TARGET_FILE:lib60870-shared>
        $<TARGET_FILE_DIR:tests>
    )
    
    # Copy mbedTLS DLLs if needed
    if(WITH_MBEDTLS)
        add_custom_command(TARGET tests POST_BUILD
            COMMAND ${CMAKE_COMMAND} -E copy_if_different
            ${CMAKE_BINARY_DIR}/dependencies/mbedtls-2.28.8/library/Release/mbedtls.dll
            ${CMAKE_BINARY_DIR}/dependencies/mbedtls-2.28.8/library/Release/mbedx509.dll
            ${CMAKE_BINARY_DIR}/dependencies/mbedtls-2.28.8/library/Release/mbedcrypto.dll
            $<TARGET_FILE_DIR:tests>
        )
    endif()
endif()

# Add test
enable_testing()
add_test(NAME all_tests COMMAND tests)
