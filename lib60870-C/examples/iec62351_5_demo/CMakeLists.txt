project(iec62351_5_demo)

# Demo Server
add_executable(iec62351_5_demo_server iec62351_5_demo_server.c)
target_link_libraries(iec62351_5_demo_server PRIVATE lib60870)

# Demo Client
add_executable(iec62351_5_demo_client iec62351_5_demo_client.c)
target_link_libraries(iec62351_5_demo_client PRIVATE lib60870)

# Link mbedTLS libraries on Windows (required when linking static lib60870)
if(MSVC OR MINGW)
    target_link_libraries(iec62351_5_demo_server PRIVATE mbedtls mbedx509 mbedcrypto)
    target_link_libraries(iec62351_5_demo_client PRIVATE mbedtls mbedx509 mbedcrypto)
endif()

# Copy DLL to output directory on Windows
# if(WIN32)
#     add_custom_command(TARGET iec62351_5_demo_server POST_BUILD
#         COMMAND ${CMAKE_COMMAND} -E copy_if_different
#         $<TARGET_FILE:lib60870-shared>
#         $<TARGET_FILE_DIR:iec62351_5_demo_server>
#     )
    
#     add_custom_command(TARGET iec62351_5_demo_client POST_BUILD
#         COMMAND ${CMAKE_COMMAND} -E copy_if_different
#         $<TARGET_FILE:lib60870-shared>
#         $<TARGET_FILE_DIR:iec62351_5_demo_client>
#     )
# endif()

target_include_directories(iec62351_5_demo_server PRIVATE
    ${CMAKE_SOURCE_DIR}/src/inc
    ${CMAKE_SOURCE_DIR}/src/inc/api
    ${CMAKE_SOURCE_DIR}/src/inc/internal
)
target_include_directories(iec62351_5_demo_client PRIVATE
    ${CMAKE_SOURCE_DIR}/src/inc
    ${CMAKE_SOURCE_DIR}/src/inc/api
    ${CMAKE_SOURCE_DIR}/src/inc/internal
)