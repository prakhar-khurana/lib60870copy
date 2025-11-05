project(iec62351_5_demo)

# Demo Server
add_executable(iec62351_5_demo_server iec62351_5_demo_server.c)
target_link_libraries(iec62351_5_demo_server lib60870)

# Demo Client
add_executable(iec62351_5_demo_client iec62351_5_demo_client.c)
target_link_libraries(iec62351_5_demo_client lib60870)

# Copy DLL to output directory on Windows
if(WIN32)
    add_custom_command(TARGET iec62351_5_demo_server POST_BUILD
        COMMAND ${CMAKE_COMMAND} -E copy_if_different
        $<TARGET_FILE:lib60870-shared>
        $<TARGET_FILE_DIR:iec62351_5_demo_server>
    )
    
    add_custom_command(TARGET iec62351_5_demo_client POST_BUILD
        COMMAND ${CMAKE_COMMAND} -E copy_if_different
        $<TARGET_FILE:lib60870-shared>
        $<TARGET_FILE_DIR:iec62351_5_demo_client>
    )
endif()
