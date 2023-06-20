add_definitions(-DENABLD_LOG_FIEL)
add_executable(hasp_verify_demo
    ${CMAKE_SOURCE_DIR}/platform/src/hasp_shm.c
    ${CMAKE_SOURCE_DIR}/platform/src/hasp_verify.c
    ${CMAKE_SOURCE_DIR}/platform/tool/hasp_verify_demo.c)
target_include_directories(hasp_verify_demo PUBLIC ${CMAKE_SOURCE_DIR}/platform/include/)
target_link_libraries(hasp_verify_demo pthread rt)
target_link_libraries(hasp_verify_demo ${CMAKE_SOURCE_DIR}/lib/libhasp_linux_x86_64_25743.a)
install(TARGETS hasp_verify_demo RUNTIME DESTINATION bin COMPONENT Program)

add_definitions(-DENABLD_LOG_FIEL)
add_executable(hasp_monitor
    ${CMAKE_SOURCE_DIR}/platform/src/hasp_shm.c
    ${CMAKE_SOURCE_DIR}/platform/src/hasp_verify.c
    ${CMAKE_SOURCE_DIR}/platform/tool/hasp_monitor.c)
target_include_directories(hasp_monitor PUBLIC ${CMAKE_SOURCE_DIR}/platform/include/)
target_link_libraries(hasp_monitor pthread rt)
target_link_libraries(hasp_monitor ${CMAKE_SOURCE_DIR}/lib/libhasp_linux_x86_64_25743.a)
install(TARGETS hasp_monitor RUNTIME DESTINATION bin COMPONENT Program)