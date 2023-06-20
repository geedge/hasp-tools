add_executable(hasp_verify_demo ${CMAKE_SOURCE_DIR}/platform/tool/hasp_verify_demo.c)
target_link_libraries(hasp_verify_demo pthread rt hasp-tools)
install(TARGETS hasp_verify_demo RUNTIME DESTINATION bin COMPONENT Program)

add_executable(hasp_monitor ${CMAKE_SOURCE_DIR}/platform/tool/hasp_monitor.c)
target_link_libraries(hasp_monitor pthread rt hasp-tools)
install(TARGETS hasp_monitor RUNTIME DESTINATION bin COMPONENT Program)