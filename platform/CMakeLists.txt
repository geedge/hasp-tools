add_executable(hasp_update src/hasp_update.c)

target_include_directories(hasp_update PUBLIC ${CMAKE_CURRENT_LIST_DIR}/include/)

target_link_libraries(hasp_update pthread)
target_link_libraries(hasp_update ${CMAKE_SOURCE_DIR}/lib/libhasp_linux_x86_64_25743.a)

install(TARGETS hasp_update RUNTIME DESTINATION bin COMPONENT Program)