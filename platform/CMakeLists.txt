# compile hasp_update
add_executable(hasp_update src/hasp_update.c)
target_include_directories(hasp_update PUBLIC ${CMAKE_CURRENT_LIST_DIR}/include/)
target_link_libraries(hasp_update pthread)
target_link_libraries(hasp_update ${CMAKE_SOURCE_DIR}/lib/libhasp_linux_x86_64_25743.a)
install(TARGETS hasp_update RUNTIME DESTINATION bin COMPONENT Program)

# compile lib hasp-tools
add_library(hasp-tools SHARED src/hasp_verify.c)
target_include_directories(hasp-tools PUBLIC ${CMAKE_CURRENT_LIST_DIR}/include)
target_link_libraries(hasp-tools pthread)
target_link_libraries(hasp-tools ${CMAKE_SOURCE_DIR}/lib/libhasp_linux_x86_64_25743.a)
install(TARGETS hasp-tools LIBRARY DESTINATION ${CMAKE_INSTALL_PREFIX}/lib/ COMPONENT LIBRARIES)
install(FILES include/hasp_verify.h DESTINATION ${CMAKE_INSTALL_PREFIX}/include/ COMPONENT LIBRARIES)

# compile hasp_verify
add_subdirectory(test)