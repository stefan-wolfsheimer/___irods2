set(IRODS_TEST_TARGET irods_dstream)

set(IRODS_TEST_SOURCE_FILES ${CMAKE_CURRENT_SOURCE_DIR}/src/main.cpp
                            ${CMAKE_CURRENT_SOURCE_DIR}/src/test_dstream.cpp)

set(IRODS_TEST_INCLUDE_PATH ${CMAKE_BINARY_DIR}/lib/core/include
                            ${CMAKE_SOURCE_DIR}/lib/core/include
                            ${CMAKE_SOURCE_DIR}/lib/api/include
                            ${CMAKE_SOURCE_DIR}/lib/filesystem/include
                            ${CMAKE_SOURCE_DIR}/plugins/api/include
                            ${CMAKE_SOURCE_DIR}/server/core/include
                            ${CMAKE_SOURCE_DIR}/server/icat/include
                            ${IRODS_EXTERNALS_FULLPATH_CATCH2}/include
                            ${IRODS_EXTERNALS_FULLPATH_BOOST}/include
                            ${IRODS_EXTERNALS_FULLPATH_JANSSON}/include)
 
set(IRODS_TEST_LINK_LIBRARIES irods_common
                              irods_client
                              c++abi)
