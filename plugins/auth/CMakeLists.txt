find_package(OpenSSL REQUIRED)
find_package(CURL REQUIRED)

set(
  IRODS_AUTH_PLUGIN_native_SOURCES
  ${CMAKE_SOURCE_DIR}/plugins/auth/native/libnative.cpp
  )

set(
  IRODS_AUTH_PLUGIN_osauth_SOURCES
  ${CMAKE_SOURCE_DIR}/plugins/auth/osauth/libosauth.cpp
  )

set(
  IRODS_AUTH_PLUGIN_pam_SOURCES
  ${CMAKE_SOURCE_DIR}/plugins/auth/pam/libpam.cpp
  )

set(
  IRODS_AUTH_PLUGIN_pam_interactive_SOURCES
  ${CMAKE_SOURCE_DIR}/plugins/auth/pam_interactive/libpam_interactive.cpp
  ${CMAKE_SOURCE_DIR}/plugins/auth/pam_interactive/pam_interactive_config.cpp
  ${CMAKE_SOURCE_DIR}/plugins/auth/pam_interactive/handshake_client.cpp
  )

set(
  IRODS_AUTH_PLUGINS
  native
  osauth
  pam
  pam_interactive
  )

set(
  IRODS_AUTH_PLUGIN_COMPILE_DEFINITIONS_client
  )

set(
  IRODS_AUTH_PLUGIN_COMPILE_DEFINITIONS_server
  RODS_SERVER
  ENABLE_RE
  )

set(
  IRODS_AUTH_PLUGIN_LINK_LIBRARIES_client
  irods_client
  )

set(
  IRODS_AUTH_PLUGIN_LINK_LIBRARIES_server
  irods_server
  )

set(
  IRODS_AUTH_PLUGIN_TYPES
  client
  server
  )

foreach(PLUGIN ${IRODS_AUTH_PLUGINS})
  foreach(TYPE ${IRODS_AUTH_PLUGIN_TYPES})
    set(IRODS_CURRENT_PLUGIN_TARGET ${PLUGIN}_${TYPE})
      add_library(
        ${IRODS_CURRENT_PLUGIN_TARGET}
        MODULE
        ${IRODS_AUTH_PLUGIN_${PLUGIN}_SOURCES}
        )

      target_include_directories(
        ${IRODS_CURRENT_PLUGIN_TARGET}
        PRIVATE
        ${CMAKE_BINARY_DIR}/lib/core/include
        ${CMAKE_SOURCE_DIR}/lib/api/include
        ${CMAKE_SOURCE_DIR}/lib/core/include
        ${CMAKE_SOURCE_DIR}/server/api/include
        ${CMAKE_SOURCE_DIR}/server/core/include
        ${CMAKE_SOURCE_DIR}/server/drivers/include
        ${CMAKE_SOURCE_DIR}/server/icat/include
        ${CMAKE_SOURCE_DIR}/server/re/include
        ${IRODS_EXTERNALS_FULLPATH_BOOST}/include
        ${IRODS_EXTERNALS_FULLPATH_JANSSON}/include
        ${IRODS_EXTERNALS_FULLPATH_ARCHIVE}/include
        ${IRODS_EXTERNALS_PACKAGE_ROOT}/json3.7.3-0/include
        ${OPENSSL_INCLUDE_DIR}
        )

      target_link_libraries(
        ${IRODS_CURRENT_PLUGIN_TARGET}
        PRIVATE
        ${IRODS_AUTH_PLUGIN_LINK_LIBRARIES_${TYPE}}
        irods_common
        irods_plugin_dependencies
        ${IRODS_EXTERNALS_FULLPATH_BOOST}/lib/libboost_filesystem.so
        ${IRODS_EXTERNALS_FULLPATH_BOOST}/lib/libboost_system.so
        ${OPENSSL_CRYPTO_LIBRARY}
        )

    target_compile_definitions(${IRODS_CURRENT_PLUGIN_TARGET} PRIVATE ${IRODS_AUTH_PLUGIN_COMPILE_DEFINITIONS_${TYPE}} ${IRODS_COMPILE_DEFINITIONS} BOOST_SYSTEM_NO_DEPRECATED)
    target_compile_options(${IRODS_CURRENT_PLUGIN_TARGET} PRIVATE -Wno-write-strings)
    set_property(TARGET ${IRODS_CURRENT_PLUGIN_TARGET} PROPERTY CXX_STANDARD ${IRODS_CXX_STANDARD})
    install(
      TARGETS
      ${IRODS_CURRENT_PLUGIN_TARGET}
      LIBRARY
      DESTINATION ${IRODS_PLUGINS_DIRECTORY}/auth
      COMPONENT ${IRODS_PACKAGE_COMPONENT_RUNTIME_NAME}
      )
    endforeach()
endforeach()

target_link_libraries(
  pam_interactive_server
  PRIVATE
  ${CURL_LIBRARIES}
)
