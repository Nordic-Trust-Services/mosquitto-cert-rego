cmake_minimum_required(VERSION 3.15)
project(mosquitto_cert_rego LANGUAGES C CXX VERSION 0.2.0)

#
# Standalone build of the mosquitto cert-rego plugin.
#
# This plugin authenticates MQTT clients using X.509 client certificates
# plus a Rego policy decision (via rego-cpp), with LDAP lookups exposed to
# the policy as custom Rego built-ins. It loads as a drop-in external .so
# against stock upstream mosquitto 2.0+ — no broker patches required.
#
# Build dependencies:
#
#   * cmake >= 3.15
#   * C11 compiler for most of the plugin
#   * C++17 compiler for the single rego_engine.cpp translation unit
#   * OpenSSL development headers
#   * OpenLDAP client (libldap-dev / openldap-devel)
#   * mosquitto development headers (libmosquitto-dev, any version with
#     plugin v5 API — mosquitto 2.0+)
#   * libcjson-dev (transitive build-time dep of <mosquitto.h>)
#   * rego-cpp installed such that find_package(regocpp CONFIG) works,
#     or at a prefix passed via -DREGOCPP_ROOT=/path
#
# See README.md for installation and configuration.
#

set(CMAKE_C_STANDARD 11)
set(CMAKE_C_STANDARD_REQUIRED ON)
# rego-cpp's public headers use std::span, which is C++20. We were C++17
# earlier; the bump is driven by upstream rego-cpp, not our own code.
set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_POSITION_INDEPENDENT_CODE ON)

option(BUILD_TESTING "Build the rego_engine test harness" ON)

if(NOT CMAKE_BUILD_TYPE)
	set(CMAKE_BUILD_TYPE RelWithDebInfo CACHE STRING "" FORCE)
endif()

if(CMAKE_C_COMPILER_ID MATCHES "GNU|Clang")
	add_compile_options(
		$<$<COMPILE_LANGUAGE:C>:-Wall>
		$<$<COMPILE_LANGUAGE:C>:-Wextra>
		$<$<COMPILE_LANGUAGE:C>:-Wconversion>
		$<$<COMPILE_LANGUAGE:C>:-Wshadow>
		$<$<COMPILE_LANGUAGE:CXX>:-Wall>
		$<$<COMPILE_LANGUAGE:CXX>:-Wextra>
		# -Wshadow is NOT enabled for C++ because mosquitto's broker.h
		# declares `mosquitto_client(const char*)` which G++ reports as
		# shadowing the `struct mosquitto_client` — an upstream quirk of
		# the public headers, not something the plugin can fix.
	)
endif()

# ---- dependencies ------------------------------------------------------

find_package(OpenSSL REQUIRED)

# OpenLDAP: no standard CMake module, probe by hand. pkg-config knows it
# under "ldap" on most Debian-family systems via libldap2-dev.
# We need BOTH libldap and liblber — libldap depends on symbols from
# liblber (ber_free etc.) and modern linkers (--as-needed by default on
# Debian) do not transitively resolve that for us.
find_package(PkgConfig)
if(PkgConfig_FOUND)
	pkg_check_modules(LDAP QUIET ldap)
	pkg_check_modules(LBER QUIET lber)
endif()
if(NOT LDAP_FOUND)
	find_path(LDAP_INCLUDE_DIR NAMES ldap.h
		HINTS ${LDAP_ROOT}/include /usr/local/include /usr/include)
	find_library(LDAP_LIBRARIES NAMES ldap
		HINTS ${LDAP_ROOT}/lib /usr/local/lib /usr/lib)
	find_library(LBER_LIBRARIES NAMES lber
		HINTS ${LDAP_ROOT}/lib /usr/local/lib /usr/lib)
	if(LDAP_INCLUDE_DIR AND LDAP_LIBRARIES)
		set(LDAP_FOUND TRUE)
		set(LDAP_INCLUDE_DIRS "${LDAP_INCLUDE_DIR}")
	endif()
endif()
if(NOT LDAP_FOUND)
	message(FATAL_ERROR
		"OpenLDAP client library not found. Install libldap2-dev (Debian) "
		"or openldap-devel (RHEL), or pass -DLDAP_ROOT=/path.")
endif()

# rego-cpp. Prefer a CMake package, fall back to a manual prefix.
#
# Even when find_package(regocpp CONFIG) succeeds, the exported
# regocpp::rego STATIC IMPORTED target does not always propagate the
# IMPORTED_LOCATION of its transitive dependencies (regocpp::json,
# regocpp::yaml, regocpp::snmalloc-new-override) through the CMake link
# interface. Consequently, linking against just regocpp::rego leaves
# trieste::json::* and snmalloc symbols unresolved. We work around this
# by listing every sub-library explicitly in the _LINK_LIBS variable
# below.
find_package(regocpp CONFIG QUIET)
if(regocpp_FOUND)
	set(REGOCPP_LINK_LIBS
		regocpp::rego
		regocpp::json
		regocpp::yaml
		regocpp::snmalloc-new-override
	)
else()
	find_path(REGOCPP_INCLUDE_DIR NAMES rego/rego.hh
		HINTS ${REGOCPP_ROOT}/include /usr/local/include /usr/include)
	find_library(REGOCPP_LIBRARY NAMES rego regocpp
		HINTS ${REGOCPP_ROOT}/lib /usr/local/lib /usr/lib)
	find_library(REGOCPP_JSON_LIBRARY NAMES json
		HINTS ${REGOCPP_ROOT}/lib /usr/local/lib /usr/lib)
	find_library(REGOCPP_YAML_LIBRARY NAMES yaml
		HINTS ${REGOCPP_ROOT}/lib /usr/local/lib /usr/lib)
	find_library(REGOCPP_SNMALLOC_LIBRARY NAMES snmalloc-new-override
		HINTS ${REGOCPP_ROOT}/lib /usr/local/lib /usr/lib)
	if(REGOCPP_INCLUDE_DIR AND REGOCPP_LIBRARY
			AND REGOCPP_JSON_LIBRARY AND REGOCPP_YAML_LIBRARY)
		add_library(regocpp::rego UNKNOWN IMPORTED)
		set_target_properties(regocpp::rego PROPERTIES
			IMPORTED_LOCATION "${REGOCPP_LIBRARY}"
			INTERFACE_INCLUDE_DIRECTORIES "${REGOCPP_INCLUDE_DIR}")
		set(regocpp_FOUND TRUE)
		set(REGOCPP_LINK_LIBS
			regocpp::rego
			${REGOCPP_JSON_LIBRARY}
			${REGOCPP_YAML_LIBRARY}
		)
		if(REGOCPP_SNMALLOC_LIBRARY)
			list(APPEND REGOCPP_LINK_LIBS ${REGOCPP_SNMALLOC_LIBRARY})
		endif()
	endif()
endif()
if(NOT regocpp_FOUND)
	message(FATAL_ERROR
		"rego-cpp not found. Build and install from "
		"https://github.com/microsoft/rego-cpp or pass -DREGOCPP_ROOT=/path.")
endif()

# mosquitto headers — no CMake package ships upstream, so probe.
find_path(MOSQUITTO_INCLUDE_DIR
	NAMES mosquitto.h mosquitto/broker.h
	HINTS ${MOSQUITTO_ROOT}/include /usr/local/include /usr/include
)
if(NOT MOSQUITTO_INCLUDE_DIR)
	message(FATAL_ERROR
		"Could not find mosquitto headers. Install libmosquitto-dev or "
		"pass -DMOSQUITTO_ROOT=/path.")
endif()

# ---- target ------------------------------------------------------------

set(PLUGIN_NAME mosquitto_cert_rego)

add_library(${PLUGIN_NAME} MODULE
	aia_fetch.c
	audit_log.c
	audit_log.h
	cache.c
	cert_auth.h
	cert_parse.c
	crl_check.c
	crl_fetch.c
	crl_fetch.h
	http_fetch.c
	http_fetch.h
	ldap_query.c
	ldap_query.h
	ocsp_check.c
	plugin.c
	rego_engine.cpp
	rego_engine.h
)

set_target_properties(${PLUGIN_NAME} PROPERTIES
	PREFIX ""
)

# The mosquitto plugin API macros have no visibility attribute on non-
# Windows, so we let default visibility carry the three plugin entry
# points and use a linker version script to keep the rest (rego-cpp,
# openssl, ldap wrapper internals) out of the dynamic symbol table.
set(PLUGIN_EXPORTS "${CMAKE_CURRENT_BINARY_DIR}/plugin_exports.map")
file(WRITE ${PLUGIN_EXPORTS}
"{
    global:
        mosquitto_plugin_version;
        mosquitto_plugin_init;
        mosquitto_plugin_cleanup;
    local:
        *;
};
")
if(CMAKE_SYSTEM_NAME STREQUAL "Linux")
	target_link_options(${PLUGIN_NAME} PRIVATE
		"LINKER:--version-script=${PLUGIN_EXPORTS}")
endif()

target_include_directories(${PLUGIN_NAME} PRIVATE
	${MOSQUITTO_INCLUDE_DIR}
	${LDAP_INCLUDE_DIRS}
)

target_link_libraries(${PLUGIN_NAME} PRIVATE
	OpenSSL::SSL
	OpenSSL::Crypto
	${REGOCPP_LINK_LIBS}
	${LDAP_LIBRARIES}
	${LBER_LIBRARIES}
	${CMAKE_DL_LIBS}
)

if(APPLE)
	# macOS: broker symbols are resolved at dlopen time, not at link time.
	target_link_options(${PLUGIN_NAME} PRIVATE "-undefined" "dynamic_lookup")
endif()

# Linux: the default -shared behaviour already tolerates unresolved
# references to mosquitto_* symbols (they are provided by the broker at
# dlopen time). We deliberately do NOT pass --unresolved-symbols=
# ignore-in-object-files because that would also mask genuine link
# errors, e.g. missing rego-cpp transitive dependencies.

include(GNUInstallDirs)
install(TARGETS ${PLUGIN_NAME}
	LIBRARY DESTINATION ${CMAKE_INSTALL_LIBDIR}/mosquitto
)
install(FILES test.conf
	DESTINATION ${CMAKE_INSTALL_DOCDIR}
	RENAME example.conf
)
install(DIRECTORY examples/
	DESTINATION ${CMAKE_INSTALL_DOCDIR}/policies
	FILES_MATCHING PATTERN "*.rego"
)

# ---- tests -------------------------------------------------------------
#
# A small C++ test binary that links rego_engine, the C modules it needs,
# and a set of libc-shim stubs that stand in for the mosquitto_* broker
# symbols. Runs the example test policy and asserts the eval path works.
# This is a dev-side sanity check, not a unit test framework — run via:
#   ctest --test-dir build
#
if(BUILD_TESTING)
	enable_testing()
	add_executable(test_rego_engine
		tests/test_rego.cpp
		tests/test_stubs.c
		rego_engine.cpp
		rego_engine.h
		ldap_query.c
		cache.c
		audit_log.c
		ocsp_check.c
		cert_parse.c
		aia_fetch.c
		crl_fetch.c
		crl_check.c
		http_fetch.c
		cert_auth.h
	)
	set_target_properties(test_rego_engine PROPERTIES
		C_VISIBILITY_PRESET default
		CXX_VISIBILITY_PRESET default
	)
	target_include_directories(test_rego_engine PRIVATE
		${MOSQUITTO_INCLUDE_DIR}
		${LDAP_INCLUDE_DIRS}
		${CMAKE_CURRENT_SOURCE_DIR}
	)
	target_link_libraries(test_rego_engine PRIVATE
		OpenSSL::SSL
		OpenSSL::Crypto
		${REGOCPP_LINK_LIBS}
		${LDAP_LIBRARIES}
		${LBER_LIBRARIES}
	)
	add_test(
		NAME rego_engine_smoke
		COMMAND test_rego_engine
			${CMAKE_CURRENT_SOURCE_DIR}/tests/test_policy_simple.rego
			${CMAKE_CURRENT_SOURCE_DIR}/tests/test_policy_multi_root.rego
	)
endif()

message(STATUS "mosquitto_cert_rego: configured")
message(STATUS "  mosquitto headers:  ${MOSQUITTO_INCLUDE_DIR}")
message(STATUS "  OpenSSL:            ${OPENSSL_VERSION}")
message(STATUS "  LDAP libraries:     ${LDAP_LIBRARIES}")
message(STATUS "  rego-cpp:           ${regocpp_FOUND}")
