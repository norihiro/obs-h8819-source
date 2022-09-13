cmake_minimum_required(VERSION 3.13)

project(obs-h8819-source VERSION 0.2.1)

# Replace `Your Name Here` with the name (yours or your organization's) you want
# to see as the author of the plugin (in the plugin's metadata itself and in the installers)
set(PLUGIN_AUTHOR "Norihiro Kamae")

# Replace `com.example.obs-plugin-template` with a unique Bundle ID for macOS releases
# (used both in the installer and when submitting the installer for notarization)
set(MACOS_BUNDLEID "net.nagater.obs-h8819-source")
set(MACOS_PACKAGE_UUID "FAA836AE-8D20-4F85-AC53-34EB8BD1D652")
set(MACOS_INSTALLER_UUID "E44BD56C-036E-480A-AE87-DAB6DBCFECF9")
set(ID_PREFIX "net.nagater.obs-h8819-source.")

# Replace `me@contoso.com` with the maintainer email address you want to put in Linux packages
set(LINUX_MAINTAINER_EMAIL "norihiro@nagater.net")

# TAKE NOTE: No need to edit things past this point

option(LINUX_DEB_PKG "Make deb package for Linux" ON)
if(LINUX_DEB_PKG)
	set(CPACK_DEBIAN_PACKAGE_DEPENDS libcap2-bin)
	set(CPACK_DEBIAN_PACKAGE_CONTROL_EXTRA ${CMAKE_CURRENT_BINARY_DIR}/postinst)
	configure_file(installer/linux-setcap.sh.in postinst)
endif()

find_package(libobs REQUIRED)
include(cmake/ObsPluginHelpers.cmake)

if(UNIX AND NOT APPLE)
	# macOS does not require it.
	find_package(PkgConfig)
	pkg_check_modules(LIBPCAP REQUIRED libpcap)
endif()

configure_file(
	src/plugin-macros.h.in
	../src/plugin-macros.generated.h
)
configure_file(
	installer/installer-Windows.iss.in
	../installer/installer-Windows.generated.iss
)

configure_file(
	ci/ci_includes.sh.in
	../ci/ci_includes.generated.sh
)
configure_file(
	ci/ci_includes.cmd.in
	../ci/ci_includes.generated.cmd
)

set(PLUGIN_SOURCES
	src/plugin-main.c
	src/source.c
	src/capdev.c
)

if(NOT OS_WINDOWS)
	set(PLUGIN_SOURCES ${PLUGIN_SOURCES} util/pipe-posix.c)
else()
	set(PLUGIN_SOURCES ${PLUGIN_SOURCES} util/pipe-windows.c)
endif()

add_library(${CMAKE_PROJECT_NAME} MODULE ${PLUGIN_SOURCES})

target_include_directories(${CMAKE_PROJECT_NAME} PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/util)

target_link_libraries(${CMAKE_PROJECT_NAME}
	OBS::libobs
)

add_executable(obs-h8819-proc
	src/capdev-proc.c
	src/capdev-proc.h
)

if(NOT OS_WINDOWS)
	target_link_libraries(obs-h8819-proc pcap)
endif()

if(OS_WINDOWS)
	# Enable Multicore Builds and disable FH4 (to not depend on VCRUNTIME140_1.DLL when building with VS2019)
	if (MSVC)
		add_definitions(/MP /d2FH4-)
	endif()

	target_link_libraries(${CMAKE_PROJECT_NAME} OBS::w32-pthreads)

	target_include_directories(obs-h8819-proc PRIVATE ${NPCAP_INCLUDE_DIR})
	target_link_directories(obs-h8819-proc PRIVATE ${NPCAP_LIBRARY_DIR})
	target_link_libraries(obs-h8819-proc ${NPCAP_LIBRARIES})
endif()

if(OS_LINUX)
	target_compile_options(${CMAKE_PROJECT_NAME} PRIVATE -Wall -Wextra)

	install(TARGETS obs-h8819-proc
		DESTINATION "${CMAKE_INSTALL_FULL_DATAROOTDIR}/obs/obs-plugins/${CMAKE_PROJECT_NAME}")

	configure_file(installer/linux-setcap.sh.in setcap.sh)
	install(CODE "execute_process(COMMAND ./setcap.sh)")
endif()

if(APPLE)
	set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -stdlib=libc++ -fvisibility=default")

	set_target_properties(${CMAKE_PROJECT_NAME} PROPERTIES PREFIX "")
	set(MACOSX_PLUGIN_GUI_IDENTIFIER "${MACOS_BUNDLEID}")
	set(MACOSX_PLUGIN_BUNDLE_VERSION "${CMAKE_PROJECT_VERSION}")
	set(MACOSX_PLUGIN_SHORT_VERSION_STRING "1")
endif()

setup_plugin_target(${CMAKE_PROJECT_NAME})

configure_file(installer/installer-macOS.pkgproj.in installer-macOS.generated.pkgproj)
