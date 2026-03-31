cmake_minimum_required(VERSION 3.13)

project(h8819-source VERSION 0.4.1)

set(PLUGIN_AUTHOR "Norihiro Kamae")

set(PLUGIN_URL "https://obsproject.com/forum/resources/reac-audio-source.1471/")
set(ID_PREFIX "net.nagater.obs-h8819-source.")
set(MACOS_BUNDLEID "net.nagater.obs-h8819-source")
set(MACOS_PACKAGE_UUID "FAA836AE-8D20-4F85-AC53-34EB8BD1D652")
set(MACOS_INSTALLER_UUID "E44BD56C-036E-480A-AE87-DAB6DBCFECF9")
set(WIN_INSTALLER_UUID   "132471B0-A4A1-4EC2-BBE7-59C9379FCB38")

set(LINUX_MAINTAINER_EMAIL "norihiro@nagater.net")

option(ENABLE_COVERAGE "Enable coverage option for GCC" OFF)
option(ENABLE_ASYNC_COMPENSATION "Enable async-compensation property for the PR 6351" OFF)

option(LINUX_DEB_PKG "Make deb package for Linux" ON)
if(LINUX_DEB_PKG)
	set(CPACK_DEBIAN_PACKAGE_DEPENDS libcap2-bin)
	set(CPACK_DEBIAN_PACKAGE_CONTROL_EXTRA ${CMAKE_CURRENT_BINARY_DIR}/postinst)
	configure_file(installer/linux-setcap.sh.in postinst)
endif()

if(${CMAKE_SOURCE_DIR} STREQUAL ${CMAKE_CURRENT_SOURCE_DIR})
	find_package(libobs REQUIRED)
	include(cmake/ObsPluginHelpers.cmake)
endif()

if(UNIX AND NOT APPLE)
	# macOS does not require it.
	find_package(PkgConfig)
	pkg_check_modules(LIBPCAP REQUIRED libpcap)
endif()

configure_file(
	src/plugin-macros.h.in
	plugin-macros.generated.h
)

set(PLUGIN_SOURCES
	src/plugin-main.c
	src/source.c
	src/capdev-common.c
)

if(NOT OS_WINDOWS)
	set(PLUGIN_SOURCES ${PLUGIN_SOURCES} src/capdev-nix.c)
else()
	set(PLUGIN_SOURCES ${PLUGIN_SOURCES} src/capdev-windows.c)
	set(PLUGIN_SOURCES ${PLUGIN_SOURCES} src/wireshark/capture_win_ifnames.c)
endif()

add_library(${PROJECT_NAME} MODULE ${PLUGIN_SOURCES})

target_link_libraries(${PROJECT_NAME}
	OBS::libobs
)

if(NOT OS_WINDOWS)
	add_executable(obs-h8819-proc
		src/capdev-proc.c
		src/capdev-proc.h
	)

	target_link_libraries(obs-h8819-proc pcap)
endif()

target_include_directories(${PROJECT_NAME}
	PRIVATE
	${CMAKE_CURRENT_BINARY_DIR}
)

if(OS_WINDOWS)
	# Enable Multicore Builds and disable FH4 (to not depend on VCRUNTIME140_1.DLL when building with VS2019)
	if (MSVC)
		add_definitions(/MP /d2FH4-)
	endif()

	target_link_libraries(${PROJECT_NAME} OBS::w32-pthreads)

	set(LICENSE_DESTINATION "${PROJECT_NAME}/data")

	target_include_directories(${PROJECT_NAME} PRIVATE ${NPCAP_INCLUDE_DIR})
	target_link_directories(${PROJECT_NAME} PRIVATE ${NPCAP_LIBRARY_DIR})
	target_link_libraries(${PROJECT_NAME} ${NPCAP_LIBRARIES} Iphlpapi.lib)
endif()

if(OS_LINUX)
	target_compile_options(${PROJECT_NAME} PRIVATE -Wall -Wextra)
	target_link_options(${PROJECT_NAME} PRIVATE -Wl,-z,defs)

	set(LICENSE_DESTINATION ${CMAKE_INSTALL_DOCDIR})

	install(TARGETS obs-h8819-proc
		DESTINATION "${CMAKE_INSTALL_FULL_DATAROOTDIR}/obs/obs-plugins/${PROJECT_NAME}")

	configure_file(installer/linux-setcap.sh.in setcap.sh)
	install(CODE "execute_process(COMMAND ./setcap.sh)")

	if(CMAKE_C_COMPILER_ID STREQUAL GNU)
		target_compile_options(${PROJECT_NAME} PRIVATE -fanalyzer)
	endif()

	if(ENABLE_COVERAGE)
		target_compile_options(${PROJECT_NAME} PRIVATE -coverage -fprofile-update=atomic)
		target_link_options(${PROJECT_NAME} PRIVATE -coverage)
		target_compile_options(obs-h8819-proc PRIVATE -coverage)
		target_link_options(obs-h8819-proc PRIVATE -coverage)
	endif()
endif()

if(OS_MACOS)
	set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -stdlib=libc++ -fvisibility=default")

	set(LICENSE_DESTINATION "${PROJECT_NAME}.plugin/Contents/Resources")

	set_target_properties(${PROJECT_NAME} PROPERTIES PREFIX "")
	set(MACOSX_PLUGIN_GUI_IDENTIFIER "${MACOS_BUNDLEID}")
	set(MACOSX_PLUGIN_BUNDLE_VERSION "${PROJECT_VERSION}")
	set(MACOSX_PLUGIN_SHORT_VERSION_STRING "1")

	if(ENABLE_COVERAGE)
		target_compile_options(${PROJECT_NAME} PRIVATE -coverage)
		target_link_options(${PROJECT_NAME} PRIVATE --coverage)
		target_compile_options(obs-h8819-proc PRIVATE -coverage)
		target_link_options(obs-h8819-proc PRIVATE -coverage)
	endif()
endif()

file(GENERATE OUTPUT .gitignore CONTENT "*\n")

setup_plugin_target(${PROJECT_NAME})

option(INSTALL_LICENSE_FILES "Install license files" ON)
if(INSTALL_LICENSE_FILES)
	install(FILES
		LICENSE
		DESTINATION ${LICENSE_DESTINATION}
	)

	if(OS_WINDOWS)
		install(FILES
			${NPCAP_INCLUDE_DIR}/pcap/pcap.h
			RENAME npcap-pcap.h
			DESTINATION ${LICENSE_DESTINATION}
		)
	endif()
endif()

if(${CMAKE_SOURCE_DIR} STREQUAL ${CMAKE_CURRENT_SOURCE_DIR})
	configure_file(
		installer/installer-Windows.iss.in
		installer-Windows.generated.iss
	)

	configure_file(
		ci/ci_includes.sh.in
		ci/ci_includes.generated.sh
	)
	configure_file(
		ci/ci_includes.cmd.in
		ci/ci_includes.generated.cmd
	)

	configure_file(
		installer/installer-macOS.pkgproj.in
		installer-macOS.generated.pkgproj
	)
	configure_file(
		installer/installer-macOS-post.sh.in
		installer-macOS-post.generated.sh
	)
endif()
