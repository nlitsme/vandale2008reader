# cmake package finder for itslib

file(GLOB ITSLIB_DIRS itslib  submodules/itslib ../itslib ../../itslib)
# first check for the local-copy itslib variant
find_path(ITSLIB_PATH NAMES incxxxlude/stringutils.h PATHS ${ITSLIB_DIRS})
if(NOT ITSLIB_PATH STREQUAL "ITSLIB_PATH-NOTFOUND")
	set(ITSLIB_INCLUDE_DIR ${ITSLIB_PATH}/include)
else()
	# then check for the repository itslib variant
	find_path(ITSLIB_PATH NAMES include/itslib/stringutils.h PATHS ${ITSLIB_DIRS})
	if(NOT ITSLIB_PATH STREQUAL "ITSLIB_PATH-NOTFOUND")
		set(ITSLIB_INCLUDE_DIR ${ITSLIB_PATH}/include/itslib)
	else()
		include(FetchContent)
		FetchContent_Populate(itslib
			GIT_REPOSITORY https://github.com/nlitsme/legacy-itsutils-library)
		set(ITSLIB_PATH ${CMAKE_BINARY_DIR}/itslib-src)
		set(ITSLIB_INCLUDE_DIR ${ITSLIB_PATH}/include/itslib)
    endif()
endif()

message(INFO " Using itslib from ${ITSLIB_PATH}")

list(APPEND ITSLIBSRC debug.cpp stringutils.cpp utfcvutils.cpp vectorutils.cpp)
list(TRANSFORM ITSLIBSRC PREPEND ${ITSLIB_PATH}/src/)
add_library(itslib STATIC ${ITSLIBSRC})
target_include_directories(itslib PUBLIC ${ITSLIB_INCLUDE_DIR})
target_compile_definitions(itslib PUBLIC _NO_RAPI _NO_WINDOWS)
if(NOT WIN32)
    target_compile_definitions(itslib PUBLIC _UNIX)
endif()


