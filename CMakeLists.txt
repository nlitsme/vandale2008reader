cmake_minimum_required(VERSION 3.10)
project(vdwreader)
set(CMAKE_CXX_STANDARD 17)
list(APPEND CMAKE_MODULE_PATH "${CMAKE_CURRENT_SOURCE_DIR}/cmake_find")

if (${CMAKE_SYSTEM_NAME} MATCHES "Linux")
    set(LINUX TRUE)
elseif (${CMAKE_SYSTEM_NAME} MATCHES "Darwin")
    set(DARWIN TRUE)
elseif (${CMAKE_SYSTEM_NAME} MATCHES "FreeBSD")
    set(FREEBSD TRUE)
endif()

# checking if we are called in the correct way:
#  with a -B argument.  and without a cache file in the source directory.
if (CMAKE_CACHEFILE_DIR STREQUAL "${CMAKE_SOURCE_DIR}")
    message(FATAL_ERROR "\nUnexpected CMakeCache.txt file in the source directory. Please remove it.")
    return()
endif()

if (EXISTS ${CMAKE_BINARY_DIR}/CMakeLists.txt)
    message(FATAL_ERROR "\nRun cmake with an explicit -B buildpath")
    return()
endif()

if(MSVC)
    # /MP = multithreaded build
    set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} /MP")
    # /utf-8 = utf8 source and execution
    set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} /utf-8")
endif()

if (WIN32)
    add_definitions(-DNOMINMAX -DNOGDI)
endif()

find_package(itslib REQUIRED)

find_package(openssl REQUIRED)
find_package(Boost REQUIRED date_time)
#find_package(ZLIB REQUIRED)
find_package(zlib)

add_executable(vdwreader ${CMAKE_SOURCE_DIR}/vdwreader.cpp)
target_link_libraries(vdwreader OpenSSL::Crypto)
#target_link_libraries(vdwreader ZLIB::ZLIB)
target_link_libraries(vdwreader zlib)
target_link_libraries(vdwreader itslib)
target_link_libraries(vdwreader Boost::headers Boost::date_time)
target_link_directories(vdwreader PUBLIC ${Boost_LIBRARY_DIRS})


