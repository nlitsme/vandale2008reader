find_path(ZLIB_DIR NAMES inftrees.c PATHS ${CMAKE_SOURCE_DIR}/symlinks/zlib)
if(ZLIB_DIR STREQUAL "ZLIB_DIR-NOTFOUND")
    include(FetchContent)
    FetchContent_Populate(zlib
        # TODO: we need a method of supplying a local cache of this file.
        URL https://www.zlib.net/zlib-1.3.tar.gz
        URL_HASH SHA256=ff0ba4c292013dbc27530b3a81e1f9a813cd39de01ca5e0f8bf355702efa593e
    )
    set(ZLIB_DIR ${CMAKE_BINARY_DIR}/zlib-src)
else()
    set(zlib_BINARY_DIR ${CMAKE_BINARY_DIR}/zlib-build)
endif()


list(APPEND ZLIBFILES inftrees.c infback.c compress.c inffast.c adler32.c uncompr.c inflate.c deflate.c crc32.c trees.c zutil.c)
#list(APPEND ZLIBFILES gzclose.c gzread.c gzwrite.c gzlib.c)  <-- build failure on macos because of missing include <unistd.h>
list(TRANSFORM ZLIBFILES PREPEND ${ZLIB_DIR}/)
add_library(zlib ${LIBSTYLE} ${ZLIBFILES})
target_include_directories(zlib PUBLIC ${ZLIB_DIR})

include(FindPackageHandleStandardArgs)
find_package_handle_standard_args(zlib REQUIRED_VARS ZLIB_DIR)

