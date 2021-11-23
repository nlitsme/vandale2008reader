include(FetchContent)
FetchContent_Populate(zlib
    # TODO: we need a method of supplying a local cache of this file.
    URL http://www.zlib.net/zlib-1.2.11.tar.gz
    URL_HASH SHA256=c3e5e9fdd5004dcb542feda5ee4f0ff0744628baf8ed2dd5d66f8ca1197cb1a1
)
set(ZLIBDIR ${CMAKE_BINARY_DIR}/zlib-src)

list(APPEND ZLIBFILES inftrees.c infback.c compress.c inffast.c adler32.c uncompr.c inflate.c deflate.c crc32.c trees.c zutil.c)
list(APPEND ZLIBFILES gzclose.c gzread.c gzwrite.c gzlib.c)
list(TRANSFORM ZLIBFILES PREPEND ${ZLIBDIR}/)
add_library(zlib ${LIBSTYLE} ${ZLIBFILES})
target_include_directories(zlib PUBLIC ${ZLIBDIR})


